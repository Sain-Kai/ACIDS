package actions

import (
	"os"
	"path/filepath"
	"testing"
)

func withFakeDockerRun(t *testing.T, fn func(staged string) (string, error)) {
	t.Helper()
	orig := runDockerRun
	runDockerRun = fn
	t.Cleanup(func() { runDockerRun = orig })
}

func TestSandboxAnalyzeRejectsMissingArtifact(t *testing.T) {
	withFakeDockerRun(t, func(string) (string, error) { t.Fatal("docker should not run for a missing artifact"); return "", nil })

	_, err := SandboxAnalyze(filepath.Join(t.TempDir(), "does-not-exist"), t.TempDir())
	if err == nil {
		t.Error("expected an error for a missing artifact")
	}
}

func TestSandboxAnalyzeRejectsRelativePath(t *testing.T) {
	_, err := SandboxAnalyze("relative/path", t.TempDir())
	if err == nil {
		t.Error("expected rejection of a non-absolute path")
	}
}

func TestSandboxAnalyzeStagesReadableCopyAndCleansUp(t *testing.T) {
	skipIfNoCp(t) // SandboxAnalyze shells out to the real `cp` for staging, same as Snapshotter
	src := t.TempDir()
	staging := t.TempDir()

	// A real quarantined file is chmod 0 (see TestQuarantineMovesAndStripsPermissions),
	// which only root can read back -- not a safe assumption for this test
	// to make if it's going to run as an ordinary CI user. The staging/
	// chmod/cleanup behavior under test here doesn't depend on exercising
	// root's permission-bypass, so a normal readable file is enough.
	artifact := filepath.Join(src, "payload")
	if err := os.WriteFile(artifact, []byte("#!/bin/sh\necho hi\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var seenPath string
	var seenMode os.FileMode
	withFakeDockerRun(t, func(staged string) (string, error) {
		seenPath = staged
		fi, err := os.Stat(staged)
		if err != nil {
			t.Fatal(err)
		}
		seenMode = fi.Mode().Perm()
		return "analysis output", nil
	})

	out, err := SandboxAnalyze(artifact, staging)
	if err != nil {
		t.Fatalf("SandboxAnalyze: %v", err)
	}
	if out != "analysis output" {
		t.Errorf("expected the fake docker output to pass through, got %q", out)
	}
	if seenMode != 0o555 {
		t.Errorf("expected the staged copy to be mode 0555, got %o", seenMode)
	}
	if _, err := os.Stat(seenPath); !os.IsNotExist(err) {
		t.Errorf("expected the staged copy to be cleaned up after analysis, got err=%v", err)
	}
	fi, err := os.Stat(artifact)
	if err != nil {
		t.Fatalf("expected the original quarantined file to be untouched: %v", err)
	}
	if fi.Mode().Perm() != 0o644 {
		t.Errorf("expected the original's permissions to be left alone, got %o", fi.Mode().Perm())
	}
}
