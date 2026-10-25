package actions

import (
	"os"
	"path/filepath"
	"testing"
)

func TestQuarantineMovesAndStripsPermissions(t *testing.T) {
	src := t.TempDir()
	qdir := filepath.Join(t.TempDir(), "quarantine")

	target := filepath.Join(src, "payload.sh")
	if err := os.WriteFile(target, []byte("#!/bin/sh\necho hi\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	dest, err := Quarantine(qdir, target, "evt-001")
	if err != nil {
		t.Fatalf("Quarantine: %v", err)
	}

	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Errorf("original file should be gone, got err=%v", err)
	}
	fi, err := os.Stat(dest)
	if err != nil {
		t.Fatalf("quarantined file missing at %q: %v", dest, err)
	}
	if fi.Mode().Perm() != 0 {
		t.Errorf("expected mode 0000, got %o", fi.Mode().Perm())
	}
	if filepath.Base(dest) != "evt-001_payload.sh" {
		t.Errorf("unexpected quarantine filename: %q", dest)
	}
}

func TestQuarantineRejectsProtectedPaths(t *testing.T) {
	qdir := t.TempDir()
	for _, p := range []string{"/etc/passwd", "/etc/shadow", "/"} {
		if _, err := Quarantine(qdir, p, "evt-002"); err == nil {
			t.Errorf("expected rejection for protected path %q", p)
		}
	}
}

func TestQuarantineRejectsDirectoriesAndSymlinks(t *testing.T) {
	src := t.TempDir()
	qdir := filepath.Join(t.TempDir(), "quarantine")

	dir := filepath.Join(src, "adir")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Quarantine(qdir, dir, "evt-003"); err == nil {
		t.Error("expected rejection for a directory")
	}

	realFile := filepath.Join(src, "real.txt")
	_ = os.WriteFile(realFile, []byte("x"), 0o644)
	link := filepath.Join(src, "link.txt")
	if err := os.Symlink(realFile, link); err != nil {
		t.Skipf("symlinks unsupported here: %v", err)
	}
	if _, err := Quarantine(qdir, link, "evt-004"); err == nil {
		t.Error("expected rejection for a symlink")
	}
}

func TestQuarantineRejectsInvalidEventID(t *testing.T) {
	src := t.TempDir()
	qdir := filepath.Join(t.TempDir(), "quarantine")
	target := filepath.Join(src, "x.sh")
	_ = os.WriteFile(target, []byte("x"), 0o644)

	if _, err := Quarantine(qdir, target, "../escape"); err == nil {
		t.Error("expected rejection for a path-traversal event id")
	}
}

func TestQuarantineRejectsPathAlreadyInQuarantineDir(t *testing.T) {
	qdir := t.TempDir()
	alreadyThere := filepath.Join(qdir, "evt-001_payload.sh")
	_ = os.WriteFile(alreadyThere, []byte("x"), 0o644)

	if _, err := Quarantine(qdir, alreadyThere, "evt-005"); err == nil {
		t.Error("expected rejection for a path already inside the quarantine dir")
	}
}

func TestQuarantineOnHostMapsLogicalPath(t *testing.T) {
	hostRoot := t.TempDir()
	qdir := filepath.Join(t.TempDir(), "quarantine")
	actualDir := filepath.Join(hostRoot, "var", "tmp")
	if err := os.MkdirAll(actualDir, 0o755); err != nil {
		t.Fatal(err)
	}
	logical := "/var/tmp/payload.sh"
	actual := filepath.Join(hostRoot, "var", "tmp", "payload.sh")
	if err := os.WriteFile(actual, []byte("#!/bin/sh\necho hi\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	dest, err := QuarantineOnHost(hostRoot, qdir, logical, "evt-root-001")
	if err != nil {
		t.Fatalf("QuarantineOnHost: %v", err)
	}
	if _, err := os.Stat(actual); !os.IsNotExist(err) {
		t.Fatalf("host-root source should be moved, err=%v", err)
	}
	if filepath.Base(dest) != "evt-root-001_payload.sh" {
		t.Fatalf("unexpected dest %q", dest)
	}
}
