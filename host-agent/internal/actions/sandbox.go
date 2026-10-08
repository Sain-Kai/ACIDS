package actions

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"sentinelmesh/host-agent/internal/validate"
)

const (
	sandboxImage   = "sentinelmesh-sandbox"
	sandboxTimeout = 30 * time.Second
)

// SandboxAnalyze stages a disposable, world-readable copy of a quarantined
// artifact and runs it through the isolated sandbox container (see
// sandbox/Dockerfile.sandbox and sandbox/analyze.sh in the repo root) for
// static inspection plus a bounded execution.
//
// Quarantined files are chmod 0 (see Quarantine in this package) so
// nothing -- including this process, if run unprivileged -- can read or
// execute them directly. The staged copy is what the sandbox container
// actually sees; it's removed afterward regardless of outcome, and the
// quarantined original is never modified. This mirrors what
// control-plane's SandboxAnalysisService used to do locally -- moved here
// because the artifact lives on THIS host, which may not be the host
// control-plane itself is running on.
//
// Requires the sentinelmesh-sandbox image to already be built on this
// host (`docker build -t sentinelmesh-sandbox sandbox/` from the repo
// root) and a working Docker daemon.
func SandboxAnalyze(quarantinedPath, stagingDir string) (string, error) {
	abs, err := validate.AbsPath(quarantinedPath)
	if err != nil {
		return "", err
	}
	if _, err := os.Stat(abs); err != nil {
		return "", fmt.Errorf("sandbox: artifact not found: %w", err)
	}

	if err := os.MkdirAll(stagingDir, 0o700); err != nil {
		return "", err
	}
	staged := filepath.Join(stagingDir, fmt.Sprintf("%d_%s", time.Now().UnixNano(), filepath.Base(abs)))
	defer os.Remove(staged)

	if err := runCmd("cp", "-a", abs, staged); err != nil {
		return "", fmt.Errorf("sandbox: staging copy failed: %w", err)
	}
	// World-readable+executable: the sandbox container's non-root user
	// won't own this file, so it relies on the "other" permission bits.
	// This disposable copy is the only thing opened up -- the quarantined
	// original stays at mode 0 throughout.
	if err := os.Chmod(staged, 0o555); err != nil {
		return "", fmt.Errorf("sandbox: failed to open up staged copy: %w", err)
	}

	return runSandboxContainer(staged)
}

// runDockerRun is a variable so tests can fake it without needing a real
// Docker daemon.
var runDockerRun = func(staged string) (string, error) {
	args := []string{"run", "--rm",
		"--network", "none",
		"--read-only",
		"--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=16m",
		"--cap-drop=ALL",
		"--security-opt", "no-new-privileges",
		"--pids-limit", "128",
		"--memory=512m", "--cpus=1",
		"--user", "10001:10001",
		"-v", staged + ":/sandbox/payload:ro",
	}
	if runtime := os.Getenv("SANDBOX_RUNTIME"); runtime != "" {
		args = append(args, "--runtime", runtime)
	}
	args = append(args, sandboxImage, "/sandbox/analyze.sh", "/sandbox/payload")
	cmd := exec.Command("docker", args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("docker run failed to start: %w", err)
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case err := <-done:
		if err != nil {
			// A non-zero exit from analyze.sh is still useful output
			// (e.g. a payload that errors when executed) -- return the
			// captured output with a note, not a bare error.
			return out.String() + fmt.Sprintf("\n[sandbox exited: %v]", err), nil
		}
		return out.String(), nil
	case <-time.After(sandboxTimeout):
		_ = cmd.Process.Kill()
		return out.String() + "\n[sandbox analysis timed out]", nil
	}
}

func runSandboxContainer(staged string) (string, error) {
	return runDockerRun(staged)
}
