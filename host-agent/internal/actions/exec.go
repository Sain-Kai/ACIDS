// Package actions implements the privileged operations the host agent
// performs on behalf of control-plane. Nothing here trusts its inputs:
// callers (internal/api) validate first, and each action re-checks the
// values that reach exec.Command or the filesystem.
package actions

import "os/exec"

// runCmd is a package variable so tests can substitute a fake instead of
// running usermod/pkill/cp for real.
var runCmd = func(name string, args ...string) error {
	return exec.Command(name, args...).Run()
}
