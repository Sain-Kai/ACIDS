// Package validate holds the input checks every host-agent action runs
// before touching the system. The agent executes privileged operations
// (kill, iptables, usermod, file moves) on behalf of a remote caller, so
// every value that reaches exec.Command or the filesystem is validated
// here first -- an argument that merely looks like an IP or a username
// must not be able to smuggle in an iptables flag or escape a directory.
package validate

import (
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	usernameRe = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
	tokenRe    = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
)

var protectedUsers = map[string]struct{}{
	"root": {}, "daemon": {}, "bin": {}, "sys": {}, "sync": {}, "nobody": {},
	"systemd-network": {}, "systemd-resolve": {}, "systemd-timesync": {},
}

// Paths the agent will never quarantine, even on an authenticated request:
// removing them can brick the host. Exact matches first, then prefixes.
var quarantineDenyExact = map[string]struct{}{
	"/": {}, "/etc": {}, "/usr": {}, "/bin": {}, "/sbin": {}, "/lib": {}, "/lib64": {},
	"/etc/passwd": {}, "/etc/shadow": {}, "/etc/group": {}, "/etc/sudoers": {},
}

var quarantineDenyPrefix = []string{"/proc", "/sys", "/dev", "/boot", "/run"}

// IPv4 returns the canonical dotted form of s, or an error if s is not a
// usable unicast IPv4 address. Loopback/unspecified are refused: firewalling
// 127.0.0.1 or 0.0.0.0 would cut the host off from itself.
func IPv4(s string) (string, error) {
	ip := net.ParseIP(strings.TrimSpace(s))
	if ip == nil || ip.To4() == nil {
		return "", errors.New("not a valid IPv4 address")
	}
	if ip.IsLoopback() || ip.IsUnspecified() {
		return "", errors.New("refusing loopback/unspecified address")
	}
	return ip.To4().String(), nil
}

// Username accepts only POSIX-portable lowercase account names and refuses
// system/protected accounts.
func Username(s string) (string, error) {
	if !usernameRe.MatchString(s) {
		return "", errors.New("invalid username")
	}
	if _, bad := protectedUsers[s]; bad {
		return "", fmt.Errorf("refusing to act on protected account %q", s)
	}
	return s, nil
}

// PID rejects init and the agent itself.
func PID(pid, self int) error {
	if pid <= 1 {
		return errors.New("refusing pid <= 1")
	}
	if pid == self {
		return errors.New("refusing to signal the agent itself")
	}
	return nil
}

// Token validates a short identifier that ends up inside a filename.
func Token(s string) error {
	if !tokenRe.MatchString(s) {
		return errors.New("invalid token (want 1-64 chars of A-Za-z0-9_-)")
	}
	return nil
}

// AbsPath requires an absolute, NUL-free path and returns it cleaned.
func AbsPath(p string) (string, error) {
	if p == "" || strings.ContainsRune(p, 0) || !filepath.IsAbs(p) {
		return "", errors.New("path must be absolute")
	}
	return filepath.Clean(p), nil
}

// Within reports whether path is strictly inside root (not equal to it).
func Within(path, root string) bool {
	rel, err := filepath.Rel(filepath.Clean(root), filepath.Clean(path))
	if err != nil || rel == "." || rel == ".." {
		return false
	}
	return !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// WithinOrEqual is Within, but root itself also counts.
func WithinOrEqual(path, root string) bool {
	return filepath.Clean(path) == filepath.Clean(root) || Within(path, root)
}

// QuarantineAllowed rejects paths that must never be moved.
func QuarantineAllowed(path, quarantineDir string) error {
	if WithinOrEqual(path, quarantineDir) {
		return errors.New("path is inside the quarantine directory")
	}
	if _, bad := quarantineDenyExact[path]; bad {
		return fmt.Errorf("refusing to quarantine protected path %q", path)
	}
	for _, p := range quarantineDenyPrefix {
		if WithinOrEqual(path, p) {
			return fmt.Errorf("refusing to quarantine anything under %s", p)
		}
	}
	return nil
}
