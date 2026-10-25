package detect

import (
	"strings"

	"sentinelmesh/detection-engine/internal/types"
)

// The rules below are a starter production-ish pack, grouped by the kind
// of malicious activity they target. Each is a small, single-purpose,
// well-understood detection heuristic -- the kind found in standard
// EDR/Falco/Sigma rule packs -- kept deterministic and cheap so they
// belong on the hot path. None of this is exotic: every pattern here is
// long-published, standard detection content (e.g. Falco's own default
// ruleset covers equivalents of most of these).

// ---------------------------------------------------------------------
// Initial access / execution
// ---------------------------------------------------------------------

// ShellFromWebProcessRule flags a shell spawned as a child of a common
// web-server/app-server process -- a classic web-shell / RCE indicator.
type ShellFromWebProcessRule struct{}

func (r ShellFromWebProcessRule) Name() string { return "shell_from_web_process" }

func (r ShellFromWebProcessRule) Evaluate(ev types.Event) (float64, bool) {
	if ev.Process == nil {
		return 0, false
	}
	shells := []string{"/bin/sh", "/bin/bash", "/bin/dash", "/bin/zsh"}
	webProcs := []string{"nginx", "apache2", "httpd", "java", "node", "python", "gunicorn", "uwsgi"}

	exe := strings.ToLower(ev.Process.Exe)
	if !containsAny(exe, shells) {
		return 0, false
	}

	parent, _ := ev.RawPayload["proc.pname"].(string)
	parent = strings.ToLower(parent)
	if containsAny(parent, webProcs) {
		return 0.85, true
	}
	return 0, false
}

// ReverseShellIndicatorRule flags command lines matching well-known
// reverse-shell one-liners (bash /dev/tcp redirection, `nc -e`, Python
// socket+dup2, etc). These patterns are extremely well-published; the
// value here is deterministic, fast recognition, not novel detection.
type ReverseShellIndicatorRule struct {
	Patterns []string
}

func NewReverseShellIndicatorRule() ReverseShellIndicatorRule {
	return ReverseShellIndicatorRule{Patterns: []string{
		"/dev/tcp/",
		"/dev/udp/",
		"nc -e",
		"ncat -e",
		"bash -i",
		"sh -i",
		"socket.socket(socket.af_inet",
		"os.dup2(s.fileno",
		"mkfifo /tmp/",
	}}
}

func (r ReverseShellIndicatorRule) Name() string { return "reverse_shell_indicator" }

func (r ReverseShellIndicatorRule) Evaluate(ev types.Event) (float64, bool) {
	if ev.Process == nil || ev.Process.Cmdline == "" {
		return 0, false
	}
	cmd := strings.ToLower(ev.Process.Cmdline)
	if containsAny(cmd, r.Patterns) {
		return 0.9, true
	}
	return 0, false
}

// ObfuscatedCommandRule flags command lines using common
// download-and-execute or decode-and-execute obfuscation patterns
// (`curl ... | sh`, `base64 -d | bash`, embedded eval of decoded output).
type ObfuscatedCommandRule struct {
	Patterns []string
}

func NewObfuscatedCommandRule() ObfuscatedCommandRule {
	return ObfuscatedCommandRule{Patterns: []string{
		"| sh",
		"| bash",
		"|sh",
		"|bash",
		"base64 -d",
		"base64 --decode",
		"eval $(echo",
		"eval \"$(echo",
		"curl -s http",
		"wget -q http",
	}}
}

func (r ObfuscatedCommandRule) Name() string { return "obfuscated_command" }

func (r ObfuscatedCommandRule) Evaluate(ev types.Event) (float64, bool) {
	if ev.Process == nil || ev.Process.Cmdline == "" {
		return 0, false
	}
	cmd := strings.ToLower(ev.Process.Cmdline)
	// A download-pipe pattern alone is common in legitimate install
	// scripts too, so score it lower than an outright reverse shell;
	// combined with other rules firing on the same event, the engine's
	// max-score aggregation still lets a truly bad event cross threshold.
	if containsAny(cmd, r.Patterns) {
		return 0.55, true
	}
	return 0, false
}

// MaskedExecutionPathRule flags a process executed from a path commonly
// used to hide dropped payloads (world-writable tmp dirs, dot-hidden
// directories).
type MaskedExecutionPathRule struct {
	SuspiciousPrefixes []string
}

func NewMaskedExecutionPathRule() MaskedExecutionPathRule {
	return MaskedExecutionPathRule{SuspiciousPrefixes: []string{
		"/tmp/.", "/dev/shm/", "/var/tmp/.", "/tmp/..",
	}}
}

func (r MaskedExecutionPathRule) Name() string { return "masked_execution_path" }

func (r MaskedExecutionPathRule) Evaluate(ev types.Event) (float64, bool) {
	if ev.Process == nil || ev.Process.Exe == "" {
		return 0, false
	}
	for _, p := range r.SuspiciousPrefixes {
		if strings.HasPrefix(ev.Process.Exe, p) {
			return 0.6, true
		}
	}
	return 0, false
}

// ---------------------------------------------------------------------
// Privilege escalation
// ---------------------------------------------------------------------

// PrivilegeEscalationRule flags su/sudo/pkexec spawned from a process
// that has no business escalating privileges interactively (a web/app
// server, rather than an interactive shell).
type PrivilegeEscalationRule struct {
	EscalationBinaries []string
	UnexpectedParents  []string
}

func NewPrivilegeEscalationRule() PrivilegeEscalationRule {
	return PrivilegeEscalationRule{
		EscalationBinaries: []string{"su", "sudo", "pkexec", "doas"},
		UnexpectedParents:  []string{"nginx", "apache2", "httpd", "java", "node", "python", "gunicorn", "uwsgi"},
	}
}

func (r PrivilegeEscalationRule) Name() string { return "privilege_escalation_from_service" }

func (r PrivilegeEscalationRule) Evaluate(ev types.Event) (float64, bool) {
	if ev.Process == nil {
		return 0, false
	}
	exe := strings.ToLower(ev.Process.Exe)
	if !containsAnySuffix(exe, r.EscalationBinaries) {
		return 0, false
	}
	parent, _ := ev.RawPayload["proc.pname"].(string)
	parent = strings.ToLower(parent)
	if containsAny(parent, r.UnexpectedParents) {
		return 0.9, true
	}
	return 0, false
}

// ---------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------

// PersistenceCronRule flags writes to cron-related paths -- a common
// persistence mechanism.
type PersistenceCronRule struct {
	Prefixes []string
}

func NewPersistenceCronRule() PersistenceCronRule {
	return PersistenceCronRule{Prefixes: []string{
		"/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.weekly",
		"/var/spool/cron", "/etc/crontab",
	}}
}

func (r PersistenceCronRule) Name() string { return "persistence_cron_write" }

func (r PersistenceCronRule) Evaluate(ev types.Event) (float64, bool) {
	if ev.File == nil || (ev.File.Operation != "write" && ev.File.Operation != "create") {
		return 0, false
	}
	for _, p := range r.Prefixes {
		if strings.HasPrefix(ev.File.Path, p) {
			return 0.9, true
		}
	}
	return 0, false
}

// PersistenceSystemdUnitRule flags creation/modification of a systemd
// unit file outside of normal package-manager activity. This heuristic
// alone can't distinguish "apt installed a service" from "attacker
// dropped a persistence unit" -- tune ContainerOnly / add a package-
// manager-parent exclusion before relying on it in production.
type PersistenceSystemdUnitRule struct {
	Prefixes []string
}

func NewPersistenceSystemdUnitRule() PersistenceSystemdUnitRule {
	return PersistenceSystemdUnitRule{Prefixes: []string{
		"/etc/systemd/system", "/lib/systemd/system", "/usr/lib/systemd/system",
	}}
}

func (r PersistenceSystemdUnitRule) Name() string { return "persistence_systemd_unit_write" }

func (r PersistenceSystemdUnitRule) Evaluate(ev types.Event) (float64, bool) {
	if ev.File == nil || (ev.File.Operation != "write" && ev.File.Operation != "create") {
		return 0, false
	}
	if !strings.HasSuffix(ev.File.Path, ".service") {
		return 0, false
	}
	for _, p := range r.Prefixes {
		if strings.HasPrefix(ev.File.Path, p) {
			return 0.65, true
		}
	}
	return 0, false
}

// SSHAuthorizedKeysRule flags writes to an authorized_keys file -- one of
// the most common persistence mechanisms once an attacker has a foothold.
type SSHAuthorizedKeysRule struct{}

func (r SSHAuthorizedKeysRule) Name() string { return "ssh_authorized_keys_write" }

func (r SSHAuthorizedKeysRule) Evaluate(ev types.Event) (float64, bool) {
	if ev.File == nil || (ev.File.Operation != "write" && ev.File.Operation != "create") {
		return 0, false
	}
	if strings.Contains(ev.File.Path, ".ssh/authorized_keys") {
		return 0.9, true
	}
	return 0, false
}

// ---------------------------------------------------------------------
// Defense evasion / discovery / credential access
// ---------------------------------------------------------------------

// SensitiveFileAccessRule flags writes to paths that should essentially
// never be written outside of package management / config management.
type SensitiveFileAccessRule struct {
	SensitivePrefixes []string
}

func NewSensitiveFileAccessRule() SensitiveFileAccessRule {
	return SensitiveFileAccessRule{
		SensitivePrefixes: []string{"/etc/shadow", "/etc/passwd", "/root/.ssh", "/etc/cron.d", "/etc/sudoers"},
	}
}

func (r SensitiveFileAccessRule) Name() string { return "sensitive_file_write" }

func (r SensitiveFileAccessRule) Evaluate(ev types.Event) (float64, bool) {
	if ev.File == nil || ev.File.Operation != "write" {
		return 0, false
	}
	for _, p := range r.SensitivePrefixes {
		if strings.HasPrefix(ev.File.Path, p) {
			return 0.95, true
		}
	}
	return 0, false
}

// CloudMetadataAccessRule flags outbound connections to the cloud
// provider instance-metadata service (169.254.169.254 is the address
// used by AWS/GCP/Azure alike). A common way to steal instance
// credentials once code execution is achieved, especially relevant for
// an SSRF-style entry point.
type CloudMetadataAccessRule struct{}

func (r CloudMetadataAccessRule) Name() string { return "cloud_metadata_access" }

func (r CloudMetadataAccessRule) Evaluate(ev types.Event) (float64, bool) {
	if ev.Network == nil {
		return 0, false
	}
	if ev.Network.DstIP == "169.254.169.254" {
		return 0.8, true
	}
	return 0, false
}

// ContainerEscapeIndicatorRule flags process activity referencing common
// container-escape vectors: the Docker control socket, or the host
// filesystem as seen through /proc/1/root.
type ContainerEscapeIndicatorRule struct {
	Patterns []string
}

func NewContainerEscapeIndicatorRule() ContainerEscapeIndicatorRule {
	return ContainerEscapeIndicatorRule{Patterns: []string{
		"/var/run/docker.sock",
		"/proc/1/root",
		"nsenter",
		"--privileged",
	}}
}

func (r ContainerEscapeIndicatorRule) Name() string { return "container_escape_indicator" }

func (r ContainerEscapeIndicatorRule) Evaluate(ev types.Event) (float64, bool) {
	if ev.Process == nil || ev.Process.Cmdline == "" {
		return 0, false
	}
	cmd := strings.ToLower(ev.Process.Cmdline)
	if containsAny(cmd, r.Patterns) {
		return 0.85, true
	}
	return 0, false
}

// ---------------------------------------------------------------------
// Impact (cryptomining is the most common "noisy" post-compromise
// monetization path and worth a dedicated, cheap signature)
// ---------------------------------------------------------------------

// CryptominerIndicatorRule flags common miner-binary command-line
// signatures and connections to typical stratum-protocol mining ports.
type CryptominerIndicatorRule struct {
	CmdlinePatterns []string
	StratumPorts    map[int]bool
}

func NewCryptominerIndicatorRule() CryptominerIndicatorRule {
	return CryptominerIndicatorRule{
		CmdlinePatterns: []string{"xmrig", "stratum+tcp", "minerd", "cpuminer", "ethminer"},
		StratumPorts:    map[int]bool{3333: true, 4444: true, 5555: true, 7777: true, 14444: true},
	}
}

func (r CryptominerIndicatorRule) Name() string { return "cryptominer_indicator" }

func (r CryptominerIndicatorRule) Evaluate(ev types.Event) (float64, bool) {
	if ev.Process != nil && ev.Process.Cmdline != "" {
		cmd := strings.ToLower(ev.Process.Cmdline)
		if containsAny(cmd, r.CmdlinePatterns) {
			return 0.85, true
		}
	}
	if ev.Network != nil && r.StratumPorts[ev.Network.DstPort] {
		return 0.6, true
	}
	return 0, false
}

// ---------------------------------------------------------------------
// Network
// ---------------------------------------------------------------------

// SuspiciousOutboundRule flags a connection to an uncommon high port --
// a common C2 callback pattern. Coarse by design; tune AllowedPorts
// against real traffic before relying on it alone.
type SuspiciousOutboundRule struct {
	AllowedPorts map[int]bool
}

func NewSuspiciousOutboundRule() SuspiciousOutboundRule {
	return SuspiciousOutboundRule{AllowedPorts: map[int]bool{80: true, 443: true, 53: true, 22: true}}
}

func (r SuspiciousOutboundRule) Name() string { return "suspicious_outbound_connection" }

func (r SuspiciousOutboundRule) Evaluate(ev types.Event) (float64, bool) {
	if ev.Network == nil || ev.EventType != "network_connect" {
		return 0, false
	}
	if r.AllowedPorts[ev.Network.DstPort] {
		return 0, false
	}
	if ev.Network.DstPort > 1024 {
		return 0.5, true
	}
	return 0, false
}

// ---------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------

func containsAny(haystack string, needles []string) bool {
	for _, n := range needles {
		if strings.Contains(haystack, n) {
			return true
		}
	}
	return false
}

func containsAnySuffix(haystack string, needles []string) bool {
	for _, n := range needles {
		if strings.HasSuffix(haystack, "/"+n) || haystack == n {
			return true
		}
	}
	return false
}

// DefaultRules returns the starter rule pack. Extend this -- or better,
// load rules from config/a rules directory -- as the pack grows.
func DefaultRules() []Rule {
	return []Rule{
		ShellFromWebProcessRule{},
		NewReverseShellIndicatorRule(),
		NewObfuscatedCommandRule(),
		NewMaskedExecutionPathRule(),
		NewPrivilegeEscalationRule(),
		NewPersistenceCronRule(),
		NewPersistenceSystemdUnitRule(),
		SSHAuthorizedKeysRule{},
		NewSensitiveFileAccessRule(),
		CloudMetadataAccessRule{},
		NewContainerEscapeIndicatorRule(),
		NewCryptominerIndicatorRule(),
		NewSuspiciousOutboundRule(),
	}
}
