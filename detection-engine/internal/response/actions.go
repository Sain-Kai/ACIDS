// Package response executes immediate containment actions once the
// detection engine crosses a threshold. These run synchronously on the hot
// path, so each Execute should be fast and should never block on a network
// call to anything slow (IAM, ticketing, LLMs).
package response

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"sentinelmesh/detection-engine/internal/types"
)

type Action interface {
	Execute(ev types.Event) error
}

// Dispatch maps a Verdict's action to a concrete Action and runs it.
func Dispatch(v types.Verdict, ev types.Event, quarantineDir, hostRoot string) error {
	switch v.Action {
	case types.ActionNone:
		return nil
	case types.ActionKillProcess:
		return KillProcessAction{}.Execute(ev)
	case types.ActionIsolateWorkload:
		return IsolateWorkloadAction{}.Execute(ev)
	case types.ActionBlockNetwork:
		return BlockNetworkAction{}.Execute(ev)
	case types.ActionQuarantineFile:
		return QuarantineArtifactAction{Dir: quarantineDir, HostRoot: hostRoot}.Execute(ev)
	case types.ActionRevokeAccess:
		return RevokeAccessAction{}.Execute(ev)
	case types.ActionEscalateToReclaim:
		// Reclaim is not a substitute for immediate containment. Do the
		// cheapest local actions first, then hand the incident to control-plane.
		return EmergencyContainmentAction{QuarantineDir: quarantineDir, HostRoot: hostRoot}.Execute(ev)
	default:
		return fmt.Errorf("response: unhandled action %q", v.Action)
	}
}

// EmergencyContainmentAction is the P0/P1 bridge. It never performs a network
// call to a control-plane or LLM. It attempts every locally-available primitive
// on the same event and returns the first error while still trying the rest.
type EmergencyContainmentAction struct {
	QuarantineDir string
	HostRoot      string
}

func (a EmergencyContainmentAction) Execute(ev types.Event) error {
	var firstErr error
	attempted := false
	remember := func(err error) {
		attempted = true
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}

	if ev.Process != nil && ev.Process.PID != 0 {
		remember(KillProcessAction{}.Execute(ev))
	}
	if ev.Host.IP != "" {
		remember(IsolateWorkloadAction{}.Execute(ev))
	}
	if ev.File != nil && ev.File.Path != "" && a.QuarantineDir != "" {
		remember((QuarantineArtifactAction{Dir: a.QuarantineDir, HostRoot: a.HostRoot}).Execute(ev))
	}
	if !attempted {
		return fmt.Errorf("reclaim containment: no local containment primitive was available for event %s", ev.EventID)
	}
	return firstErr
}

// KillProcessAction sends SIGKILL to the offending PID. Real, not a stub —
// this is the cheapest, fastest containment action available.
type KillProcessAction struct{}

func (KillProcessAction) Execute(ev types.Event) error {
	if ev.Process == nil || ev.Process.PID == 0 {
		return fmt.Errorf("kill_process: no pid on event %s", ev.EventID)
	}
	if ev.Process.PID <= 1 || ev.Process.PID == os.Getpid() {
		return fmt.Errorf("kill_process: refusing unsafe pid=%d", ev.Process.PID)
	}
	if ev.Process.Exe != "" {
		actual, err := os.Readlink("/proc/" + fmt.Sprint(ev.Process.PID) + "/exe")
		if err != nil {
			return fmt.Errorf("kill_process: cannot verify pid=%d: %w", ev.Process.PID, err)
		}
		actual = strings.TrimSuffix(actual, " (deleted)")
		if filepath.Base(actual) == "" || filepath.Base(ev.Process.Exe) == "" || (filepath.Base(actual) != filepath.Base(ev.Process.Exe) && !strings.HasPrefix(filepath.Base(actual), filepath.Base(ev.Process.Exe)) && !strings.HasPrefix(filepath.Base(ev.Process.Exe), filepath.Base(actual))) {
			return fmt.Errorf("kill_process: pid=%d executable mismatch", ev.Process.PID)
		}
	}
	err := syscall.Kill(ev.Process.PID, syscall.SIGKILL)
	if errors.Is(err, syscall.ESRCH) {
		return nil
	}
	return err
}

// IsolateWorkloadAction removes network access from a host without
// killing the process outright — useful when you want to preserve process
// state for forensics while cutting off further damage. Real, not a
// implementation: it firewalls the host's IP off via iptables, leaving SSH
// open so responders can still reach it. control-plane's recover() step
// (Java IsolationService) reverses this with the identical rule specs
// once ReclaimProtocolService.verify() clears the host.
//
// Deployment boundary: this actuator intentionally protects a host as the
// security boundary. Dense multi-tenant/container deployments must supply a
// workload-specific network namespace/NetworkPolicy actuator instead.
type IsolateWorkloadAction struct{}

func (IsolateWorkloadAction) Execute(ev types.Event) error {
	if ev.Host.IP == "" {
		return fmt.Errorf("isolate_workload: no host ip on event %s", ev.EventID)
	}
	return IsolateHost(ev.Host.IP)
}

const isolateChain = "SENTINELMESH_ISOLATE"

// acceptRuleSpecs/dropRuleSpecs are shared between IsolateHost and
// LiftIsolation so the exact same rule content is inserted and later
// deleted -- iptables -D matches by rule spec, not position.
func acceptRuleSpecs(ip string) [][]string {
	return [][]string{
		{"-p", "tcp", "-s", ip, "--sport", "22", "-j", "ACCEPT"},
		{"-p", "tcp", "-d", ip, "--dport", "22", "-j", "ACCEPT"},
	}
}

func dropRuleSpecs(ip string) [][]string {
	return [][]string{
		{"-s", ip, "-j", "DROP"},
		{"-d", ip, "-j", "DROP"},
	}
}

// IsolateHost blocks all traffic to/from ip except SSH, via a dedicated
// iptables chain. Exported (rather than folded into Execute) so it's
// reusable and independently testable-by-inspection.
func IsolateHost(ip string) error {
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil || parsed.To4() == nil || parsed.IsLoopback() || parsed.IsUnspecified() {
		return fmt.Errorf("isolate_workload: refusing invalid/unsafe ip %q", ip)
	}
	ip = parsed.To4().String()
	if err := ensureIsolateChain(); err != nil {
		return fmt.Errorf("isolate_workload: ensure chain: %w", err)
	}
	// Accept rules use -I (insert at top) and drop rules use -A (append
	// at bottom) so the final order is always accept-before-drop,
	// regardless of what's already in the chain or the order these two
	// loops run in.
	for _, spec := range acceptRuleSpecs(ip) {
		if err := ensureRule(isolateChain, spec, true); err != nil {
			return fmt.Errorf("isolate_workload: insert accept rule: %w", err)
		}
	}
	for _, spec := range dropRuleSpecs(ip) {
		if err := ensureRule(isolateChain, spec, false); err != nil {
			return fmt.Errorf("isolate_workload: insert drop rule: %w", err)
		}
	}
	return nil
}

// LiftIsolation reverses IsolateHost for the same ip. It is idempotent so
// reclaim crash-resume can safely repeat the RECOVER step.
func LiftIsolation(ip string) error {
	clean := net.ParseIP(strings.TrimSpace(ip))
	if clean == nil || clean.To4() == nil || clean.IsLoopback() || clean.IsUnspecified() {
		return fmt.Errorf("lift_isolation: refusing invalid/unsafe ip %q", ip)
	}
	ip = clean.To4().String()
	var firstErr error
	all := append(acceptRuleSpecs(ip), dropRuleSpecs(ip)...)
	for _, spec := range all {
		if err := runIptables(append([]string{"-C", isolateChain}, spec...)...); err != nil {
			continue // already absent
		}
		if err := runIptables(append([]string{"-D", isolateChain}, spec...)...); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func ensureRule(chain string, spec []string, top bool) error {
	if err := runIptables(append([]string{"-C", chain}, spec...)...); err == nil {
		return nil
	}
	if top {
		return runIptables(append([]string{"-I", chain, "1"}, spec...)...)
	}
	return runIptables(append([]string{"-A", chain}, spec...)...)
}

func ensureIsolateChain() error {
	// -N fails harmlessly if the chain already exists -- ignore that
	// specific, expected case rather than trying to parse iptables'
	// error text to distinguish it from a real failure.
	_ = runIptables("-N", isolateChain)
	for _, builtin := range []string{"INPUT", "OUTPUT", "FORWARD"} {
		if err := runIptables("-C", builtin, "-j", isolateChain); err != nil {
			if err := runIptables("-I", builtin, "-j", isolateChain); err != nil {
				return err
			}
		}
	}
	return nil
}

func runIptables(args ...string) error {
	return exec.Command("iptables", args...).Run()
}

// BlockNetworkAction drops further traffic from/to an offending IP.
type BlockNetworkAction struct{}

func (BlockNetworkAction) Execute(ev types.Event) error {
	if ev.Network == nil {
		return fmt.Errorf("block_network: no network evidence on event %s", ev.EventID)
	}
	var firstErr error
	if src := net.ParseIP(strings.TrimSpace(ev.Network.SrcIP)); ev.Network.SrcIP != "" {
		if src == nil || src.IsLoopback() || src.IsUnspecified() || src.IsLinkLocalUnicast() {
			return fmt.Errorf("block_network: refusing unsafe source ip %q", ev.Network.SrcIP)
		}
		if v4 := src.To4(); v4 != nil {
			if err := exec.Command("iptables", "-I", "INPUT", "-s", v4.String(), "-j", "DROP").Run(); err != nil {
				firstErr = err
			}
		} else if firstErr == nil {
			firstErr = fmt.Errorf("block_network: IPv6 source blocking requires nftables/Falco network isolation adapter")
		}
	}
	if dst := net.ParseIP(strings.TrimSpace(ev.Network.DstIP)); ev.Network.DstIP != "" {
		if dst == nil || dst.IsLoopback() || dst.IsUnspecified() || dst.IsLinkLocalUnicast() {
			if firstErr == nil {
				firstErr = fmt.Errorf("block_network: refusing unsafe destination ip %q", ev.Network.DstIP)
			}
		} else if v4 := dst.To4(); v4 != nil {
			if err := exec.Command("iptables", "-I", "OUTPUT", "-d", v4.String(), "-j", "DROP").Run(); err != nil && firstErr == nil {
				firstErr = err
			}
		} else if firstErr == nil {
			firstErr = fmt.Errorf("block_network: IPv6 destination blocking requires nftables/Falco network isolation adapter")
		}
	}
	if ev.Network.SrcIP == "" && ev.Network.DstIP == "" {
		return fmt.Errorf("block_network: no source or destination ip on event %s", ev.EventID)
	}
	return firstErr
}

// QuarantineArtifactAction moves a suspicious file out of place and strips
// its permissions so it can't be executed or read by non-root, but is
// preserved for forensics/sandbox analysis.
type QuarantineArtifactAction struct {
	Dir      string
	HostRoot string
}

func (q QuarantineArtifactAction) Execute(ev types.Event) error {
	if ev.File == nil || ev.File.Path == "" {
		return fmt.Errorf("quarantine_file: no file path on event %s", ev.EventID)
	}
	if err := validateQuarantinePath(ev.File.Path, q.Dir); err != nil {
		return err
	}
	src, err := resolveHostPath(ev.File.Path, q.HostRoot)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(q.Dir, 0o700); err != nil {
		return err
	}
	dest := QuarantineDestPath(q.Dir, ev.EventID, ev.File.Path)
	if err := os.Rename(src, dest); err != nil {
		if !errors.Is(err, syscall.EXDEV) {
			return err
		}
		if err := copyFileLocal(src, dest); err != nil {
			return err
		}
		if err := os.Remove(src); err != nil {
			_ = os.Remove(dest)
			return err
		}
	}
	return os.Chmod(dest, 0o000)
}

func resolveHostPath(logicalPath, hostRoot string) (string, error) {
	clean, err := filepath.Abs(logicalPath)
	if err != nil {
		return "", err
	}
	root := strings.TrimSpace(hostRoot)
	if root == "" {
		root = "/"
	}
	root, err = filepath.Abs(root)
	if err != nil {
		return "", err
	}
	if root == "/" {
		return clean, nil
	}
	actual := filepath.Join(root, strings.TrimPrefix(clean, string(filepath.Separator)))
	rel, err := filepath.Rel(root, actual)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("host path escapes configured host root")
	}
	return actual, nil
}

func validateQuarantinePath(path, quarantineDir string) error {
	clean, err := filepath.Abs(path)
	if err != nil || clean != filepath.Clean(path) && !filepath.IsAbs(path) {
		return fmt.Errorf("quarantine_file: invalid path")
	}
	cleanQ, err := filepath.Abs(quarantineDir)
	if err != nil {
		return err
	}
	rel, _ := filepath.Rel(cleanQ, clean)
	if rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("quarantine_file: refusing path inside quarantine")
	}
	for _, prefix := range []string{"/proc", "/sys", "/dev", "/boot", "/run"} {
		if clean == prefix || strings.HasPrefix(clean, prefix+string(filepath.Separator)) {
			return fmt.Errorf("quarantine_file: refusing protected path %s", clean)
		}
	}
	for _, exact := range []string{"/", "/etc", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc/passwd", "/etc/shadow", "/etc/sudoers"} {
		if clean == exact {
			return fmt.Errorf("quarantine_file: refusing protected path %s", clean)
		}
	}
	return nil
}

func copyFileLocal(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, in)
	cerr := out.Close()
	if err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(dst)
	}
	return err
}

// QuarantineDestPath computes where QuarantineArtifactAction puts a file,
// given the same (dir, eventID, originalPath) inputs. Exported so callers
// (main.go) can record the resulting path on the Incident without having
// to re-derive it or thread extra return values through Dispatch.
func QuarantineDestPath(dir, eventID, originalPath string) string {
	return filepath.Join(dir, eventID+"_"+filepath.Base(originalPath))
}

// RevokeAccessAction revokes/rotates credentials associated with the
// event's user/process.
//
// RevokeAccessAction is intentionally non-operational on the detector hot path.
// Credential revocation is executed by the authenticated host/control-plane
// reclaim workflow, where retries, auditability and provider-specific adapters
// are available. The detector never pretends this action succeeded locally.
type RevokeAccessAction struct{}

func (RevokeAccessAction) Execute(ev types.Event) error {
	return fmt.Errorf("revoke_access: delegated to control-plane reclaim")
}
