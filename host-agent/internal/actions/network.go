package actions

import (
	"errors"
	"sentinelmesh/host-agent/internal/validate"
)

var errRuleStillPresent = errors.New("iptables isolation rule remains after lift")

// IsolateChain is the dedicated iptables chain SentinelMesh uses for
// host isolation, kept separate from a host's own rules so Isolate/Lift
// can be exact inverses of each other without touching anything else.
const IsolateChain = "SENTINELMESH_ISOLATE"

// acceptSpecs/dropSpecs are shared between Isolate and Lift so the exact
// same rule content is inserted and later deleted -- iptables -D matches
// by rule spec, not position.
func acceptSpecs(ip string) [][]string {
	return [][]string{
		{"-p", "tcp", "-s", ip, "--sport", "22", "-j", "ACCEPT"},
		{"-p", "tcp", "-d", ip, "--dport", "22", "-j", "ACCEPT"},
	}
}

func dropSpecs(ip string) [][]string {
	return [][]string{
		{"-s", ip, "-j", "DROP"},
		{"-d", ip, "-j", "DROP"},
	}
}

// Isolate blocks all traffic to/from ip except SSH, via IsolateChain.
// Accept rules are inserted at the top and drop rules appended at the
// bottom, so the final order is always accept-before-drop regardless of
// what's already in the chain.
func Isolate(ip string) error {
	clean, err := validate.IPv4(ip)
	if err != nil {
		return err
	}
	if err := ensureChain(); err != nil {
		return err
	}
	for _, spec := range acceptSpecs(clean) {
		if err := ensureRule(IsolateChain, spec, true); err != nil {
			return err
		}
	}
	for _, spec := range dropSpecs(clean) {
		if err := ensureRule(IsolateChain, spec, false); err != nil {
			return err
		}
	}
	return nil
}

// Lift reverses Isolate for the same ip. It is idempotent: rules that are
// already absent are treated as success. This is important for crash-resume
// of the reclaim protocol, where the RECOVER step may legitimately run twice.
func Lift(ip string) error {
	clean, err := validate.IPv4(ip)
	if err != nil {
		return err
	}
	var firstErr error
	all := append(acceptSpecs(clean), dropSpecs(clean)...)
	for _, spec := range all {
		if err := runCmd("iptables", append([]string{"-C", IsolateChain}, spec...)...); err != nil {
			continue // already absent
		}
		if err := runCmd("iptables", append([]string{"-D", IsolateChain}, spec...)...); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func ensureRule(chain string, spec []string, top bool) error {
	if err := runCmd("iptables", append([]string{"-C", chain}, spec...)...); err == nil {
		return nil
	}
	if top {
		return runCmd("iptables", append([]string{"-I", chain, "1"}, spec...)...)
	}
	return runCmd("iptables", append([]string{"-A", chain}, spec...)...)
}

func ensureChain() error {
	// -N fails harmlessly if the chain already exists -- ignore that
	// specific, expected case rather than trying to parse iptables'
	// error text to distinguish it from a real failure.
	_ = runCmd("iptables", "-N", IsolateChain)
	for _, builtin := range []string{"INPUT", "OUTPUT", "FORWARD"} {
		if err := runCmd("iptables", "-C", builtin, "-j", IsolateChain); err != nil {
			if err := runCmd("iptables", "-I", builtin, "-j", IsolateChain); err != nil {
				return err
			}
		}
	}
	return nil
}
