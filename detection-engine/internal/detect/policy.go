package detect

import (
	"net"
	"sentinelmesh/detection-engine/internal/policy"
	"sentinelmesh/detection-engine/internal/types"
	"strings"
)

type RuntimePolicyRule struct{ source func() policy.Document }

func NewRuntimePolicyRule(source func() policy.Document) *RuntimePolicyRule {
	return &RuntimePolicyRule{source: source}
}
func (r *RuntimePolicyRule) Name() string { return "runtime_policy" }
func (r *RuntimePolicyRule) Evaluate(ev types.Event) (float64, bool) {
	p := r.source()
	if ev.Network != nil {
		for _, blocked := range p.BlockedIPs {
			if net.ParseIP(strings.TrimSpace(blocked)) != nil && (ev.Network.SrcIP == blocked || ev.Network.DstIP == blocked) {
				return 0.99, true
			}
		}
	}
	if ev.Process != nil {
		cmd := strings.ToLower(ev.Process.Cmdline)
		for _, pat := range p.ExtraCommandPatterns {
			if pat != "" && strings.Contains(cmd, strings.ToLower(pat)) {
				return 0.97, true
			}
		}
	}
	return 0, false
}
