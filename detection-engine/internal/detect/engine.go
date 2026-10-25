// Package detect is the deterministic hot-path detection engine. No LLM
// calls happen anywhere in this package — every decision here must resolve
// in-process, synchronously, with no network round-trip to a model.
package detect

import (
	"sentinelmesh/detection-engine/internal/policy"
	"sentinelmesh/detection-engine/internal/types"
)

// Rule is a single deterministic detection signature. Implementations
// should be cheap: this runs on every normalized event.
type Rule interface {
	Name() string
	// Evaluate returns a score contribution (0.0-1.0) and true if the rule
	// matched. A non-matching rule returns (0, false).
	Evaluate(ev types.Event) (score float64, matched bool)
}

// Engine aggregates rules into a single verdict and maps the resulting
// score onto a response action via configured thresholds.
type Engine struct {
	Rules []Rule
	// Thresholds, in ascending order of severity. Configure from
	// config/config.yaml — do not hardcode in production.
	BlockThreshold   float64 // e.g. 0.9 -> immediate hard containment
	ContainThreshold float64 // e.g. 0.6 -> softer containment (isolate)
	ReclaimThreshold float64 // e.g. 0.95 -> treat as likely-already-compromised
	PolicySource     func() policy.Document
}

func NewEngine(rules []Rule, block, contain, reclaim float64) *Engine {
	return &Engine{Rules: rules, BlockThreshold: block, ContainThreshold: contain, ReclaimThreshold: reclaim}
}

func (e *Engine) Evaluate(ev types.Event) types.Verdict {
	containThreshold, blockThreshold, reclaimThreshold := e.ContainThreshold, e.BlockThreshold, e.ReclaimThreshold
	if e.PolicySource != nil {
		p := e.PolicySource()
		if p.ContainThreshold != nil {
			containThreshold = *p.ContainThreshold
		}
		if p.BlockThreshold != nil {
			blockThreshold = *p.BlockThreshold
		}
		if p.ReclaimThreshold != nil {
			reclaimThreshold = *p.ReclaimThreshold
		}
	}
	var risk float64
	var matched []string

	for _, r := range e.Rules {
		score, ok := r.Evaluate(ev)
		if !ok {
			continue
		}
		matched = append(matched, r.Name())
		if score < 0 {
			score = 0
		}
		if score > 1 {
			score = 1
		}
		// Noisy-OR combines independent deterministic signals without
		// allowing simple addition to exceed 1.0. This is important for
		// correlated attack evidence: two medium-confidence rules can
		// legitimately cross the reclaim threshold together.
		risk = 1 - (1-risk)*(1-score)
	}
	if risk > 0.999 {
		risk = 0.999
	}

	v := types.Verdict{Score: risk, MatchedRules: matched, Action: types.ActionNone}

	switch {
	case risk >= reclaimThreshold:
		v.Action = types.ActionEscalateToReclaim
	case risk >= blockThreshold:
		// Route blocking to the fastest local primitive that matches the
		// evidence type. This keeps file/network containment concrete
		// instead of collapsing every high-confidence event into process kill.
		if ev.Network != nil && ev.Network.SrcIP != "" {
			v.Action = types.ActionBlockNetwork
		} else if ev.File != nil && ev.File.Path != "" {
			v.Action = types.ActionQuarantineFile
		} else {
			v.Action = types.ActionKillProcess
		}
	case risk >= containThreshold:
		v.Action = types.ActionIsolateWorkload
	}

	return v
}
