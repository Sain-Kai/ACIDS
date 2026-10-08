package normalize

import (
	"net"
	"os"
	"testing"
	"time"

	"sentinelmesh/detection-engine/internal/types"
)

// This file exists because Host.Hostname/Host.IP going unset was a real
// bug that sat undetected through several rounds of building on top of
// it (control-plane's entire host-agent addressing scheme, and
// detection-engine's own IsolateWorkloadAction, both silently no-op
// without these). Locking the fix in with tests, not just a comment.

func TestDetectHostnameMatchesOSHostname(t *testing.T) {
	want, err := os.Hostname()
	if err != nil {
		t.Skip("os.Hostname() unavailable in this environment")
	}
	if got := detectHostname(); got != want {
		t.Errorf("detectHostname() = %q, want %q", got, want)
	}
}

func TestDetectLocalIPReturnsValidIPv4OrEmpty(t *testing.T) {
	got := detectLocalIP()
	if got == "" {
		t.Skip("no default route in this environment -- empty is the documented fallback")
	}
	if net.ParseIP(got) == nil {
		t.Errorf("detectLocalIP() = %q is not a parseable IP", got)
	}
}

func TestBaseEventStampsHostInfo(t *testing.T) {
	ev := baseEvent(types.RawEvent{Source: "falco", Timestamp: time.Now()})
	if ev.Host.Hostname == "" {
		t.Error("expected baseEvent to stamp a non-empty Host.Hostname")
	}
}

func TestNormalizeFalcoPreservesHostInfo(t *testing.T) {
	raw := types.RawEvent{
		Source:    "falco",
		Timestamp: time.Now(),
		Payload: map[string]interface{}{
			"rule":         "Test Rule",
			"container.id": "abc123",
		},
	}
	ev, err := Normalize(raw)
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if ev.Host.Hostname == "" {
		t.Error("expected normalizeFalco's result to still have Host.Hostname set")
	}
	if ev.Host.ContainerID != "abc123" {
		t.Errorf("expected ContainerID to be set alongside Hostname, got %q", ev.Host.ContainerID)
	}
}

func TestNormalizeEBPFPreservesHostInfo(t *testing.T) {
	raw := types.RawEvent{
		Source:    "ebpf",
		Timestamp: time.Now(),
		Payload: map[string]interface{}{
			"event_type": "process_exec",
			"pid":        1234,
			"proc.exe":   "/bin/bash",
		},
	}
	ev, err := Normalize(raw)
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if ev.Host.Hostname == "" {
		t.Error("expected normalizeEBPF's result to still have Host.Hostname set")
	}
}

func TestNormalizeFalcoMapsSecurityTelemetry(t *testing.T) {
	raw := types.RawEvent{
		Source: "falco",
		Payload: map[string]interface{}{
			"rule":                       "Terminal shell in container",
			"priority":                   "Warning",
			"evt.type":                   "execve",
			"proc.pid":                   int64(42),
			"proc.ppid":                  int64(7),
			"proc.exe":                   "/bin/bash",
			"proc.cmdline":               "/bin/bash -c id",
			"user.name":                  "www-data",
			"container.id":               "cid",
			"container.image.repository": "demo/app",
			"tags":                       []interface{}{"container", "shell"},
		},
	}
	ev, err := Normalize(raw)
	if err != nil {
		t.Fatal(err)
	}
	if ev.EventType != "process_exec" {
		t.Fatalf("event type = %q", ev.EventType)
	}
	if ev.Process == nil || ev.Process.PID != 42 || ev.Process.PPID != 7 || ev.Process.Cmdline == "" {
		t.Fatalf("process mapping incomplete: %+v", ev.Process)
	}
	if ev.Process.User != "www-data" || ev.Host.ContainerID != "cid" || ev.Host.ContainerImage != "demo/app" {
		t.Fatalf("metadata mapping incomplete: %+v %+v", ev.Process, ev.Host)
	}
	if len(ev.Tags) != 2 || ev.SeverityRaw != "warning" {
		t.Fatalf("severity/tags not normalized: severity=%q tags=%v", ev.SeverityRaw, ev.Tags)
	}
}

func TestNormalizeFalcoMapsNetworkAndFileTelemetry(t *testing.T) {
	network, err := Normalize(types.RawEvent{Source: "falco", Payload: map[string]interface{}{
		"evt.type": "connect", "fd.sip": "10.0.0.2", "fd.dip": "1.2.3.4", "fd.sport": "3456", "fd.dport": int64(443), "fd.l4proto": "TCP",
	}})
	if err != nil {
		t.Fatal(err)
	}
	if network.Network == nil || network.Network.DstIP != "1.2.3.4" || network.Network.DstPort != 443 || network.Network.Protocol != "tcp" {
		t.Fatalf("network mapping incomplete: %+v", network.Network)
	}

	file, err := Normalize(types.RawEvent{Source: "falco", Payload: map[string]interface{}{
		"evt.type": "openat", "fd.name": "/etc/cron.d/dropper", "proc.pid": int64(9),
	}})
	if err != nil {
		t.Fatal(err)
	}
	if file.File == nil || file.File.Path != "/etc/cron.d/dropper" || file.File.Operation != "write" {
		t.Fatalf("file mapping incomplete: %+v", file.File)
	}
}
