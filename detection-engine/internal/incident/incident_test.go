package incident

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"sentinelmesh/detection-engine/internal/types"
)

func TestForwarderIsAsynchronousAndIdempotent(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		if r.Header.Get("Idempotency-Key") != "incident-1" {
			t.Errorf("missing idempotency key")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	f := NewForwarder(srv.URL, "k", 64, 1)
	defer f.Close()
	inc := Incident{IncidentID: "incident-1", CreatedAt: time.Now().UTC(), Event: types.Event{EventID: "event-1"}}
	if !f.Submit(inc) {
		t.Fatal("expected submit to enqueue")
	}
	deadline := time.Now().Add(2 * time.Second)
	for atomic.LoadInt32(&calls) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if atomic.LoadInt32(&calls) == 0 {
		t.Fatal("forwarder did not deliver")
	}
}

func TestForwarderDoesNotBlockWhenQueueIsFull(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	f := NewForwarder(srv.URL, "k", 64, 1)
	defer f.Close()
	for i := 0; i < 64; i++ {
		f.Submit(Incident{IncidentID: fmt.Sprintf("i-%d", i)})
	}
	start := time.Now()
	_ = f.Submit(Incident{IncidentID: "overflow"})
	if time.Since(start) > 25*time.Millisecond {
		t.Fatal("Submit blocked on a full queue")
	}
}

func TestForwarderDurableSpoolSurvivesControlPlaneOutage(t *testing.T) {
	dir := t.TempDir()
	srvURL := "http://127.0.0.1:1"
	f := NewForwarder(srvURL, "k", 64, 1, dir)
	inc := Incident{IncidentID: "spool-1", CreatedAt: time.Now().UTC(), Event: types.Event{EventID: "event-spool"}}
	if !f.Submit(inc) {
		t.Fatal("expected durable submit to succeed even when control plane is unavailable")
	}
	f.Close()
	if _, err := os.Stat(filepath.Join(dir, "spool-1.json")); err != nil {
		t.Fatalf("expected spool file: %v", err)
	}

	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { atomic.AddInt32(&calls, 1); w.WriteHeader(http.StatusOK) }))
	defer srv.Close()
	g := NewForwarder(srv.URL, "k", 64, 1, dir)
	defer g.Close()
	deadline := time.Now().Add(4 * time.Second)
	for atomic.LoadInt32(&calls) == 0 && time.Now().Before(deadline) {
		time.Sleep(25 * time.Millisecond)
	}
	if atomic.LoadInt32(&calls) == 0 {
		t.Fatal("spooled incident was not replayed")
	}
	if _, err := os.Stat(filepath.Join(dir, "spool-1.json")); !os.IsNotExist(err) {
		t.Fatalf("expected spool to be removed after delivery, err=%v", err)
	}
}
