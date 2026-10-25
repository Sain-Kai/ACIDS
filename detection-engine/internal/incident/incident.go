// Package incident creates incident records and ships them off the hot path.
package incident

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"sentinelmesh/detection-engine/internal/id"
	"sentinelmesh/detection-engine/internal/types"
)

type Incident struct {
	IncidentID     string        `json:"incident_id"`
	Event          types.Event   `json:"event"`
	Verdict        types.Verdict `json:"verdict"`
	ActionError    string        `json:"action_error,omitempty"`
	QuarantinePath string        `json:"quarantine_path,omitempty"`
	CreatedAt      time.Time     `json:"created_at"`
}

func New(ev types.Event, v types.Verdict, actionErr error) Incident {
	inc := Incident{IncidentID: id.UUID(), Event: ev, Verdict: v, CreatedAt: time.Now().UTC()}
	if actionErr != nil {
		inc.ActionError = actionErr.Error()
	}
	return inc
}

// Forwarder ships incidents asynchronously so a slow/unreachable control plane
// cannot stall the deterministic detection loop. Critical containment happens
// locally before Submit returns. Delivery is retried with bounded backoff.
type Forwarder struct {
	url       string
	apiKey    string
	queue     chan Incident
	client    *http.Client
	maxRetry  int
	spoolDir  string
	workerCtx context.Context
	queueMu   sync.Mutex
	queued    map[string]struct{}
	cancel    context.CancelFunc
}

func NewForwarder(controlPlaneURL, apiKey string, queueSize, workers int, spoolDirs ...string) *Forwarder {
	if queueSize < 64 {
		queueSize = 64
	}
	if workers < 1 {
		workers = 1
	}
	ctx, cancel := context.WithCancel(context.Background())
	spoolDir := ""
	if len(spoolDirs) > 0 {
		spoolDir = spoolDirs[0]
	}
	f := &Forwarder{
		url: controlPlaneURL, apiKey: apiKey, queue: make(chan Incident, queueSize),
		client: &http.Client{Timeout: 750 * time.Millisecond}, maxRetry: 4,
		spoolDir:  spoolDir,
		queued:    make(map[string]struct{}),
		workerCtx: ctx, cancel: cancel,
	}
	if spoolDir != "" {
		if err := os.MkdirAll(spoolDir, 0o700); err != nil {
			log.Printf("incident spool unavailable path=%s err=%v; delivery remains memory-only", spoolDir, err)
			f.spoolDir = ""
		}
	}
	for i := 0; i < workers; i++ {
		go f.worker()
	}
	if f.spoolDir != "" {
		go f.replayLoop()
	}
	return f
}

func (f *Forwarder) Close() { f.cancel() }

func (f *Forwarder) Submit(inc Incident) bool {
	if f.spoolDir != "" {
		if err := f.persist(inc); err != nil {
			log.Printf("incident spool write failed: incident=%s err=%v", inc.IncidentID, err)
			return false
		}
		// Durable spool is the source of truth. A temporarily full RAM queue
		// is backpressure, not data loss; replayLoop will enqueue the file later.
		_ = f.enqueue(inc)
		return true
	}
	return f.enqueue(inc)
}

func (f *Forwarder) enqueue(inc Incident) bool {
	f.queueMu.Lock()
	if _, ok := f.queued[inc.IncidentID]; ok {
		f.queueMu.Unlock()
		return true
	}
	select {
	case f.queue <- inc:
		f.queued[inc.IncidentID] = struct{}{}
		f.queueMu.Unlock()
		return true
	default:
		f.queueMu.Unlock()
		return false
	}
}

func (f *Forwarder) worker() {
	for {
		select {
		case <-f.workerCtx.Done():
			return
		case inc := <-f.queue:
			f.deliver(inc)
			f.queueMu.Lock()
			delete(f.queued, inc.IncidentID)
			f.queueMu.Unlock()
		}
	}
}

func (f *Forwarder) deliver(inc Incident) {
	var lastErr error
	for attempt := 0; attempt <= f.maxRetry; attempt++ {
		if attempt > 0 {
			delay := 100 * time.Millisecond * time.Duration(1<<(attempt-1))
			select {
			case <-time.After(delay):
			case <-f.workerCtx.Done():
				return
			}
		}
		if err := forwardOnce(f.workerCtx, f.client, f.url, f.apiKey, inc); err == nil {
			f.removeSpool(inc.IncidentID)
			return
		} else {
			lastErr = err
		}
	}
	log.Printf("incident delivery failed after %d attempts: incident=%s err=%v", f.maxRetry+1, inc.IncidentID, lastErr)
}

func forwardOnce(ctx context.Context, client *http.Client, controlPlaneURL, apiKey string, inc Incident) error {
	body, err := json.Marshal(inc)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, controlPlaneURL+"/incidents", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-SentinelMesh-Api-Key", apiKey)
	req.Header.Set("Idempotency-Key", inc.IncidentID)

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("incident: control-plane returned %d", resp.StatusCode)
	}
	return nil
}

func (f *Forwarder) persist(inc Incident) error {
	b, err := json.Marshal(inc)
	if err != nil {
		return err
	}
	tmp := filepath.Join(f.spoolDir, "."+inc.IncidentID+".tmp")
	dst := filepath.Join(f.spoolDir, inc.IncidentID+".json")
	file, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(b); err != nil {
		_ = file.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func (f *Forwarder) removeSpool(incidentID string) {
	if f.spoolDir == "" {
		return
	}
	_ = os.Remove(filepath.Join(f.spoolDir, incidentID+".json"))
}

func (f *Forwarder) replayLoop() {
	ticker := time.NewTicker(750 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-f.workerCtx.Done():
			return
		case <-ticker.C:
			entries, err := os.ReadDir(f.spoolDir)
			if err != nil {
				continue
			}
			for _, e := range entries {
				if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
					continue
				}
				b, err := os.ReadFile(filepath.Join(f.spoolDir, e.Name()))
				if err != nil {
					continue
				}
				var inc Incident
				if json.Unmarshal(b, &inc) != nil || inc.IncidentID == "" {
					log.Printf("invalid incident spool entry=%s; leaving in place for inspection", e.Name())
					continue
				}
				if !f.enqueue(inc) {
					break
				}
			}
		}
	}
}

// Forward is retained for callers/tests that need a direct synchronous send.
// Production detector code should use Forwarder.Submit instead.
func Forward(controlPlaneURL, apiKey string, inc Incident) error {
	return forwardOnce(context.Background(), &http.Client{Timeout: 2 * time.Second}, controlPlaneURL, apiKey, inc)
}
