package ingest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"sentinelmesh/detection-engine/internal/types"
)

// FalcoHTTPReceiver accepts Falco's JSON HTTP output and converts it into the
// same RawEvent contract used by the local eBPF source. Binding this listener
// to loopback on a protected host keeps the telemetry ingress local; TLS/mTLS
// should be used instead when the receiver is exposed over a network.
type FalcoHTTPReceiver struct {
	server *http.Server
	path   string
	out    chan<- types.RawEvent
}

func NewFalcoHTTPReceiver(addr, path string, out chan<- types.RawEvent) *FalcoHTTPReceiver {
	if strings.TrimSpace(path) == "" {
		path = "/falco/events"
	}
	mux := http.NewServeMux()
	r := &FalcoHTTPReceiver{path: path, out: out}
	mux.HandleFunc("POST "+path, r.handle)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	r.server = &http.Server{
		Addr:              addr,
		Handler:           requestLimits(mux),
		ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      5 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	return r
}

func requestLimits(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost && req.Method != http.MethodGet {
			w.Header().Set("Allow", "POST, GET")
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		next.ServeHTTP(w, req)
	})
}

// Start blocks until the listener stops or ctx is cancelled.
func (r *FalcoHTTPReceiver) Start(ctx context.Context) error {
	if r == nil || r.server == nil {
		return errors.New("falco http: receiver not initialized")
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = r.server.Shutdown(shutdownCtx)
	}()
	err := r.server.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return fmt.Errorf("falco http: listen: %w", err)
}

func (r *FalcoHTTPReceiver) handle(w http.ResponseWriter, req *http.Request) {
	if req.URL.Path != r.path {
		http.NotFound(w, req)
		return
	}
	if req.ContentLength > 2<<20 {
		http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
		return
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, req.Body, 2<<20))
	dec.UseNumber()
	var raw map[string]interface{}
	if err := dec.Decode(&raw); err != nil {
		http.Error(w, "invalid JSON payload", http.StatusBadRequest)
		return
	}
	if raw == nil {
		http.Error(w, "JSON object required", http.StatusBadRequest)
		return
	}

	payload := make(map[string]interface{}, len(raw)+8)
	for k, v := range raw {
		payload[k] = v
	}
	if fields, ok := raw["output_fields"].(map[string]interface{}); ok {
		for k, v := range fields {
			payload[k] = v
		}
	}
	if output := raw["output_fields"]; output != nil {
		payload["_falco_output_fields"] = output
	}

	ts := time.Now().UTC()
	if rawTS, ok := raw["time"].(string); ok && strings.TrimSpace(rawTS) != "" {
		if parsed, err := time.Parse(time.RFC3339Nano, rawTS); err == nil {
			ts = parsed
		}
	}
	payload["http_received_at"] = time.Now().UTC().Format(time.RFC3339Nano)

	select {
	case r.out <- types.RawEvent{Source: "falco", Timestamp: ts, Payload: payload}:
		w.WriteHeader(http.StatusAccepted)
	case <-time.After(25 * time.Millisecond):
		// Do not block an HTTP worker behind a saturated detector queue. A 503
		// tells Falco the consumer is under pressure and avoids turning the
		// detector into an unbounded memory sink.
		http.Error(w, "detector queue saturated", http.StatusServiceUnavailable)
	}
}
