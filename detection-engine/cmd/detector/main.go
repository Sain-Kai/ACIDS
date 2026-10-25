// Command detector is the entrypoint for the hot-path pipeline:
// ingest -> normalize -> detect -> respond -> record incident.
package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"sentinelmesh/detection-engine/internal/audit"
	"sentinelmesh/detection-engine/internal/detect"
	"sentinelmesh/detection-engine/internal/incident"
	"sentinelmesh/detection-engine/internal/ingest"
	"sentinelmesh/detection-engine/internal/metrics"
	"sentinelmesh/detection-engine/internal/normalize"
	"sentinelmesh/detection-engine/internal/policy"
	"sentinelmesh/detection-engine/internal/response"
	"sentinelmesh/detection-engine/internal/types"
)

type Config struct {
	FalcoHTTPAddr    string `json:"falco_http_addr"`
	FalcoHTTPPath    string `json:"falco_http_path"`
	PolicyPath       string `json:"policy_path"`
	PolicySigningKey string `json:"policy_signing_key"`
	EventFile        string `json:"event_file"`
	Thresholds       struct {
		Contain float64 `json:"contain"`
		Block   float64 `json:"block"`
		Reclaim float64 `json:"reclaim"`
	} `json:"thresholds"`
	QuarantineDir      string `json:"quarantine_dir"`
	HostRoot           string `json:"host_root"`
	ControlPlaneURL    string `json:"control_plane_url"`
	ControlPlaneAPIKey string `json:"control_plane_api_key"`
	ResponseMode       string `json:"response_mode"` // enforce (default), dry-run, disabled
}

func loadConfig(path string) (Config, error) {
	var cfg Config
	b, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		return cfg, err
	}
	applyEnvOverrides(&cfg)
	return cfg, nil
}

// applyEnvOverrides lets container/orchestration environments (see
// deploy/docker-compose.yml) override individual config.yaml values
// without needing a different YAML file per environment. YAML values are
// the defaults; a set env var always wins.
func applyEnvOverrides(cfg *Config) {
	if v := os.Getenv("FALCO_HTTP_ADDR"); v != "" {
		cfg.FalcoHTTPAddr = v
	}
	if v := os.Getenv("FALCO_HTTP_PATH"); v != "" {
		cfg.FalcoHTTPPath = v
	}
	if v := os.Getenv("QUARANTINE_DIR"); v != "" {
		cfg.QuarantineDir = v
	}
	if v := os.Getenv("HOST_ROOT"); v != "" {
		cfg.HostRoot = v
	}
	if v := os.Getenv("CONTROL_PLANE_URL"); v != "" {
		cfg.ControlPlaneURL = v
	}
	if v := os.Getenv("CONTROL_PLANE_API_KEY"); v != "" {
		cfg.ControlPlaneAPIKey = v
	}
	if v := os.Getenv("POLICY_PATH"); v != "" {
		cfg.PolicyPath = v
	}
	if v := os.Getenv("POLICY_SIGNING_KEY"); v != "" {
		cfg.PolicySigningKey = v
	}
	if v := os.Getenv("SENTINELMESH_EVENT_FILE"); v != "" {
		cfg.EventFile = v
	}
	if v := os.Getenv("RESPONSE_MODE"); v != "" {
		cfg.ResponseMode = v
	}
}

// runWithBackoff keeps an ingest source's Stream running, reconnecting
// with a capped exponential backoff whenever it returns a non-context
// error (dropped connection, Falco restarted, etc). It gives up only when
// ctx is cancelled.
func runWithBackoff(ctx context.Context, name string, stream func() error) {
	backoff := time.Second
	const maxBackoff = 30 * time.Second

	for {
		if ctx.Err() != nil {
			return
		}
		err := stream()
		if ctx.Err() != nil {
			return
		}
		if name == "event-file" {
			// JSONL is a finite integration/offline source. Do not replay it
			// forever after EOF; real Falco/eBPF sources are the only
			// continuously reconnecting streams.
			return
		}
		if err != nil {
			log.Printf("%s source error: %v (retrying in %s)", name, err, backoff)
		} else {
			log.Printf("%s source stopped cleanly (retrying in %s)", name, backoff)
		}
		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return
		}
		if backoff < maxBackoff {
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		}
	}
}

func watchPolicy(ctx context.Context, path, key string, store *policy.Store) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	var last int64
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			doc, _, err := policy.Read(path, key)
			if err != nil {
				continue
			}
			if doc.Version > last {
				store.Swap(doc)
				last = doc.Version
				log.Printf("activated verified runtime policy version=%d", doc.Version)
			}
		}
	}
}

func main() {
	cfg, err := loadConfig("config/config.json")
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if cfg.PolicySigningKey == "" {
		log.Println("warning: POLICY_SIGNING_KEY not set; runtime policy updates are disabled")
	}
	initialPolicy := policy.Document{Version: 1, GeneratedAt: time.Now().UTC().Format(time.RFC3339Nano),
		ContainThreshold: &cfg.Thresholds.Contain, BlockThreshold: &cfg.Thresholds.Block, ReclaimThreshold: &cfg.Thresholds.Reclaim}
	policyStore := policy.NewStore(initialPolicy)
	if cfg.PolicyPath != "" && cfg.PolicySigningKey != "" {
		if doc, _, err := policy.Read(cfg.PolicyPath, cfg.PolicySigningKey); err == nil {
			policyStore.Swap(doc)
			log.Printf("loaded verified runtime policy version=%d", doc.Version)
		} else if !os.IsNotExist(err) {
			log.Printf("runtime policy rejected: %v", err)
		}
		go watchPolicy(ctx, cfg.PolicyPath, cfg.PolicySigningKey, policyStore)
	}

	rawCh := make(chan types.RawEvent, 1024)

	if strings.TrimSpace(cfg.FalcoHTTPAddr) != "" {
		falcoHTTP := ingest.NewFalcoHTTPReceiver(cfg.FalcoHTTPAddr, cfg.FalcoHTTPPath, rawCh)
		go func() {
			if err := falcoHTTP.Start(ctx); err != nil && ctx.Err() == nil {
				log.Printf("falco-http source error: %v", err)
			}
		}()
	}
	ebpf := ingest.NewEBPFSource()
	go runWithBackoff(ctx, "ebpf", func() error { return ebpf.Stream(ctx, rawCh) })
	if cfg.EventFile != "" {
		fileSrc := ingest.NewFileSource(cfg.EventFile)
		go runWithBackoff(ctx, "event-file", func() error { return fileSrc.Stream(ctx, rawCh) })
	}

	if cfg.ResponseMode == "" {
		cfg.ResponseMode = "enforce"
	}
	if cfg.ResponseMode == "enforce" && strings.TrimSpace(cfg.ControlPlaneAPIKey) == "" {
		log.Fatal("config: CONTROL_PLANE_API_KEY must be set when RESPONSE_MODE=enforce")
	}
	if cfg.PolicyPath != "" && strings.TrimSpace(cfg.PolicySigningKey) == "" {
		log.Fatal("config: POLICY_SIGNING_KEY must be set when POLICY_PATH is configured")
	}

	engine := detect.NewEngine(
		append(detect.DefaultRules(), detect.NewRuntimePolicyRule(policyStore.Load)),
		cfg.Thresholds.Block,
		cfg.Thresholds.Contain,
		cfg.Thresholds.Reclaim,
	)
	engine.PolicySource = policyStore.Load

	auditPath := os.Getenv("LOCAL_AUDIT_LOG_PATH")
	if auditPath == "" {
		auditPath = "/var/lib/sentinelmesh/audit/detector.log"
	}
	localAudit, err := audit.New(auditPath)
	if err != nil {
		log.Fatalf("local audit: %v", err)
	}

	spoolDir := os.Getenv("INCIDENT_SPOOL_DIR")
	if spoolDir == "" {
		spoolDir = "/var/lib/sentinelmesh/incidents/outbox"
	}
	forwarder := incident.NewForwarder(cfg.ControlPlaneURL, cfg.ControlPlaneAPIKey, 4096, 2, spoolDir)
	defer forwarder.Close()
	var counters metrics.Counters
	go func() {
		addr := os.Getenv("METRICS_ADDR")
		if addr == "" {
			addr = ":2112"
		}
		if err := http.ListenAndServe(addr, metrics.Handler(&counters)); err != nil {
			log.Printf("metrics server stopped: %v", err)
		}
	}()

	log.Println("sentinelmesh detection-engine: hot path running")

	for {
		select {
		case <-ctx.Done():
			log.Println("shutting down")
			return
		case raw := <-rawCh:
			counters.Events.Add(1)
			ev, err := normalize.Normalize(raw)
			if err != nil {
				counters.NormalizeErrors.Add(1)
				log.Printf("normalize error: %v", err)
				continue
			}

			verdict := engine.Evaluate(ev)

			var actionErr error
			if verdict.Action != types.ActionNone {
				counters.Detections.Add(1)
				if cfg.ResponseMode == "dry-run" {
					log.Printf("DRY-RUN response action=%s score=%.2f event=%s", verdict.Action, verdict.Score, ev.EventID)
				} else if cfg.ResponseMode != "disabled" {
					actionErr = response.Dispatch(verdict, ev, cfg.QuarantineDir, cfg.HostRoot)
				}
				if actionErr != nil {
					log.Printf("response action failed: %v", actionErr)
				} else {
					counters.Containments.Add(1)
				}
				success := actionErr == nil && cfg.ResponseMode != "dry-run" && cfg.ResponseMode != "disabled"
				if err := localAudit.Record(ev, verdict, success, actionErr); err != nil {
					log.Printf("LOCAL_AUDIT_FAILURE event=%s action=%s err=%v", ev.EventID, verdict.Action, err)
				}
			}

			// Only security-relevant verdicts become incidents. Benign telemetry
			// stays in the event stream and does not trigger the LLM path.
			if verdict.Action != types.ActionNone {
				inc := incident.New(ev, verdict, actionErr)
				if (verdict.Action == types.ActionQuarantineFile || verdict.Action == types.ActionEscalateToReclaim) && ev.File != nil {
					candidate := response.QuarantineDestPath(cfg.QuarantineDir, ev.EventID, ev.File.Path)
					if actionErr == nil {
						inc.QuarantinePath = candidate
					}
				}
				if !forwarder.Submit(inc) {
					counters.QueueDrops.Add(1)
					log.Printf("incident delivery queue full: incident=%s score=%.2f action=%s", inc.IncidentID, verdict.Score, verdict.Action)
				}
				if verdict.Action == types.ActionEscalateToReclaim {
					counters.Reclaims.Add(1)
				}
			}

			if verdict.Action == types.ActionEscalateToReclaim {
				log.Printf("ESCALATION: event %s crossed reclaim threshold (score=%.2f) — control-plane should trigger ReclaimProtocolService", ev.EventID, verdict.Score)
			}
		}
	}
}
