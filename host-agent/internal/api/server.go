// Package api is host-agent's HTTP surface: control-plane's
// HostAgentClient calls these endpoints to run privileged actions on this
// host. Every non-health endpoint requires the X-SentinelMesh-Api-Key
// header -- same auth pattern as control-plane's ApiKeyAuthFilter and
// llm-orchestration's app.py, for a consistent story across all four
// services.
package api

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"sentinelmesh/host-agent/internal/actions"
	"sentinelmesh/host-agent/internal/config"
)

const apiKeyHeader = "X-SentinelMesh-Api-Key"

type Server struct {
	cfg         config.Config
	snapshotter *actions.Snapshotter
}

func New(cfg config.Config) *Server {
	return &Server{
		cfg: cfg,
		snapshotter: &actions.Snapshotter{
			Root:     cfg.SnapshotDir,
			Paths:    cfg.SnapshotPaths,
			Keep:     cfg.SnapshotKeep,
			HostRoot: cfg.HostRoot,
		},
	}
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /v1/identity", s.auth(s.handleIdentity))
	mux.HandleFunc("POST /v1/kill", s.auth(s.handleKill))
	mux.HandleFunc("POST /v1/account/lock", s.auth(s.handleLockAccount))
	mux.HandleFunc("POST /v1/quarantine", s.auth(s.handleQuarantine))
	mux.HandleFunc("POST /v1/network/isolate", s.auth(s.handleIsolate))
	mux.HandleFunc("POST /v1/network/lift", s.auth(s.handleLift))
	mux.HandleFunc("POST /v1/snapshot", s.auth(s.handleSnapshot))
	mux.HandleFunc("POST /v1/restore", s.auth(s.handleRestore))
	mux.HandleFunc("POST /v1/persistence-scan", s.auth(s.handlePersistenceScan))
	mux.HandleFunc("POST /v1/sandbox-analyze", s.auth(s.handleSandboxAnalyze))
	mux.HandleFunc("GET /v1/policy/status", s.auth(s.handlePolicyStatus))
	mux.HandleFunc("POST /v1/policy/apply", s.auth(s.handlePolicyApply))
	mux.HandleFunc("POST /v1/policy/rollback", s.auth(s.handlePolicyRollback))
	return withRequestLogging(mux)
}

func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		provided := r.Header.Get(apiKeyHeader)
		if subtle.ConstantTimeCompare([]byte(provided), []byte(s.cfg.APIKey)) != 1 {
			writeError(w, http.StatusUnauthorized, "missing or invalid "+apiKeyHeader)
			return
		}
		next(w, r)
	}
}

func withRequestLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %s", r.Method, r.URL.Path, time.Since(start))
	})
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleIdentity(w http.ResponseWriter, r *http.Request) {
	hostname, ip, err := hostIdentity()
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"hostname": hostname, "ip": ip})
}

func hostIdentity() (string, string, error) {
	h, err := os.Hostname()
	if err != nil || h == "" {
		return "", "", fmt.Errorf("cannot determine host identity: %v", err)
	}
	if override := os.Getenv("SENTINELMESH_HOST_IP"); override != "" {
		if net.ParseIP(override) == nil || net.ParseIP(override).To4() == nil {
			return "", "", fmt.Errorf("SENTINELMESH_HOST_IP is not a valid IPv4 address")
		}
		return h, override, nil
	}
	ifs, err := net.Interfaces()
	if err != nil {
		return "", "", fmt.Errorf("list interfaces: %w", err)
	}
	for _, iface := range ifs {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip != nil && ip.To4() != nil && !ip.IsLoopback() {
				return h, ip.To4().String(), nil
			}
		}
	}
	return "", "", fmt.Errorf("no non-loopback IPv4 address available")
}

// --- request/response plumbing -----------------------------------------

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return false
	}
	return true
}
