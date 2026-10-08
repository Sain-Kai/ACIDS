package api

import (
	"net/http"
	"os"
	"time"

	"sentinelmesh/host-agent/internal/actions"
	"sentinelmesh/host-agent/internal/policy"
)

// --- kill ----------------------------------------------------------------

type killRequest struct {
	Targets []actions.KillTarget `json:"targets"`
}

func (s *Server) handleKill(w http.ResponseWriter, r *http.Request) {
	var req killRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	writeJSON(w, http.StatusOK, actions.Kill(req.Targets))
}

// --- account lock ----------------------------------------------------------

type lockAccountRequest struct {
	Username string `json:"username"`
}

func (s *Server) handleLockAccount(w http.ResponseWriter, r *http.Request) {
	var req lockAccountRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := actions.LockAccountOnHost(s.cfg.HostRoot, req.Username); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"locked": true})
}

// --- quarantine --------------------------------------------------------

type quarantineRequest struct {
	Path    string `json:"path"`
	EventID string `json:"event_id"`
}

func (s *Server) handleQuarantine(w http.ResponseWriter, r *http.Request) {
	var req quarantineRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	dest, err := actions.QuarantineOnHost(s.cfg.HostRoot, s.cfg.QuarantineDir, req.Path, req.EventID)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"quarantine_path": dest})
}

// --- network isolate/lift -----------------------------------------------

type networkRequest struct {
	IP string `json:"ip"`
}

func (s *Server) handleIsolate(w http.ResponseWriter, r *http.Request) {
	var req networkRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := actions.Isolate(req.IP); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"isolated": true})
}

func (s *Server) handleLift(w http.ResponseWriter, r *http.Request) {
	var req networkRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := actions.Lift(req.IP); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"lifted": true})
}

// --- snapshot / restore --------------------------------------------------

func (s *Server) handleSnapshot(w http.ResponseWriter, r *http.Request) {
	id, err := s.snapshotter.Create(time.Now())
	if err != nil {
		// A forensic snapshot used by reclaim must be complete. Returning a
		// success response for a partial copy could make control-plane believe
		// restoration is possible when it is not. Keep the snapshot id for
		// operators, but fail the request so reclaim stays isolated.
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"snapshot_id": id,
			"complete":    false,
			"error":       err.Error(),
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"snapshot_id": id, "complete": true})
}

type restoreRequest struct {
	Path   string    `json:"path"`
	Before time.Time `json:"before"`
}

func (s *Server) handleRestore(w http.ResponseWriter, r *http.Request) {
	var req restoreRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Before.IsZero() {
		req.Before = time.Now()
	}
	restored, err := s.snapshotter.Restore(req.Path, req.Before)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"restored": restored})
}

// --- sandbox analysis ----------------------------------------------------

type sandboxAnalyzeRequest struct {
	QuarantinePath string `json:"quarantine_path"`
}

func (s *Server) handleSandboxAnalyze(w http.ResponseWriter, r *http.Request) {
	var req sandboxAnalyzeRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	report, err := actions.SandboxAnalyze(req.QuarantinePath, s.cfg.SandboxStagingDir)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"report": report})
}

// --- persistence scan ------------------------------------------------

type persistenceScanRequest struct {
	Since time.Time `json:"since"`
}

func (s *Server) handlePersistenceScan(w http.ResponseWriter, r *http.Request) {
	var req persistenceScanRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	findings := actions.ScanModifiedSinceRoot(s.cfg.PersistPaths, req.Since, s.cfg.HostRoot)
	writeJSON(w, http.StatusOK, map[string]any{"findings": findings})
}

// --- runtime policy ----------------------------------------------------

func (s *Server) handlePolicyStatus(w http.ResponseWriter, r *http.Request) {
	doc, err := actions.ReadPolicy(s.cfg.PolicyPath, s.cfg.PolicySigningKey)
	if err != nil {
		if os.IsNotExist(err) {
			writeJSON(w, http.StatusOK, map[string]any{"present": false, "version": 0})
			return
		}
		writeError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"present": true, "version": doc.Version})
}

type policyRequest struct {
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

func (s *Server) handlePolicyApply(w http.ResponseWriter, r *http.Request) {
	var req policyRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Payload == "" || req.Signature == "" {
		writeError(w, http.StatusBadRequest, "payload and signature are required")
		return
	}
	_, _, err := actions.ApplyPolicy(s.cfg.PolicyPath, s.cfg.PolicySigningKey, policy.Signed{Payload: req.Payload, Signature: req.Signature})
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"applied": true})
}

func (s *Server) handlePolicyRollback(w http.ResponseWriter, r *http.Request) {
	var req policyRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Payload == "" || req.Signature == "" {
		writeError(w, http.StatusBadRequest, "payload and signature are required")
		return
	}
	if _, _, err := actions.RollbackPolicy(s.cfg.PolicyPath, s.cfg.PolicySigningKey, policy.Signed{Payload: req.Payload, Signature: req.Signature}); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"rolled_back": true})
}
