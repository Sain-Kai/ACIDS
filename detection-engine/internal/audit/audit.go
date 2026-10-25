// Package audit writes a local, hash-chained action journal for the P0
// responder. It is deliberately independent of the control-plane so a
// network outage cannot erase evidence of a local containment decision.
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"sentinelmesh/detection-engine/internal/types"
)

type Record struct {
	Timestamp    string   `json:"timestamp"`
	EventID      string   `json:"event_id"`
	Action       string   `json:"action"`
	Score        float64  `json:"score"`
	MatchedRules []string `json:"matched_rules,omitempty"`
	Success      bool     `json:"success"`
	Error        string   `json:"error,omitempty"`
	PreviousHash string   `json:"previous_hash,omitempty"`
	Hash         string   `json:"hash"`
}

type Logger struct {
	path string
	mu   sync.Mutex
	prev string
}

func New(path string) (*Logger, error) {
	if path == "" {
		return nil, errors.New("audit path is required")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	l := &Logger{path: path}
	if b, err := os.ReadFile(path); err == nil && len(b) > 0 {
		lines := splitLines(b)
		if len(lines) > 0 {
			var last Record
			if err := json.Unmarshal(lines[len(lines)-1], &last); err != nil {
				return nil, fmt.Errorf("invalid audit journal tail: %w", err)
			}
			if last.Hash == "" {
				return nil, errors.New("invalid audit journal tail: missing hash")
			}
			l.prev = last.Hash
		}
	} else if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	return l, nil
}

func splitLines(b []byte) [][]byte {
	var out [][]byte
	start := 0
	for i, c := range b {
		if c == '\n' {
			if i > start {
				out = append(out, append([]byte(nil), b[start:i]...))
			}
			start = i + 1
		}
	}
	if start < len(b) {
		out = append(out, append([]byte(nil), b[start:]...))
	}
	return out
}

func (l *Logger) Record(ev types.Event, verdict types.Verdict, success bool, actionErr error) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	r := Record{
		Timestamp:    time.Now().UTC().Format(time.RFC3339Nano),
		EventID:      ev.EventID,
		Action:       string(verdict.Action),
		Score:        verdict.Score,
		MatchedRules: append([]string(nil), verdict.MatchedRules...),
		Success:      success,
		PreviousHash: l.prev,
	}
	if actionErr != nil {
		r.Error = actionErr.Error()
	}

	canonical, err := json.Marshal(struct {
		Timestamp    string   `json:"timestamp"`
		EventID      string   `json:"event_id"`
		Action       string   `json:"action"`
		Score        float64  `json:"score"`
		MatchedRules []string `json:"matched_rules,omitempty"`
		Success      bool     `json:"success"`
		Error        string   `json:"error,omitempty"`
		PreviousHash string   `json:"previous_hash,omitempty"`
	}{r.Timestamp, r.EventID, r.Action, r.Score, r.MatchedRules, r.Success, r.Error, r.PreviousHash})
	if err != nil {
		return err
	}
	sum := sha256.Sum256(append([]byte(r.PreviousHash+"\n"), canonical...))
	r.Hash = hex.EncodeToString(sum[:])
	line, err := json.Marshal(r)
	if err != nil {
		return err
	}
	line = append(line, '\n')

	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(line); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	l.prev = r.Hash
	return nil
}
