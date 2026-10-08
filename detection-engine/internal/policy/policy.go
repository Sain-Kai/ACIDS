package policy

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

type Document struct {
	Version              int64    `json:"version"`
	GeneratedAt          string   `json:"generated_at"`
	BlockedIPs           []string `json:"blocked_ips,omitempty"`
	ExtraCommandPatterns []string `json:"extra_command_patterns,omitempty"`
	ContainThreshold     *float64 `json:"contain_threshold,omitempty"`
	BlockThreshold       *float64 `json:"block_threshold,omitempty"`
	ReclaimThreshold     *float64 `json:"reclaim_threshold,omitempty"`
}

type Signed struct {
	Payload   string `json:"payload"`   // exact JSON bytes, base64 not required; URL transport is JSON
	Signature string `json:"signature"` // lowercase hex HMAC-SHA256(payload)
}

func Sign(doc Document, secret string) (Signed, error) {
	if strings.TrimSpace(secret) == "" {
		return Signed{}, errors.New("policy signing key is empty")
	}
	if doc.GeneratedAt == "" {
		doc.GeneratedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	b, err := json.Marshal(doc)
	if err != nil {
		return Signed{}, err
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(b)
	return Signed{Payload: string(b), Signature: hex.EncodeToString(mac.Sum(nil))}, nil
}

func Verify(s Signed, secret string) (Document, error) {
	if strings.TrimSpace(secret) == "" {
		return Document{}, errors.New("policy signing key is empty")
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(s.Payload))
	expected := hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(strings.ToLower(strings.TrimSpace(s.Signature))), []byte(expected)) {
		return Document{}, errors.New("invalid policy signature")
	}
	var doc Document
	if err := json.Unmarshal([]byte(s.Payload), &doc); err != nil {
		return Document{}, err
	}
	if doc.Version <= 0 {
		return Document{}, errors.New("invalid policy version")
	}
	return doc, nil
}

func WriteAtomically(path string, s Signed, secret string) error {
	if _, err := Verify(s, secret); err != nil {
		return err
	}
	out, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepathDir(path), 0700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, out, 0600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func Read(path, secret string) (Document, Signed, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Document{}, Signed{}, err
	}
	var s Signed
	if err := json.Unmarshal(b, &s); err != nil {
		return Document{}, Signed{}, err
	}
	doc, err := Verify(s, secret)
	return doc, s, err
}

func filepathDir(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			if i == 0 {
				return "/"
			}
			return path[:i]
		}
	}
	return "."
}

type Store struct{ v atomic.Value }

func NewStore(initial Document) *Store { s := &Store{}; s.v.Store(initial); return s }
func (s *Store) Load() Document {
	if v := s.v.Load(); v != nil {
		return v.(Document)
	}
	return Document{Version: 1}
}
func (s *Store) Swap(d Document) { s.v.Store(d) }
