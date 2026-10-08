package policy

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"os"
	"strings"
)

type Signed struct {
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}
type Document struct {
	Version              int64    `json:"version"`
	GeneratedAt          string   `json:"generated_at"`
	BlockedIPs           []string `json:"blocked_ips,omitempty"`
	ExtraCommandPatterns []string `json:"extra_command_patterns,omitempty"`
	ContainThreshold     *float64 `json:"contain_threshold,omitempty"`
	BlockThreshold       *float64 `json:"block_threshold,omitempty"`
	ReclaimThreshold     *float64 `json:"reclaim_threshold,omitempty"`
}

func Sign(d Document, secret string) (Signed, error) {
	if strings.TrimSpace(secret) == "" {
		return Signed{}, errors.New("policy signing key is empty")
	}
	b, err := json.Marshal(d)
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
	exp := hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(strings.ToLower(strings.TrimSpace(s.Signature))), []byte(exp)) {
		return Document{}, errors.New("invalid policy signature")
	}
	var d Document
	if err := json.Unmarshal([]byte(s.Payload), &d); err != nil {
		return d, err
	}
	if d.Version <= 0 {
		return d, errors.New("invalid policy version")
	}
	if d.ContainThreshold != nil && (math.IsNaN(*d.ContainThreshold) || math.IsInf(*d.ContainThreshold, 0) || *d.ContainThreshold <= 0 || *d.ContainThreshold >= 1) {
		return d, errors.New("invalid contain threshold")
	}
	if d.BlockThreshold != nil && (math.IsNaN(*d.BlockThreshold) || math.IsInf(*d.BlockThreshold, 0) || *d.BlockThreshold <= 0 || *d.BlockThreshold >= 1) {
		return d, errors.New("invalid block threshold")
	}
	if d.ReclaimThreshold != nil && (math.IsNaN(*d.ReclaimThreshold) || math.IsInf(*d.ReclaimThreshold, 0) || *d.ReclaimThreshold <= 0 || *d.ReclaimThreshold >= 1) {
		return d, errors.New("invalid reclaim threshold")
	}
	if d.ContainThreshold != nil && d.BlockThreshold != nil && *d.ContainThreshold >= *d.BlockThreshold {
		return d, errors.New("contain threshold must be below block threshold")
	}
	if d.BlockThreshold != nil && d.ReclaimThreshold != nil && *d.BlockThreshold >= *d.ReclaimThreshold {
		return d, errors.New("block threshold must be below reclaim threshold")
	}
	return d, nil
}
func WriteAtomic(path string, s Signed, secret string) error {
	if _, err := Verify(s, secret); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir(path), 0700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if d, err := os.Open(dir(path)); err == nil {
		defer d.Close()
		_ = d.Sync()
	}
	return nil
}
func Read(path, secret string) (Document, Signed, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Document{}, Signed{}, err
	}
	var s Signed
	if err = json.Unmarshal(b, &s); err != nil {
		return Document{}, s, err
	}
	d, err := Verify(s, secret)
	return d, s, err
}
func dir(path string) string {
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
