package actions

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"sentinelmesh/host-agent/internal/policy"
)

func signedDoc(t *testing.T, version int64, secret string) policy.Signed {
	t.Helper()
	d := policy.Document{Version: version, GeneratedAt: "2026-10-08T00:00:00Z"}
	s, err := policy.Sign(d, secret)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestApplyPolicyRejectsDowngrade(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "current.json")
	secret := "secret"
	if _, _, err := ApplyPolicy(path, secret, signedDoc(t, 2, secret)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ApplyPolicy(path, secret, signedDoc(t, 1, secret)); err == nil {
		t.Fatal("expected downgrade rejection")
	}
}

func TestRollbackPolicyAllowsLowerSignedVersion(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "current.json")
	secret := "secret"
	if _, _, err := ApplyPolicy(path, secret, signedDoc(t, 2, secret)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := RollbackPolicy(path, secret, signedDoc(t, 1, secret)); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var s policy.Signed
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	d, err := policy.Verify(s, secret)
	if err != nil {
		t.Fatal(err)
	}
	if d.Version != 1 {
		t.Fatalf("expected version 1 after rollback, got %d", d.Version)
	}
}

func TestApplyPolicyIsIdempotentForExactSameSignedPolicy(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "current.json")
	secret := "secret"
	s := signedDoc(t, 2, secret)
	if _, _, err := ApplyPolicy(path, secret, s); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ApplyPolicy(path, secret, s); err != nil {
		t.Fatalf("expected idempotent replay, got %v", err)
	}
}

func TestApplyPolicyRejectsSameVersionDifferentContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "current.json")
	secret := "secret"
	first := signedDoc(t, 2, secret)
	secondDoc := policy.Document{Version: 2, GeneratedAt: "2026-10-08T00:00:01Z"}
	second, err := policy.Sign(secondDoc, secret)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ApplyPolicy(path, secret, first); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ApplyPolicy(path, secret, second); err == nil {
		t.Fatal("expected same-version collision rejection")
	}
}
