package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"sentinelmesh/host-agent/internal/config"
)

func testServer(t *testing.T) (*Server, string) {
	t.Helper()
	cfg := config.Config{
		APIKey:            "test-key",
		QuarantineDir:     t.TempDir(),
		SandboxStagingDir: t.TempDir(),
		SnapshotDir:       t.TempDir(),
		SnapshotPaths:     []string{t.TempDir()},
		PersistPaths:      []string{t.TempDir()},
	}
	return New(cfg), cfg.APIKey
}

func doRequest(t *testing.T, h http.Handler, method, path, apiKey string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatal(err)
		}
	}
	req := httptest.NewRequest(method, path, &buf)
	if apiKey != "" {
		req.Header.Set(apiKeyHeader, apiKey)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestHealthzRequiresNoAuth(t *testing.T) {
	s, _ := testServer(t)
	rec := doRequest(t, s.Routes(), "GET", "/healthz", "", nil)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestIdentityEndpointRequiresAuthAndReturnsHostIP(t *testing.T) {
	s, key := testServer(t)
	unauth := doRequest(t, s.Routes(), "GET", "/v1/identity", "", nil)
	if unauth.Code != http.StatusUnauthorized {
		t.Fatalf("expected unauthenticated identity request to be 401, got %d", unauth.Code)
	}
	auth := doRequest(t, s.Routes(), "GET", "/v1/identity", key, nil)
	if auth.Code != http.StatusOK && auth.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected identity 200 or explicit unavailable, got %d: %s", auth.Code, auth.Body.String())
	}
}

func TestProtectedEndpointsRejectMissingOrWrongKey(t *testing.T) {
	s, _ := testServer(t)
	for _, key := range []string{"", "wrong-key"} {
		rec := doRequest(t, s.Routes(), "POST", "/v1/network/isolate", key, map[string]string{"ip": "10.0.0.5"})
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("key=%q: expected 401, got %d", key, rec.Code)
		}
	}
}

func TestProtectedEndpointAcceptsCorrectKey(t *testing.T) {
	s, key := testServer(t)
	rec := doRequest(t, s.Routes(), "POST", "/v1/network/isolate", key, map[string]string{"ip": "not-an-ip"})
	// Wrong IP, but a *validation* 400, not an auth 401 -- proves the
	// request got past auth and into the handler.
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 (validation, not auth), got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestKillEndpointReturnsSkipForBadTarget(t *testing.T) {
	s, key := testServer(t)
	rec := doRequest(t, s.Routes(), "POST", "/v1/kill", key, map[string]any{
		"targets": []map[string]any{{"pid": 1, "exe": "/tmp/x"}},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp map[string]int
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["skipped"] != 1 || resp["killed"] != 0 {
		t.Errorf("expected pid=1 to be skipped, got %v", resp)
	}
}

func TestLockAccountEndpointRejectsProtectedUser(t *testing.T) {
	s, key := testServer(t)
	rec := doRequest(t, s.Routes(), "POST", "/v1/account/lock", key, map[string]string{"username": "root"})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for protected account, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestQuarantineEndpointRejectsProtectedPath(t *testing.T) {
	s, key := testServer(t)
	rec := doRequest(t, s.Routes(), "POST", "/v1/quarantine", key, map[string]string{"path": "/etc/shadow", "event_id": "evt-1"})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for protected path, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestPersistenceScanEndpointReturnsEmptyArrayNotNull(t *testing.T) {
	s, key := testServer(t)
	rec := doRequest(t, s.Routes(), "POST", "/v1/persistence-scan", key, map[string]string{})
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if bytes.Contains(rec.Body.Bytes(), []byte(`"findings":null`)) {
		t.Error("expected findings to serialize as [], not null")
	}
}

func TestSandboxAnalyzeEndpointRejectsMissingArtifact(t *testing.T) {
	s, key := testServer(t)
	rec := doRequest(t, s.Routes(), "POST", "/v1/sandbox-analyze", key, map[string]string{
		"quarantine_path": "/does/not/exist",
	})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for a missing artifact, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestMalformedJSONBodyReturns400(t *testing.T) {
	s, key := testServer(t)
	req := httptest.NewRequest("POST", "/v1/network/isolate", bytes.NewBufferString("{not json"))
	req.Header.Set(apiKeyHeader, key)
	rec := httptest.NewRecorder()
	s.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for malformed JSON, got %d", rec.Code)
	}
}
