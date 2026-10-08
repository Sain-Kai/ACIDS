// Package config loads host-agent's configuration from environment
// variables -- the agent runs as a single-purpose system daemon/container
// per host, not something with its own YAML file to ship and keep in
// sync; env vars are the natural fit for that deployment shape (and match
// how the rest of SentinelMesh already does container config).
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

type Config struct {
	ListenAddr        string // e.g. ":9090"
	APIKey            string // required -- the agent refuses to start without one
	QuarantineDir     string
	SandboxStagingDir string
	SnapshotDir       string
	SnapshotPaths     []string
	SnapshotKeep      int
	PersistPaths      []string
	PolicyPath        string
	PolicySigningKey  string
	HostRoot          string
}

func Load() (Config, error) {
	cfg := Config{
		ListenAddr:        getenv("LISTEN_ADDR", ":9090"),
		APIKey:            os.Getenv("SENTINELMESH_API_KEY"),
		QuarantineDir:     getenv("QUARANTINE_DIR", "/var/lib/sentinelmesh/quarantine"),
		SandboxStagingDir: getenv("SANDBOX_STAGING_DIR", "/var/lib/sentinelmesh/sandbox-staging"),
		SnapshotDir:       getenv("SNAPSHOT_DIR", "/var/lib/sentinelmesh/snapshots"),
		SnapshotPaths:     splitCSV(getenv("SNAPSHOT_PATHS", "/etc,/home/*/.ssh,/root/.ssh")),
		PolicyPath:        getenv("POLICY_PATH", "/var/lib/sentinelmesh/policy/current.json"),
		HostRoot:          getenv("HOST_ROOT", "/"),
		PolicySigningKey:  os.Getenv("SENTINELMESH_POLICY_SIGNING_KEY"),
		PersistPaths: splitCSV(getenv("PERSISTENCE_CHECK_PATHS",
			"/etc/cron.d,/etc/cron.daily,/etc/cron.hourly,/etc/cron.weekly,/etc/crontab,"+
				"/etc/systemd/system,/root/.ssh,/home/*/.ssh")),
	}

	keep, err := strconv.Atoi(getenv("SNAPSHOT_KEEP", "24"))
	if err != nil {
		return cfg, fmt.Errorf("config: SNAPSHOT_KEEP: %w", err)
	}
	cfg.SnapshotKeep = keep

	if cfg.APIKey == "" {
		// Fail closed, not open -- same posture as control-plane's
		// ApiKeyAuthFilter and llm-orchestration's app.py: refuse to
		// start rather than silently serve an unauthenticated API that
		// can kill processes, firewall the host, and lock accounts.
		return cfg, fmt.Errorf("config: SENTINELMESH_API_KEY must be set -- refusing to start without auth configured")
	}
	if cfg.PolicySigningKey == "" {
		return cfg, fmt.Errorf("config: SENTINELMESH_POLICY_SIGNING_KEY must be set -- refusing to start without policy verification key")
	}
	if !filepath.IsAbs(cfg.HostRoot) {
		return cfg, fmt.Errorf("config: HOST_ROOT must be absolute")
	}
	if cfg.SnapshotKeep < 0 {
		return cfg, fmt.Errorf("config: SNAPSHOT_KEEP cannot be negative")
	}
	return cfg, nil
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func splitCSV(s string) []string {
	var out []string
	cur := ""
	for _, r := range s {
		if r == ',' {
			if cur != "" {
				out = append(out, cur)
			}
			cur = ""
			continue
		}
		cur += string(r)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}
