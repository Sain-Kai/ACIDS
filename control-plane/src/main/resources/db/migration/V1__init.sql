CREATE TABLE IF NOT EXISTS security_events (
  event_id VARCHAR(128) PRIMARY KEY,
  correlation_id VARCHAR(128), timestamp TIMESTAMPTZ,
  source VARCHAR(64), hostname VARCHAR(255), host_ip VARCHAR(64),
  event_type VARCHAR(128), severity_raw VARCHAR(64), process_pid INTEGER, process_ppid INTEGER,
  process_cmdline TEXT, process_exe VARCHAR(1024), process_user VARCHAR(255),
  network_src_ip VARCHAR(64), network_dst_ip VARCHAR(64), network_src_port INTEGER, network_dst_port INTEGER, network_protocol VARCHAR(32),
  file_path VARCHAR(4096), file_operation VARCHAR(64), tags_csv VARCHAR(4000), container_id VARCHAR(255), container_image VARCHAR(1024), raw_payload_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_security_events_host_time ON security_events(hostname, timestamp);

CREATE TABLE IF NOT EXISTS incidents (
  incident_id VARCHAR(128) PRIMARY KEY,
  event_id VARCHAR(128) UNIQUE,
  verdict_score DOUBLE PRECISION NOT NULL,
  matched_rules VARCHAR(2000), action_taken VARCHAR(128), action_error VARCHAR(2000),
  quarantine_path VARCHAR(4096), status VARCHAR(64), reclaim_state VARCHAR(64), idempotency_key VARCHAR(200) UNIQUE,
  created_at TIMESTAMPTZ, updated_at TIMESTAMPTZ,
  CONSTRAINT fk_incident_event FOREIGN KEY(event_id) REFERENCES security_events(event_id)
);
CREATE INDEX IF NOT EXISTS idx_incidents_status_created ON incidents(status, created_at);
CREATE INDEX IF NOT EXISTS idx_incidents_rules_time ON incidents(matched_rules, created_at);

CREATE TABLE IF NOT EXISTS guarded_deployments (
  deployment_id VARCHAR(128) PRIMARY KEY,
  incident_id VARCHAR(128), matched_rules VARCHAR(2000), proposed_change TEXT,
  judge_rationale TEXT, stage VARCHAR(32), signed_policy TEXT, previous_policy TEXT,
  target_hosts VARCHAR(4000), canary_host VARCHAR(255), canary_started_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ, updated_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS active_policy (
  id VARCHAR(64) PRIMARY KEY,
  version BIGINT NOT NULL, updated_at TIMESTAMPTZ, payload TEXT, signature VARCHAR(128)
);
