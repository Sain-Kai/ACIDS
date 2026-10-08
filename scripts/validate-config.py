#!/usr/bin/env python3
import json
import xml.etree.ElementTree as ET
from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parents[1]

for p in ROOT.glob("**/*.json"):
    json.loads(p.read_text())
for p in list(ROOT.glob("deploy/*.yml")) + [ROOT / "detection-engine/falco-rules/sentinelmesh_rules.yaml"]:
    yaml.safe_load(p.read_text())
ET.parse(ROOT / "control-plane/pom.xml")
for p in ROOT.glob("llm-orchestration/*.py"):
    compile(p.read_text(), str(p), "exec")
for p in (ROOT / "llm-orchestration/agents").glob("*.py"):
    compile(p.read_text(), str(p), "exec")
# Deployment invariants that are cheap to verify without starting containers.
prod = yaml.safe_load((ROOT / "deploy/docker-compose.prod.yml").read_text())
assert "falco" in prod["services"], "production compose must include Falco"
assert prod["services"]["falco"]["network_mode"] == "host", "Falco must share host network for host telemetry"
assert prod["services"]["detection-engine"]["network_mode"] == "host", "detector must share host network for P0 response"
assert prod["services"]["host-agent"]["network_mode"] == "host", "host-agent must share host network"
assert prod["services"]["prometheus"]["network_mode"] == "host", "Prometheus must scrape host-local metrics"
assert "SENTINELMESH_HOST_IP" in (ROOT / "deploy/.env.example").read_text()
protected = yaml.safe_load((ROOT / "deploy/docker-compose.protected-host.yml").read_text())
assert protected["services"]["postgres"]["network_mode"] == "host"
assert protected["services"]["postgres"]["environment"]["PGPORT"] == "${SENTINELMESH_POSTGRES_PORT:-15432}"
assert protected["services"]["control-plane"]["environment"]["SPRING_DATASOURCE_URL"].endswith(":${SENTINELMESH_POSTGRES_PORT:-15432}/sentinelmesh")
assert protected["services"]["host-agent"]["environment"]["LISTEN_ADDR"] == "127.0.0.1:9090"
assert protected["services"]["prometheus"]["network_mode"] == "host"
assert "hostname:" in (ROOT / "deploy/docker-compose.protected-host.yml").read_text()
assert "docker.io" in (ROOT / "host-agent/Dockerfile").read_text(), "host-agent image must contain Docker CLI for sandbox execution"
assert "Flask==" in (ROOT / "llm-orchestration/requirements.txt").read_text()
print("Configuration/syntax/deployment-invariant validation passed.")
