#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ -f "$ROOT/deploy/.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  . "$ROOT/deploy/.env"
  set +a
fi
fail=0
check(){ if command -v "$1" >/dev/null 2>&1; then printf 'OK   %-12s\n' "$1"; else printf 'MISS %-12s\n' "$1"; fail=1; fi; }
check docker
check openssl
check go
if command -v go >/dev/null 2>&1; then
  GO_MAJOR="$(go env GOVERSION | sed -E 's/^go([0-9]+).*/\1/')"
  GO_MINOR="$(go env GOVERSION | sed -E 's/^go[0-9]+\.([0-9]+).*/\1/')"
  if (( GO_MAJOR > 1 || (GO_MAJOR == 1 && GO_MINOR >= 25) )); then echo 'OK   Go 1.25+'; else echo 'MISS Go 1.25+ (cilium/ebpf v0.22.0 prerequisite)'; fail=1; fi
fi
check clang
check bpftool
check iptables
check ip
[[ -r /sys/kernel/btf/vmlinux ]] && echo 'OK   kernel BTF' || { echo 'MISS kernel BTF'; fail=1; }
SANDBOX_RUNTIME=${SANDBOX_RUNTIME:-runsc}
if [[ "$SANDBOX_RUNTIME" == "runsc" ]]; then
  command -v runsc >/dev/null 2>&1 && echo 'OK   gVisor runsc' || { echo 'MISS gVisor runsc (set SANDBOX_RUNTIME=runc only for lab/development deployments)'; fail=1; }
else
  echo "WARN sandbox runtime=$SANDBOX_RUNTIME; production should use runsc or a Firecracker adapter"
fi
if docker image inspect "${FALCO_IMAGE:-docker.io/falcosecurity/falco:0.45.0}" >/dev/null 2>&1; then
  echo 'OK   Falco image cached'
else
  echo 'INFO Falco image will be pulled during compose startup'
fi
if command -v ollama >/dev/null 2>&1; then echo 'OK   Ollama'; else echo 'WARN Ollama CLI not found; configure OLLAMA_BASE_URL to a reachable Ollama service'; fi
if [[ -f "$ROOT/deploy/.env" ]]; then
  echo 'OK   deploy/.env'
  grep -q '^SENTINELMESH_POLICY_SIGNING_KEY=[^R].*' "$ROOT/deploy/.env" || { echo 'MISS non-placeholder policy key'; fail=1; }
else
  echo 'WARN deploy/.env not created; run deploy/bootstrap.sh'
fi
exit "$fail"
