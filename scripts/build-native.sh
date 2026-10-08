#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

need() { command -v "$1" >/dev/null 2>&1 || { echo "ERROR: required command '$1' not found" >&2; exit 1; }; }
need go
need clang
need bpftool

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "ERROR: native eBPF build must run on Linux." >&2
  exit 1
fi
if [[ ! -r /sys/kernel/btf/vmlinux ]]; then
  echo "ERROR: /sys/kernel/btf/vmlinux is unavailable; target kernel must expose BTF." >&2
  exit 1
fi

cd "$ROOT/detection-engine"
go mod tidy
cd internal/ingest/probes
make vmlinux-header
make generate

# go generate must see the sentinel_native build-tagged ebpf.go; verify the
# generated bpf2go bindings exist before attempting to compile the native path.
if [[ ! -f "$ROOT/detection-engine/internal/ingest/bpf_bpfel.go" || ! -f "$ROOT/detection-engine/internal/ingest/bpf_bpfeb.go" ]]; then
  echo "ERROR: bpf2go did not generate native bindings. Check go generate -tags sentinel_native output." >&2
  exit 1
fi

cd "$ROOT/detection-engine"
go test -tags sentinel_native ./...
go vet -tags sentinel_native ./...
go build -tags sentinel_native ./...

echo "Native eBPF/Falco detection-engine build passed."
