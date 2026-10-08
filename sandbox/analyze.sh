#!/bin/bash
# Baseline static + bounded-dynamic analysis run inside the isolated
# sandbox container. Deliberately conservative: static inspection first,
# and only a few seconds of execution -- with no network, a read-only
# root filesystem, all capabilities dropped, and no-new-privileges already
# enforced by the `docker run` flags this is invoked with (see
# SandboxAnalysisService.java / the Dockerfile header comment).
set -uo pipefail

PAYLOAD="${1:-/sandbox/payload}"

echo "=== SentinelMesh sandbox analysis: $PAYLOAD ==="

echo "--- file type ---"
file "$PAYLOAD" 2>&1 || true

echo "--- sha256 ---"
sha256sum "$PAYLOAD" 2>&1 || true

echo "--- strings (first 200 lines) ---"
strings "$PAYLOAD" 2>/dev/null | head -200 || true

if [ -x "$PAYLOAD" ]; then
  echo "--- bounded execution (5s timeout) ---"
  timeout 5 "$PAYLOAD" >/tmp/exec_stdout.log 2>/tmp/exec_stderr.log
  status=$?
  echo "exit_status=$status"
  echo "stdout:"
  cat /tmp/exec_stdout.log 2>/dev/null || true
  echo "stderr:"
  cat /tmp/exec_stderr.log 2>/dev/null || true
else
  echo "--- not marked executable, skipping dynamic analysis ---"
fi

echo "=== end analysis ==="
