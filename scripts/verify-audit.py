#!/usr/bin/env python3
import hashlib
import hmac
import re
import sys
from pathlib import Path

HASH_RE = re.compile(r"(?:^| )hash=([0-9a-fA-F]{64})(?:\s|$)")
PREV_RE = re.compile(r"(?:^| )prev_hash=([0-9a-fA-F]{64}|GENESIS)(?:\s|$)")
LINE_RE = re.compile(r"^(\S+) incident=(\S*) action=(\S*) detail=(.*?) prev_hash=([0-9a-fA-F]{64}|GENESIS) hash=([0-9a-fA-F]{64})$")

def main(path: str) -> int:
    p = Path(path)
    if not p.exists():
        print(f"ERROR: audit file not found: {p}", file=sys.stderr); return 2
    prev = "GENESIS"
    count = 0
    for lineno, line in enumerate(p.read_text(encoding="utf-8", errors="strict").splitlines(), 1):
        if not line.strip(): continue
        m = LINE_RE.match(line)
        if not m:
            print(f"ERROR: malformed audit record at line {lineno}", file=sys.stderr); return 1
        timestamp, incident, action, detail, record_prev, record_hash = m.groups()
        if record_prev.lower() != prev.lower():
            print(f"ERROR: hash-chain break at line {lineno}", file=sys.stderr); return 1
        canonical = f"{timestamp}\t{incident}\t{action}\t{detail}\t{record_prev}"
        expected = hashlib.sha256(canonical.encode()).hexdigest()
        if not hmac.compare_digest(expected, record_hash.lower()):
            print(f"ERROR: record hash mismatch at line {lineno}", file=sys.stderr); return 1
        prev = record_hash.lower(); count += 1
    print(f"AUDIT VERIFY PASS: {count} chained record(s)")
    return 0

if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1]))
