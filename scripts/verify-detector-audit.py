#!/usr/bin/env python3
import hashlib
import hmac
import json
import sys
from pathlib import Path


def canonical(record):
    obj = {
        "timestamp": record["timestamp"],
        "event_id": record["event_id"],
        "action": record["action"],
        "score": record["score"],
        "success": record["success"],
    }
    if record.get("matched_rules"):
        obj["matched_rules"] = record["matched_rules"]
    if record.get("error"):
        obj["error"] = record["error"]
    if record.get("previous_hash"):
        obj["previous_hash"] = record["previous_hash"]
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode()

def main(path):
    p = Path(path)
    if not p.exists():
        print(f"ERROR: audit file not found: {p}", file=sys.stderr); return 2
    prev = ""; count = 0
    for n, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip(): continue
        try: r=json.loads(line)
        except json.JSONDecodeError as exc:
            print(f"ERROR: malformed JSON at line {n}: {exc}", file=sys.stderr); return 1
        if r.get("previous_hash", "") != prev:
            print(f"ERROR: detector audit hash-chain break at line {n}", file=sys.stderr); return 1
        expected=hashlib.sha256((prev+"\n").encode()+canonical(r)).hexdigest()
        if not hmac.compare_digest(expected, str(r.get("hash",""))):
            print(f"ERROR: detector audit hash mismatch at line {n}", file=sys.stderr); return 1
        prev=r["hash"]; count += 1
    print(f"DETECTOR AUDIT VERIFY PASS: {count} chained record(s)")
    return 0

if __name__ == "__main__":
    if len(sys.argv) != 2: print("usage: verify-detector-audit.py AUDIT_LOG", file=sys.stderr); raise SystemExit(2)
    raise SystemExit(main(sys.argv[1]))
