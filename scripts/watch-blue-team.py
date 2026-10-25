#!/usr/bin/env python3
import time
import os
import sys
import json
import re

LOG_DIR = "/home/sohan-vm/Downloads/SentinelMesh-1.0.0/logs"
DETECTOR_LOG = os.path.join(LOG_DIR, "detector.log")
CP_LOG = os.path.join(LOG_DIR, "control-plane.log")

# ANSI color codes
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
RESET = "\033[0m"

print(f"{BOLD}{CYAN}======================================================={RESET}")
print(f"{BOLD}{CYAN}   SENTINELMESH LIVE BLUE TEAM DEFENSE MONITOR        {RESET}")
print(f"{BOLD}{CYAN}======================================================={RESET}")
print(f"Monitoring logs in: {LOG_DIR}")
print(f"Waiting for telemetry events and blue team responses...\n")

def follow_files(files):
    fps = [open(f, "r") for f in files if os.path.exists(f)]
    for fp in fps:
        fp.seek(0, os.SEEK_END)
    
    while True:
        line_read = False
        for i, fp in enumerate(fps):
            line = fp.readline()
            if line:
                line_read = True
                yield (files[i], line.strip())
        if not line_read:
            time.sleep(0.1)

try:
    for filename, line in follow_files([DETECTOR_LOG, CP_LOG]):
        # Filter for meaningful security events and containment
        if "hot path running" in line or "ebpf source error" in line:
            continue
        
        timestamp = time.strftime("%H:%M:%S")

        if "ESCALATION" in line or "crossed reclaim threshold" in line:
            print(f"{BOLD}{RED}[{timestamp} RECLAIM ESCALATION]{RESET} {line}")
        elif "response action" in line or "kill_process" in line or "quarantine" in line or "isolate" in line:
            print(f"{BOLD}{YELLOW}[{timestamp} CONTAINMENT ACTION]{RESET} {line}")
        elif "incident" in line.lower() and "accepted" in line.lower():
            print(f"{BOLD}{GREEN}[{timestamp} CONTROL-PLANE INCIDENT]{RESET} {line}")
        elif "rule" in line.lower() or "detect" in line.lower() or "matched" in line.lower():
            print(f"{CYAN}[{timestamp} P0 DETECTOR]{RESET} {line}")
        elif "POST /falco/events" in line or "202" in line:
            print(f"{GREEN}[{timestamp} INGESTION]{RESET} {line}")
except KeyboardInterrupt:
    print(f"\n{YELLOW}Stopped monitor.{RESET}")
    sys.exit(0)
