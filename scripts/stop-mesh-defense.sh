#!/usr/bin/env bash
echo "Stopping SentinelMesh services..."
pkill -f "sentinelmesh-detector" 2>/dev/null || true
pkill -f "sentinelmesh-host-agent" 2>/dev/null || true
pkill -f "llm-orchestration/app.py" 2>/dev/null || true
pkill -f "control-plane-0.1.0-SNAPSHOT.jar" 2>/dev/null || true
echo "All SentinelMesh services stopped."
