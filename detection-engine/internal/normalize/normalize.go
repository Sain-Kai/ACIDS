// Package normalize converts source-specific RawEvents into the common Event representation.
package normalize

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"sentinelmesh/detection-engine/internal/id"
	"sentinelmesh/detection-engine/internal/types"
)

var (
	localHostname = detectHostname()
	localIP       = detectLocalIP()
)

func detectHostname() string {
	if configured := strings.TrimSpace(os.Getenv("SENTINELMESH_HOSTNAME")); configured != "" {
		return configured
	}
	h, err := os.Hostname()
	if err != nil || h == "" {
		return "unknown-host"
	}
	return h
}
func detectLocalIP() string {
	if configured := strings.TrimSpace(os.Getenv("SENTINELMESH_HOST_IP")); configured != "" {
		ip := net.ParseIP(configured)
		if ip != nil && ip.To4() != nil && !ip.IsLoopback() && !ip.IsUnspecified() {
			return ip.To4().String()
		}
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() || ip.IsUnspecified() {
				continue
			}
			if v4 := ip.To4(); v4 != nil {
				return v4.String()
			}
		}
	}
	return ""
}

func Normalize(raw types.RawEvent) (types.Event, error) {
	switch raw.Source {
	case "falco":
		return normalizeFalco(raw)
	case "ebpf":
		return normalizeEBPF(raw)
	default:
		return types.Event{}, fmt.Errorf("normalize: unknown source %q", raw.Source)
	}
}

func normalizeFalco(raw types.RawEvent) (types.Event, error) {
	ev := baseEvent(raw)
	ev.EventType = falcoEventType(raw.Payload)
	ev.SeverityRaw = normalizeSeverity(stringField(raw.Payload, "priority"))
	ev.Syscall = firstString(raw.Payload, "syscall", "evt.type")
	ev.Tags = stringSlice(raw.Payload["tags"])

	pid := intField(raw.Payload, "proc.pid", "pid", "thread.tid")
	ppid := intField(raw.Payload, "proc.ppid", "ppid")
	exe := firstString(raw.Payload, "proc.exe", "proc.exepath", "proc.name")
	cmdline := firstString(raw.Payload, "proc.cmdline", "proc.args")
	user := firstString(raw.Payload, "user.name", "proc.user", "user.username")
	if pid != 0 || exe != "" || cmdline != "" || user != "" {
		ev.Process = &types.ProcessInfo{PID: pid, PPID: ppid, Exe: exe, Cmdline: cmdline, User: user}
	}

	if hasAny(raw.Payload, "fd.sip", "fd.cip", "net.sip", "net.cip", "fd.dip", "fd.rip", "net.dip", "net.rip") {
		ev.Network = &types.NetworkInfo{
			SrcIP:    firstString(raw.Payload, "fd.sip", "net.sip", "fd.cip", "net.cip"),
			DstIP:    firstString(raw.Payload, "fd.dip", "net.dip", "fd.rip", "net.rip"),
			SrcPort:  intField(raw.Payload, "fd.sport", "net.sport", "fd.cport"),
			DstPort:  intField(raw.Payload, "fd.dport", "net.dport", "fd.rport"),
			Protocol: strings.ToLower(firstString(raw.Payload, "fd.l4proto", "net.proto", "proto")),
		}
	}

	path := firstString(raw.Payload, "fd.name", "fd.filename", "file.path", "fs.path")
	if path != "" {
		op := normalizeFileOperation(raw.Payload)
		ev.File = &types.FileInfo{Path: path, Operation: op}
	}
	ev.Host.ContainerID = firstString(raw.Payload, "container.id")
	ev.Host.ContainerImage = firstString(raw.Payload, "container.image.repository", "container.image", "container.image.tag")
	if ev.Host.ContainerID == "" && ev.Process == nil && ev.Network == nil && ev.File == nil {
		return ev, nil
	}
	return ev, nil
}

func normalizeEBPF(raw types.RawEvent) (types.Event, error) {
	ev := baseEvent(raw)
	ev.EventType = stringField(raw.Payload, "event_type")
	switch ev.EventType {
	case "process_exec":
		ev.Process = &types.ProcessInfo{
			PID:     intField(raw.Payload, "pid"),
			PPID:    intField(raw.Payload, "ppid"),
			Exe:     stringField(raw.Payload, "proc.exe"),
			Cmdline: firstString(raw.Payload, "proc.cmdline", "proc.exe"),
			User:    firstString(raw.Payload, "proc.user", "user.name"),
		}
		ev.Syscall = "execve"
	case "network_connect":
		ev.Process = &types.ProcessInfo{PID: intField(raw.Payload, "pid"), User: firstString(raw.Payload, "proc.user", "user.name")}
		ev.Network = &types.NetworkInfo{SrcIP: stringField(raw.Payload, "net.saddr"), DstIP: stringField(raw.Payload, "net.daddr"), SrcPort: intField(raw.Payload, "net.sport"), DstPort: intField(raw.Payload, "net.dport"), Protocol: "tcp"}
		ev.Syscall = "connect"
	case "file_write":
		ev.Process = &types.ProcessInfo{PID: intField(raw.Payload, "pid"), User: firstString(raw.Payload, "proc.user", "user.name")}
		ev.File = &types.FileInfo{Path: stringField(raw.Payload, "file.path"), Operation: "write"}
		ev.Syscall = "openat"
	default:
		return types.Event{}, fmt.Errorf("normalize: unsupported eBPF event_type %q", ev.EventType)
	}
	return ev, nil
}

func baseEvent(raw types.RawEvent) types.Event {
	ts := raw.Timestamp
	if ts.IsZero() {
		ts = time.Now().UTC()
	}
	correlation := firstString(raw.Payload, "correlation_id", "session_id")
	if correlation == "" {
		correlation = id.UUID()
	}
	return types.Event{EventID: id.UUID(), CorrelationID: correlation, Timestamp: ts, Source: raw.Source, RawPayload: raw.Payload, SeverityRaw: "info", Host: types.HostInfo{Hostname: localHostname, IP: localIP}}
}

func falcoEventType(m map[string]interface{}) string {
	if evt := firstString(m, "evt.type", "event_type"); evt != "" {
		e := strings.ToLower(evt)
		if strings.Contains(e, "exec") {
			return "process_exec"
		}
		if strings.Contains(e, "connect") || strings.Contains(e, "accept") {
			return "network_connect"
		}
		if strings.Contains(e, "open") || strings.Contains(e, "write") || strings.Contains(e, "creat") || strings.Contains(e, "unlink") {
			return "file_write"
		}
		return e
	}
	rule := strings.ToLower(stringField(m, "rule"))
	if strings.Contains(rule, "network") || strings.Contains(rule, "connect") || strings.Contains(rule, "egress") {
		return "network_connect"
	}
	if strings.Contains(rule, "file") || strings.Contains(rule, "write") || strings.Contains(rule, "modify") {
		return "file_write"
	}
	if hasAny(m, "proc.exe", "proc.cmdline") {
		return "process_exec"
	}
	return "falco_alert"
}

func normalizeSeverity(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	switch v {
	case "emergency", "alert", "critical", "error", "warning", "notice", "info", "debug":
		return v
	default:
		return "info"
	}
}
func normalizeFileOperation(m map[string]interface{}) string {
	op := strings.ToLower(firstString(m, "file.operation", "evt.type", "operation"))
	if strings.Contains(op, "unlink") || strings.Contains(op, "delete") {
		return "delete"
	}
	if strings.Contains(op, "rename") {
		return "rename"
	}
	if strings.Contains(op, "chmod") {
		return "chmod"
	}
	if strings.Contains(op, "creat") {
		return "create"
	}
	return "write"
}
func hasAny(m map[string]interface{}, keys ...string) bool {
	for _, k := range keys {
		if v, ok := m[k]; ok && fmt.Sprint(v) != "" {
			return true
		}
	}
	return false
}
func firstString(m map[string]interface{}, keys ...string) string {
	for _, k := range keys {
		if s := stringValue(m[k]); s != "" {
			return s
		}
	}
	return ""
}
func stringField(m map[string]interface{}, key string) string { return stringValue(m[key]) }
func stringValue(v interface{}) string {
	switch x := v.(type) {
	case string:
		return x
	case json.Number:
		return x.String()
	case fmt.Stringer:
		return x.String()
	default:
		if v != nil {
			return fmt.Sprint(v)
		}
	}
	return ""
}
func intField(m map[string]interface{}, keys ...string) int {
	for _, k := range keys {
		switch v := m[k].(type) {
		case int:
			return v
		case int32:
			return int(v)
		case int64:
			return int(v)
		case uint:
			return int(v)
		case uint32:
			return int(v)
		case uint64:
			return int(v)
		case float64:
			return int(v)
		case json.Number:
			if i, err := v.Int64(); err == nil {
				return int(i)
			}
		case string:
			if i, err := strconv.Atoi(v); err == nil {
				return i
			}
		}
	}
	return 0
}
func stringSlice(v interface{}) []string {
	switch x := v.(type) {
	case []string:
		return x
	case []interface{}:
		out := make([]string, 0, len(x))
		for _, item := range x {
			if s := stringValue(item); s != "" {
				out = append(out, s)
			}
		}
		return out
	case string:
		if x != "" {
			return []string{x}
		}
	}
	return nil
}
