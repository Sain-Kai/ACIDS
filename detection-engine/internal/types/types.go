// Package types holds the shared structs used across every stage of the
// detection-engine pipeline (ingest -> normalize -> detect -> response).
package types

import "time"

// RawEvent is whatever an ingest source hands off, before normalization.
// Kept deliberately loose (map) because eBPF and Falco raw payloads differ.
type RawEvent struct {
	Source    string
	Timestamp time.Time
	Payload   map[string]interface{}
}

// Event is the normalized representation, mirroring
// common/schema/event.schema.json. Every downstream stage operates on this.
// JSON tags match the schema field names exactly -- control-plane's
// IncomingEventDTO is written against this same shape.
type Event struct {
	EventID       string                 `json:"event_id"`
	CorrelationID string                 `json:"correlation_id,omitempty"`
	Timestamp     time.Time              `json:"timestamp"`
	Source        string                 `json:"source"`
	Host          HostInfo               `json:"host"`
	EventType     string                 `json:"event_type"`
	Process       *ProcessInfo           `json:"process,omitempty"`
	Network       *NetworkInfo           `json:"network,omitempty"`
	File          *FileInfo              `json:"file,omitempty"`
	Syscall       string                 `json:"syscall,omitempty"`
	SeverityRaw   string                 `json:"severity_raw"`
	Tags          []string               `json:"tags,omitempty"`
	RawPayload    map[string]interface{} `json:"raw_payload,omitempty"`
}

type HostInfo struct {
	Hostname       string `json:"hostname"`
	IP             string `json:"ip,omitempty"`
	ContainerID    string `json:"container_id,omitempty"`
	ContainerImage string `json:"container_image,omitempty"`
}

type ProcessInfo struct {
	PID     int    `json:"pid"`
	PPID    int    `json:"ppid,omitempty"`
	Exe     string `json:"exe,omitempty"`
	Cmdline string `json:"cmdline,omitempty"`
	User    string `json:"user,omitempty"`
}

type NetworkInfo struct {
	SrcIP    string `json:"src_ip,omitempty"`
	DstIP    string `json:"dst_ip,omitempty"`
	SrcPort  int    `json:"src_port,omitempty"`
	DstPort  int    `json:"dst_port,omitempty"`
	Protocol string `json:"protocol,omitempty"`
}

type FileInfo struct {
	Path      string `json:"path"`
	Operation string `json:"operation"`
}

// Verdict is what the detection engine returns for an event.
type Verdict struct {
	Score        float64        `json:"score"` // 0.0 (benign) - 1.0 (certain malicious)
	MatchedRules []string       `json:"matched_rules,omitempty"`
	Action       ResponseAction `json:"action"`
}

type ResponseAction string

const (
	ActionNone              ResponseAction = "none"
	ActionBlockNetwork      ResponseAction = "block_network"
	ActionIsolateWorkload   ResponseAction = "isolate_workload"
	ActionKillProcess       ResponseAction = "kill_process"
	ActionQuarantineFile    ResponseAction = "quarantine_file"
	ActionRevokeAccess      ResponseAction = "revoke_access"
	ActionEscalateToReclaim ResponseAction = "escalate_to_reclaim"
)
