//go:build sentinel_native

package ingest

// Regenerate with `make generate` in probes/ (needs headers/vmlinux.h
// generated on the target machine first -- see probes/README.md).
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror -Wno-missing-declarations -D__TARGET_ARCH_x86" bpf probes/probes.c -- -I./probes/headers

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"sentinelmesh/detection-engine/internal/types"
)

// EBPFSource loads SentinelMesh's own eBPF probes (process exec, TCP
// connect, write-intent file open) for lower-level visibility than
// Falco's default rule set gives. Real, not a stub -- see probes/probes.c
// for the kernel side and probes/README.md for the one-time per-machine
// build steps and this probe set's known limitations.
//
// Needs CAP_BPF+CAP_PERFMON (or root) to load, and a 5.8+ kernel for
// BPF_MAP_TYPE_RINGBUF.
type EBPFSource struct{}

func NewEBPFSource() *EBPFSource {
	return &EBPFSource{}
}

// Struct layouts below must byte-for-byte match probes.c's
// `__attribute__((packed))` event structs -- packed specifically so
// there's no compiler-dependent alignment padding to account for on
// either side of this boundary. Address fields are raw byte arrays
// rather than integers so there's no endianness reinterpretation to get
// wrong when decoding (see probes.c's comment on this).

type execEventRaw struct {
	PID      uint32
	PPID     uint32
	UID      uint32
	Comm     [16]byte
	Filename [256]byte
}

type connectEventRaw struct {
	PID   uint32
	UID   uint32
	Comm  [16]byte
	SAddr [4]byte
	DAddr [4]byte
	SPort uint16
	DPort uint16
}

type fileEventRaw struct {
	PID      uint32
	UID      uint32
	Comm     [16]byte
	Filename [256]byte
}

func cString(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}

func (e *EBPFSource) Stream(ctx context.Context, out chan<- types.RawEvent) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("ebpf: remove memlock rlimit (running as root/CAP_BPF?): %w", err)
	}

	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		return fmt.Errorf("ebpf: load probes (built with `make generate` in probes/?): %w", err)
	}
	defer objs.Close()

	execLink, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.TraceSysEnterExecve, nil)
	if err != nil {
		return fmt.Errorf("ebpf: attach exec tracepoint: %w", err)
	}
	defer execLink.Close()

	connectEntryLink, err := link.Kprobe("tcp_v4_connect", objs.TraceTcpV4ConnectEntry, nil)
	if err != nil {
		return fmt.Errorf("ebpf: attach tcp_v4_connect kprobe: %w", err)
	}
	defer connectEntryLink.Close()

	connectReturnLink, err := link.Kretprobe("tcp_v4_connect", objs.TraceTcpV4ConnectReturn, nil)
	if err != nil {
		return fmt.Errorf("ebpf: attach tcp_v4_connect kretprobe: %w", err)
	}
	defer connectReturnLink.Close()

	openLink, err := link.Tracepoint("syscalls", "sys_enter_openat", objs.TraceSysEnterOpenat, nil)
	if err != nil {
		return fmt.Errorf("ebpf: attach openat tracepoint: %w", err)
	}
	defer openLink.Close()

	execRd, err := ringbuf.NewReader(objs.ExecEvents)
	if err != nil {
		return fmt.Errorf("ebpf: open exec ringbuf reader: %w", err)
	}
	defer execRd.Close()

	connectRd, err := ringbuf.NewReader(objs.ConnectEvents)
	if err != nil {
		return fmt.Errorf("ebpf: open connect ringbuf reader: %w", err)
	}
	defer connectRd.Close()

	fileRd, err := ringbuf.NewReader(objs.FileEvents)
	if err != nil {
		return fmt.Errorf("ebpf: open file ringbuf reader: %w", err)
	}
	defer fileRd.Close()

	// Each ring buffer reader blocks on Read(), so each gets its own
	// goroutine; all three funnel into the same RawEvent channel that
	// the rest of the hot path (normalize -> detect -> respond) already
	// reads from regardless of source.
	errCh := make(chan error, 3)
	go readExecEvents(ctx, execRd, out, errCh)
	go readConnectEvents(ctx, connectRd, out, errCh)
	go readFileEvents(ctx, fileRd, out, errCh)

	select {
	case <-ctx.Done():
		// Closing the readers unblocks their blocking Read() calls so
		// the three goroutines above actually exit instead of leaking.
		execRd.Close()
		connectRd.Close()
		fileRd.Close()
		return ctx.Err()
	case err := <-errCh:
		return err
	}
}

func readExecEvents(ctx context.Context, rd *ringbuf.Reader, out chan<- types.RawEvent, errCh chan<- error) {
	for {
		record, err := rd.Read()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			errCh <- fmt.Errorf("ebpf: read exec ringbuf: %w", err)
			return
		}

		var raw execEventRaw
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &raw); err != nil {
			continue // malformed record -- drop and keep reading
		}

		payload := map[string]interface{}{
			"event_type": "process_exec",
			"pid":        int(raw.PID),
			"ppid":       int(raw.PPID),
			"uid":        int(raw.UID),
			"proc.comm":  cString(raw.Comm[:]),
			"proc.exe":   cString(raw.Filename[:]),
		}
		send(ctx, out, "ebpf", payload)
	}
}

func readConnectEvents(ctx context.Context, rd *ringbuf.Reader, out chan<- types.RawEvent, errCh chan<- error) {
	for {
		record, err := rd.Read()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			errCh <- fmt.Errorf("ebpf: read connect ringbuf: %w", err)
			return
		}

		var raw connectEventRaw
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &raw); err != nil {
			continue
		}

		payload := map[string]interface{}{
			"event_type": "network_connect",
			"pid":        int(raw.PID),
			"uid":        int(raw.UID),
			"proc.comm":  cString(raw.Comm[:]),
			"net.saddr":  net.IPv4(raw.SAddr[0], raw.SAddr[1], raw.SAddr[2], raw.SAddr[3]).String(),
			"net.daddr":  net.IPv4(raw.DAddr[0], raw.DAddr[1], raw.DAddr[2], raw.DAddr[3]).String(),
			"net.sport":  int(raw.SPort),
			"net.dport":  int(raw.DPort),
		}
		send(ctx, out, "ebpf", payload)
	}
}

func readFileEvents(ctx context.Context, rd *ringbuf.Reader, out chan<- types.RawEvent, errCh chan<- error) {
	for {
		record, err := rd.Read()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			errCh <- fmt.Errorf("ebpf: read file ringbuf: %w", err)
			return
		}

		var raw fileEventRaw
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &raw); err != nil {
			continue
		}

		payload := map[string]interface{}{
			"event_type": "file_write",
			"pid":        int(raw.PID),
			"uid":        int(raw.UID),
			"proc.comm":  cString(raw.Comm[:]),
			"file.path":  cString(raw.Filename[:]),
		}
		send(ctx, out, "ebpf", payload)
	}
}

func send(ctx context.Context, out chan<- types.RawEvent, source string, payload map[string]interface{}) {
	select {
	case out <- types.RawEvent{Source: source, Timestamp: time.Now().UTC(), Payload: payload}:
	case <-ctx.Done():
	}
}
