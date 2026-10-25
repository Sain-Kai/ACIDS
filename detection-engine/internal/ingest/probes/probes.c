//go:build ignore

// SentinelMesh's own eBPF probes: process exec, outbound TCP connect, and
// write-intent file opens. Deliberately narrow in scope (see probes/README.md
// for exactly what each one does and doesn't capture) -- these exist to give
// the hot path kernel-level visibility that doesn't depend on Falco being
// installed, not to replace a full Falco/Tetragon-grade rule engine.
//
// Compiled via bpf2go (see ../ebpf.go's //go:generate line), which needs
// headers/vmlinux.h generated on the TARGET machine first -- see
// probes/README.md. This file is never compiled directly by `go build`;
// the `//go:build ignore` tag above keeps the Go toolchain from trying.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

char __license[] SEC("license") = "Dual MIT/GPL";

#define COMM_LEN 16
#define FILENAME_LEN 256

// Syscall open(2)/openat(2) flag bits. Hardcoded rather than included from
// a UAPI fcntl.h: these specific low bits (access-mode + O_CREAT) have been
// stable, fixed ABI values since the earliest Linux versions, and pulling
// in fcntl.h inside a restricted BPF compilation unit is more trouble than
// it's worth for three constants.
#define O_ACCMODE 00000003
#define O_RDONLY  00000000

// ---------------------------------------------------------------------
// process_exec: one event per execve(2) call, captured at syscall entry.
// ---------------------------------------------------------------------

struct exec_event {
	__u32 pid;
	__u32 ppid;
	__u32 uid;
	char comm[COMM_LEN];
	char filename[FILENAME_LEN];
} __attribute__((packed));

const struct exec_event *unused_exec_event __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} exec_events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_sys_enter_execve(struct trace_event_raw_sys_enter *ctx)
{
	struct exec_event *e;
	struct task_struct *task;
	u64 pid_tgid;

	e = bpf_ringbuf_reserve(&exec_events, sizeof(*e), 0);
	if (!e) {
		return 0;
	}

	pid_tgid = bpf_get_current_pid_tgid();
	e->pid = pid_tgid >> 32;
	e->uid = (u32)bpf_get_current_uid_gid();
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	// Real parent's tgid via CO-RE task_struct walk -- standard pattern
	// for getting ppid from tracepoint/kprobe context, where there's no
	// syscall argument carrying it directly.
	task = (struct task_struct *)bpf_get_current_task();
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);

	// args[0] is execve's `filename` argument -- a userspace pointer,
	// still valid to read at sys_enter (the syscall hasn't run yet).
	// This is the path as the caller passed it (may be relative, and
	// argv/envp are not captured here -- see README's known limitations).
	bpf_probe_read_user_str(&e->filename, sizeof(e->filename), (const char *)ctx->args[0]);

	bpf_ringbuf_submit(e, 0);
	return 0;
}

// ---------------------------------------------------------------------
// network_connect: one event per successful outbound IPv4 TCP connect.
// A kprobe+kretprobe pair rather than a single kprobe, because the
// socket's address/port fields aren't reliably populated yet at
// tcp_v4_connect's entry -- only after it returns successfully. This
// mirrors the well-established bcc tcpv4connect pattern.
// ---------------------------------------------------------------------

struct connect_event {
	__u32 pid;
	__u32 uid;
	char comm[COMM_LEN];
	__u8 saddr[4];
	__u8 daddr[4];
	__u16 sport;
	__u16 dport;
} __attribute__((packed));

const struct connect_event *unused_connect_event __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} connect_events SEC(".maps");

// Stashes the in-flight `struct sock *` between kprobe entry and
// kretprobe return, keyed by pid_tgid (assumes one in-flight connect(2)
// per thread at a time, which holds in practice).
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, u64);
	__type(value, u64);
} sentinelmesh_currsock SEC(".maps");

SEC("kprobe/tcp_v4_connect")
int trace_tcp_v4_connect_entry(struct pt_regs *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u64 skp = (u64)PT_REGS_PARM1(ctx);
	bpf_map_update_elem(&sentinelmesh_currsock, &pid_tgid, &skp, BPF_ANY);
	return 0;
}

SEC("kretprobe/tcp_v4_connect")
int trace_tcp_v4_connect_return(struct pt_regs *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u64 *skpp;
	struct sock *sk;
	struct connect_event *e;
	int ret;

	skpp = bpf_map_lookup_elem(&sentinelmesh_currsock, &pid_tgid);
	if (!skpp) {
		return 0; // missed the entry probe for this call
	}

	ret = PT_REGS_RC(ctx);
	if (ret != 0) {
		// connect() failed -- socket fields may be half-populated;
		// nothing worth reporting.
		bpf_map_delete_elem(&sentinelmesh_currsock, &pid_tgid);
		return 0;
	}

	sk = (struct sock *)(*skpp);

	e = bpf_ringbuf_reserve(&connect_events, sizeof(*e), 0);
	if (!e) {
		bpf_map_delete_elem(&sentinelmesh_currsock, &pid_tgid);
		return 0;
	}

	e->pid = pid_tgid >> 32;
	e->uid = (u32)bpf_get_current_uid_gid();
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	// skc_rcv_saddr/skc_daddr are __be32 (network-byte-order) -- copied
	// here as raw bytes into a byte array rather than a Go uint32, so
	// there is no endianness reinterpretation to get wrong on either
	// side of the boundary; see ebpf.go's decode side.
	BPF_CORE_READ_INTO(&e->saddr, sk, __sk_common.skc_rcv_saddr);
	BPF_CORE_READ_INTO(&e->daddr, sk, __sk_common.skc_daddr);

	// skc_num (local/source port) is already host-byte-order in the
	// kernel; skc_dport (remote/dest port) is network-byte-order and
	// needs bpf_ntohs() -- this asymmetry is a well-known kernel quirk,
	// not a typo.
	e->sport = BPF_CORE_READ(sk, __sk_common.skc_num);
	e->dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

	bpf_ringbuf_submit(e, 0);
	bpf_map_delete_elem(&sentinelmesh_currsock, &pid_tgid);
	return 0;
}

// ---------------------------------------------------------------------
// file_write: one event per non-read-only openat(2) call (i.e. the
// caller asked to write). Deliberately hooked at open, not at vfs_write:
// vfs_write fires on every single write() syscall system-wide, which on
// a busy host is enormous volume for very little extra signal over
// "this process opened this path for writing." openat gives one event
// per file touched instead of one per write() call.
// ---------------------------------------------------------------------

struct file_event {
	__u32 pid;
	__u32 uid;
	char comm[COMM_LEN];
	char filename[FILENAME_LEN];
} __attribute__((packed));

const struct file_event *unused_file_event __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} file_events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_sys_enter_openat(struct trace_event_raw_sys_enter *ctx)
{
	struct file_event *e;
	long flags;
	u64 pid_tgid;

	// args: (int dfd, const char *filename, int flags, umode_t mode)
	flags = (long)ctx->args[2];
	if ((flags & O_ACCMODE) == O_RDONLY) {
		return 0; // not a write-intent open -- not interesting here
	}

	e = bpf_ringbuf_reserve(&file_events, sizeof(*e), 0);
	if (!e) {
		return 0;
	}

	pid_tgid = bpf_get_current_pid_tgid();
	e->pid = pid_tgid >> 32;
	e->uid = (u32)bpf_get_current_uid_gid();
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	// args[1] is openat's `filename` argument -- as passed by the
	// caller, so it may be relative to `dfd` rather than absolute; full
	// path resolution is a known limitation, see README.
	bpf_probe_read_user_str(&e->filename, sizeof(e->filename), (const char *)ctx->args[1]);

	bpf_ringbuf_submit(e, 0);
	return 0;
}
