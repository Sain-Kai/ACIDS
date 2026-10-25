# SentinelMesh eBPF probes

Three probes, each described in more detail in `probes.c`:

| Probe | Hook | Fires on |
|---|---|---|
| `trace_sys_enter_execve` | tracepoint `syscalls/sys_enter_execve` | every `execve(2)` call |
| `trace_tcp_v4_connect_entry` / `_return` | kprobe+kretprobe `tcp_v4_connect` | every **successful outbound IPv4 TCP** connect |
| `trace_sys_enter_openat` | tracepoint `syscalls/sys_enter_openat` | every `openat(2)` call **not** opened read-only |

## One-time setup (per target machine)

1. Install `clang`, `llvm`, `libbpf-dev` (or equivalent for your distro),
   and `bpftool`.
2. Generate `headers/vmlinux.h` from the target kernel's own BTF info —
   this is machine/kernel-specific and deliberately not checked into the
   repo:
   ```
   make vmlinux-header
   ```
   Requires a kernel with `CONFIG_DEBUG_INFO_BTF=y` (default on most
   mainstream distro kernels from the last several years; check with
   `ls /sys/kernel/btf/vmlinux`).
3. Generate the Go bindings and embedded bytecode:
   ```
   make generate
   ```
   This runs `go generate -tags sentinel_native ./...`, which includes the build-tagged eBPF loader and invokes `bpf2go`; it needs the `github.com/cilium/ebpf` module
   resolvable — `go mod tidy` in `detection-engine/` first if you
   haven't already (see the module's own note about needing network
   access, same as the Falco client dependency).
4. Run as root (or with `CAP_BPF`+`CAP_PERFMON`, or in a container with
   those capabilities and host PID namespace):
   ```
   sudo ./detector
   ```
   Kernel 5.8+ is required for `BPF_MAP_TYPE_RINGBUF`.

## Known limitations

These are deliberate scoping decisions, not oversights — noted here so
they're not mistaken for the finished article:

- **IPv4 only.** `tcp_v6_connect` isn't hooked; IPv6 outbound connects
  are invisible to this probe (Falco, if also running, may still catch
  them depending on its own rule pack).
- **exec filename, not resolved path.** `execve`'s `filename` argument is
  captured as the caller passed it — may be relative, and isn't resolved
  against the process's cwd. Same for `openat`'s filename against its
  `dfd` argument.
- **No argv/envp, no parent process name.** Only the exec target path and
  numeric PPID are captured — cmdline-pattern rules
  (`ReverseShellIndicatorRule`, `ObfuscatedCommandRule`,
  `ContainerEscapeIndicatorRule`) and parent-name rules
  (`ShellFromWebProcessRule`, `PrivilegeEscalationRule`) don't get
  meaningful signal from an eBPF-sourced exec event today. Falco
  ingestion already fills this gap (its default rules capture full
  `proc.cmdline` and `proc.pname`), so this matters less if Falco is also
  running — the two sources are meant to cover for each other here, not
  duplicate.
- **File monitoring is open-based, not write-based.** Deliberately
  hooked at `openat` rather than `vfs_write` to avoid the event volume
  of tracing every `write()` syscall system-wide — this means a file
  opened once and written to many times produces one event, not many,
  but also means writes through an fd opened before the probe attached
  are invisible.
- **No path resolution beyond what the string argument gives.**
  Resolving a full absolute path from a kprobe/tracepoint context (dentry
  walk, or the `dfd`+relative-path case for `openat`) is possible but
  adds real complexity and risk of getting the CO-RE reads wrong; left
  out for now in favor of a correct, narrower probe.
Build note: clang 18 can report harmless forward declarations emitted by bpftool-generated vmlinux.h as `-Wmissing-declarations`; the bpf2go command disables that single warning while retaining `-Werror` for the probe source.
