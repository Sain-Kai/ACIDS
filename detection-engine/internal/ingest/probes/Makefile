# One-time and repeat build steps for SentinelMesh's eBPF probes.
# Run these from this directory (internal/ingest/probes/).

# vmlinux.h is generated FROM THE TARGET KERNEL's own BTF info -- it
# can't be checked into the repo (it's kernel-version-specific and
# would silently go stale). Requires a kernel built with
# CONFIG_DEBUG_INFO_BTF=y (true on any mainstream distro kernel from
# roughly the last several years) and bpftool installed.
vmlinux-header:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > headers/vmlinux.h

# Regenerates probes_bpfel.go / probes_bpfeb.go and the compiled object
# bytes embedded into the Go binary. Requires clang and vmlinux-header
# to have been run at least once.
generate:
	cd .. && go generate -tags sentinel_native ./...

# Runs the whole detection-engine, which needs CAP_BPF+CAP_PERFMON (or
# root) to load the probes and attach kprobes/tracepoints.
run:
	cd ../../.. && go run ./cmd/detector

.PHONY: vmlinux-header generate run
