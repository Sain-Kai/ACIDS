# Multi-stage: build with the Go toolchain, run in a minimal image that
# still has the host-level binaries the agent shells out to (iptables,
# usermod, pkill, cp). This needs to run with real host privileges --
# see deploy/docker-compose.yml's commented-out host-agent service for
# the capabilities/mounts it actually needs, which are NOT optional
# extras here the way they were for detection-engine's "uncomment for
# real use" containment actions. Without them every endpoint just
# returns errors.
FROM golang:1.25-bookworm AS build
WORKDIR /src
COPY go.mod ./
RUN go mod download 2>/dev/null || true
COPY . .
RUN CGO_ENABLED=0 go build -o /out/agent ./cmd/agent

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      iptables passwd procps coreutils wget ca-certificates docker.io \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/agent /usr/local/bin/sentinelmesh-agent
RUN mkdir -p /var/lib/sentinelmesh/policy /var/lib/sentinelmesh/quarantine /var/lib/sentinelmesh/snapshots /var/lib/sentinelmesh/sandbox-staging
EXPOSE 9090
ENTRYPOINT ["/usr/local/bin/sentinelmesh-agent"]
