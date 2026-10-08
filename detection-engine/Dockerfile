FROM golang:1.25-bookworm AS build
WORKDIR /src
COPY go.mod ./
COPY . .
ARG BUILD_TAGS=""
RUN CGO_ENABLED=0 go build -tags "${BUILD_TAGS}" -trimpath -ldflags='-s -w' -o /out/sentinelmesh-detector ./cmd/detector

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends iptables wget ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --create-home sentinelmesh
WORKDIR /app
COPY --from=build /out/sentinelmesh-detector /usr/local/bin/sentinelmesh-detector
COPY config/config.json /app/config/config.json
RUN mkdir -p /var/lib/sentinelmesh/quarantine /var/lib/sentinelmesh/policy && chown -R sentinelmesh:sentinelmesh /var/lib/sentinelmesh
USER 0
EXPOSE 2112
ENTRYPOINT ["/usr/local/bin/sentinelmesh-detector"]
