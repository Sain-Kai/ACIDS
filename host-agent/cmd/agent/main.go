// Command agent is SentinelMesh's per-host privileged-action daemon.
// Runs on every protected host (one instance each -- this is NOT a
// central service); control-plane calls it over HTTP by hostname to
// perform the reclaim-protocol actions that need to happen on that
// specific host (kill, firewall isolate/lift, lock account, quarantine,
// snapshot/restore, persistence scan). See ../../README.md.
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"sentinelmesh/host-agent/internal/actions"

	"sentinelmesh/host-agent/internal/api"
	"sentinelmesh/host-agent/internal/config"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	snapshotter := &actions.Snapshotter{Root: cfg.SnapshotDir, Paths: cfg.SnapshotPaths, Keep: cfg.SnapshotKeep, HostRoot: cfg.HostRoot}
	if id, snapErr := snapshotter.Create(time.Now().UTC()); snapErr != nil {
		log.Printf("startup snapshot completed with warnings id=%s err=%v", id, snapErr)
	} else {
		log.Printf("startup baseline snapshot created id=%s", id)
	}

	srv := api.New(cfg)
	log.Printf("sentinelmesh host-agent listening on %s", cfg.ListenAddr)
	httpSrv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           srv.Routes(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	serverErr := make(chan error, 1)
	go func() { serverErr <- httpSrv.ListenAndServe() }()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	select {
	case err := <-serverErr:
		if err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %v", err)
		}
	case <-sig:
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := httpSrv.Shutdown(ctx); err != nil {
			log.Printf("graceful shutdown failed: %v", err)
		}
	}
}
