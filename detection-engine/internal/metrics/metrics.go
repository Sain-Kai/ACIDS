package metrics

import (
	"fmt"
	"net/http"
	"sync/atomic"
)

type Counters struct {
	Events          atomic.Uint64
	Detections      atomic.Uint64
	Containments    atomic.Uint64
	Reclaims        atomic.Uint64
	QueueDrops      atomic.Uint64
	NormalizeErrors atomic.Uint64
}

func Handler(c *Counters) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		fmt.Fprintf(w,
			"sentinelmesh_events_total %d\nsentinelmesh_detections_total %d\nsentinelmesh_containments_total %d\nsentinelmesh_reclaims_total %d\nsentinelmesh_incident_queue_drops_total %d\nsentinelmesh_normalize_errors_total %d\n",
			c.Events.Load(), c.Detections.Load(), c.Containments.Load(), c.Reclaims.Load(), c.QueueDrops.Load(), c.NormalizeErrors.Load())
	})
	return mux
}
