package ingest

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sentinelmesh/detection-engine/internal/types"
	"strings"
	"time"
)

// FileSource is a deterministic integration-test and offline-deployment source.
// It consumes one RawEvent JSON object per line and preserves the same ingest
// contract as Falco/eBPF. Production deployments can disable it entirely.
type FileSource struct{ path string }

func NewFileSource(path string) *FileSource { return &FileSource{path: path} }
func (f *FileSource) Stream(ctx context.Context, out chan<- types.RawEvent) error {
	if strings.TrimSpace(f.path) == "" {
		return fmt.Errorf("event file path is empty")
	}
	fh, err := os.Open(f.path)
	if err != nil {
		return err
	}
	defer fh.Close()
	scan := bufio.NewScanner(fh)
	scan.Buffer(make([]byte, 4096), 1<<20)
	for scan.Scan() {
		var raw types.RawEvent
		if err := json.Unmarshal(scan.Bytes(), &raw); err != nil {
			return fmt.Errorf("event-file decode: %w", err)
		}
		if raw.Timestamp.IsZero() {
			raw.Timestamp = time.Now().UTC()
		}
		if raw.Source == "" {
			return fmt.Errorf("event-file event missing source")
		}
		select {
		case out <- raw:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return scan.Err()
}
