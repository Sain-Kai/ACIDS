//go:build !sentinel_native

package ingest

import (
	"context"
	"errors"
	"sentinelmesh/detection-engine/internal/types"
)

type EBPFSource struct{}

func NewEBPFSource() *EBPFSource { return &EBPFSource{} }
func (e *EBPFSource) Stream(ctx context.Context, out chan<- types.RawEvent) error {
	_ = out
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return errors.New("eBPF integration disabled: build with -tags sentinel_native")
	}
}
