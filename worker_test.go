package caddymcp

import (
	"sync/atomic"
	"testing"

	"go.uber.org/zap"
)

func TestWorkerGroup_GoAndWait(t *testing.T) {
	wg := newWorkerGroup(zap.NewNop())
	var count atomic.Int64

	for i := 0; i < 10; i++ {
		wg.Go("test-worker", func() {
			count.Add(1)
		})
	}

	wg.Wait()

	if got := count.Load(); got != 10 {
		t.Errorf("count = %d, want 10", got)
	}
	if got := wg.Count(); got != 0 {
		t.Errorf("Count() = %d, want 0 after Wait", got)
	}
}

func TestWorkerGroup_PanicRecovery(t *testing.T) {
	wg := newWorkerGroup(zap.NewNop())

	wg.Go("panicking-worker", func() {
		panic("test panic")
	})

	wg.Wait()
}
