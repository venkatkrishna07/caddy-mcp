package caddymcp

import (
	"runtime/debug"
	"sync"
	"sync/atomic"

	"go.uber.org/zap"
)

// workerGroup manages named goroutines with panic recovery
// and an atomic active-count for observability and graceful shutdown.
type workerGroup struct {
	wg    sync.WaitGroup
	count atomic.Int64
	log   *zap.Logger
}

func newWorkerGroup(log *zap.Logger) *workerGroup {
	return &workerGroup{log: log}
}

// Go starts fn in a goroutine named name.
// Panics inside fn are caught, logged, and do not propagate.
func (g *workerGroup) Go(name string, fn func()) {
	g.wg.Add(1)
	g.count.Add(1)
	go func() {
		defer g.wg.Done()
		defer g.count.Add(-1)
		defer g.recoverPanic(name)
		fn()
	}()
}

func (g *workerGroup) Count() int64 { return g.count.Load() }

func (g *workerGroup) Wait() { g.wg.Wait() }

func (g *workerGroup) recoverPanic(name string) {
	r := recover()
	if r == nil {
		return
	}
	g.log.Error("goroutine panicked — recovered",
		zap.String("worker", name),
		zap.Any("panic", r),
		zap.String("stack", string(debug.Stack())),
	)
}
