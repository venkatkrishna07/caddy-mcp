package caddymcp

import (
	"sync"
	"time"
)

const defaultCleanupThreshold = 1000

type authRateLimiter struct {
	mu               sync.Mutex
	failures         map[string]*ipFailureRecord
	maxFails         int
	window           time.Duration
	cleanupThreshold int
}

type ipFailureRecord struct {
	count   int
	firstAt time.Time
}

func newAuthRateLimiter(maxFails int, window time.Duration) *authRateLimiter {
	return &authRateLimiter{
		failures:         make(map[string]*ipFailureRecord),
		maxFails:         maxFails,
		window:           window,
		cleanupThreshold: defaultCleanupThreshold,
	}
}

// maybeCleanup sweeps expired entries when map size exceeds threshold.
// Must be called with mu held.
func (rl *authRateLimiter) maybeCleanup() {
	if len(rl.failures) < rl.cleanupThreshold {
		return
	}
	now := time.Now()
	for ip, rec := range rl.failures {
		if now.Sub(rec.firstAt) > rl.window {
			delete(rl.failures, ip)
		}
	}
}

func (rl *authRateLimiter) allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.maybeCleanup()
	rec, ok := rl.failures[ip]
	if !ok {
		return true
	}
	if time.Since(rec.firstAt) > rl.window {
		delete(rl.failures, ip)
		return true
	}
	return rec.count < rl.maxFails
}

func (rl *authRateLimiter) recordFailure(ip string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.maybeCleanup()
	rec, ok := rl.failures[ip]
	if !ok || time.Since(rec.firstAt) > rl.window {
		rl.failures[ip] = &ipFailureRecord{count: 1, firstAt: time.Now()}
		return
	}
	rec.count++
}

func (rl *authRateLimiter) recordSuccess(ip string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	delete(rl.failures, ip)
}
