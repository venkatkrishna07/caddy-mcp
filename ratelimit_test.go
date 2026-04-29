package caddymcp

import (
	"testing"
	"time"
)

func TestAuthRateLimiter_AllowsInitialRequest(t *testing.T) {
	rl := newAuthRateLimiter(3, 30*time.Second)
	if !rl.allow("1.2.3.4") {
		t.Error("first request should be allowed")
	}
}

func TestAuthRateLimiter_BlocksAfterMaxFailures(t *testing.T) {
	rl := newAuthRateLimiter(3, 30*time.Second)
	ip := "1.2.3.4"

	for i := 0; i < 3; i++ {
		rl.recordFailure(ip)
	}

	if rl.allow(ip) {
		t.Error("should be blocked after 3 failures")
	}
}

func TestAuthRateLimiter_SuccessResetsFailures(t *testing.T) {
	rl := newAuthRateLimiter(3, 30*time.Second)
	ip := "1.2.3.4"

	rl.recordFailure(ip)
	rl.recordFailure(ip)
	rl.recordSuccess(ip)

	if !rl.allow(ip) {
		t.Error("should be allowed after success reset")
	}
}

func TestAuthRateLimiter_WindowExpiry(t *testing.T) {
	rl := newAuthRateLimiter(3, 1*time.Millisecond)
	ip := "1.2.3.4"

	for i := 0; i < 3; i++ {
		rl.recordFailure(ip)
	}

	time.Sleep(5 * time.Millisecond)

	if !rl.allow(ip) {
		t.Error("should be allowed after window expiry")
	}
}

func TestAuthRateLimiter_IndependentIPs(t *testing.T) {
	rl := newAuthRateLimiter(3, 30*time.Second)

	for i := 0; i < 3; i++ {
		rl.recordFailure("1.1.1.1")
	}

	if !rl.allow("2.2.2.2") {
		t.Error("different IP should not be affected")
	}
}
