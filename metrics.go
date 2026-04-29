package caddymcp

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	metricTunnelsDeclared = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "mcp",
		Name:      "tunnels_registered",
		Help:      "Number of tunnels declared in Caddyfile.",
	})

	metricTunnelsClaimed = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "mcp",
		Name:      "tunnels_claimed",
		Help:      "Number of tunnels currently claimed by clients.",
	})

	metricClientsConnected = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "mcp",
		Name:      "clients_connected",
		Help:      "Number of QUIC client connections currently active.",
	})

	metricClientConnects = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "mcp",
		Name:      "client_connects_total",
		Help:      "Total client connection attempts.",
	}, []string{"result"})

	metricRequests = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "mcp",
		Name:      "requests_total",
		Help:      "Total HTTP requests proxied through tunnels.",
	}, []string{"tunnel", "mcp_method", "status"})

	metricRequestDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "mcp",
		Name:      "request_duration_seconds",
		Help:      "Histogram of request durations through tunnels.",
		Buckets:   prometheus.DefBuckets,
	}, []string{"tunnel", "mcp_method"})

	metricStreamsActive = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "mcp",
		Name:      "streams_active",
		Help:      "Number of active QUIC data streams per tunnel.",
	}, []string{"tunnel"})

	metricTokenAuthFailures = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "mcp",
		Name:      "auth_failures_total",
		Help:      "Total token authentication failures.",
	})

	metricSessionsActive = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "mcp",
		Name:      "sessions_active",
		Help:      "Number of active MCP sessions per tunnel.",
	}, []string{"tunnel"})

	metricSessionDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "mcp",
		Name:      "session_duration_seconds",
		Help:      "Histogram of MCP session durations.",
		Buckets:   prometheus.DefBuckets,
	}, []string{"tunnel"})

	metricPolicyDecisions = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "mcp",
		Name:      "policy_decisions_total",
		Help:      "Total policy evaluation decisions.",
	}, []string{"tunnel", "decision", "reason"})

	metricSSEStreamsActive = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "mcp",
		Name:      "sse_streams_active",
		Help:      "Number of active SSE streams per tunnel.",
	}, []string{"tunnel"})

	metricSSEEvents = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "mcp",
		Name:      "sse_events_total",
		Help:      "Total SSE events sent per tunnel.",
	}, []string{"tunnel"})
)
