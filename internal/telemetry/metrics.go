package telemetry

import (
	"context"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/cyberark/secretless-broker/pkg/secretless"
)

// Instruments holds the OpenTelemetry metric instruments for Secretless Broker.
type Instruments struct {
	HTTPRequests        metric.Int64Counter
	HTTPRequestDuration metric.Float64Histogram
	HTTPActiveRequests  metric.Int64UpDownCounter
	HTTPUpstreamDur     metric.Float64Histogram

	TCPConnections       metric.Int64Counter
	TCPActiveConnections metric.Int64UpDownCounter
	TCPConnectionDur     metric.Float64Histogram
	TCPConnectDur        metric.Float64Histogram
	TCPBytes             metric.Int64Counter

	SSHConnections       metric.Int64Counter
	SSHActiveConnections metric.Int64UpDownCounter
	SSHConnectionDur     metric.Float64Histogram

	CredentialResolves   metric.Int64Counter
	CredentialResolveDur metric.Float64Histogram

	ConfigReloads metric.Int64Counter
}

var (
	instrumentsMu     sync.RWMutex
	cachedProvider    metric.MeterProvider
	cachedInstruments *Instruments
)

// GetInstruments returns metric instruments bound to the current global
// OpenTelemetry MeterProvider. Instruments are cached per MeterProvider so
// hot-path recording incurs no allocations while still reflecting provider
// changes during initialization or tests.
func GetInstruments() *Instruments {
	mp := otel.GetMeterProvider()

	instrumentsMu.RLock()
	if cachedInstruments != nil && cachedProvider == mp {
		inst := cachedInstruments
		instrumentsMu.RUnlock()
		return inst
	}
	instrumentsMu.RUnlock()

	instrumentsMu.Lock()
	defer instrumentsMu.Unlock()

	if cachedInstruments != nil && cachedProvider == mp {
		return cachedInstruments
	}

	inst := newInstruments(mp.Meter(
		InstrumentationScope,
		metric.WithInstrumentationVersion(secretless.FullVersionName),
	))
	cachedProvider = mp
	cachedInstruments = inst
	return inst
}

func newInstruments(meter metric.Meter) *Instruments {
	httpReqs, _ := meter.Int64Counter(
		"secretless.http.requests",
		metric.WithDescription("Total number of HTTP proxy requests handled by Secretless Broker"),
		metric.WithUnit("{request}"),
	)
	httpReqDur, _ := meter.Float64Histogram(
		"secretless.http.request.duration",
		metric.WithDescription("End-to-end duration of HTTP proxy requests"),
		metric.WithUnit("s"),
	)
	httpActive, _ := meter.Int64UpDownCounter(
		"secretless.http.active_requests",
		metric.WithDescription("Number of in-flight HTTP proxy requests"),
		metric.WithUnit("{request}"),
	)
	httpUpstreamDur, _ := meter.Float64Histogram(
		"secretless.http.upstream.duration",
		metric.WithDescription("Duration of upstream HTTP round trips"),
		metric.WithUnit("s"),
	)

	tcpConns, _ := meter.Int64Counter(
		"secretless.tcp.connections",
		metric.WithDescription("Total number of TCP proxy connections handled by Secretless Broker"),
		metric.WithUnit("{connection}"),
	)
	tcpActive, _ := meter.Int64UpDownCounter(
		"secretless.tcp.active_connections",
		metric.WithDescription("Number of active TCP proxy connections"),
		metric.WithUnit("{connection}"),
	)
	tcpConnDur, _ := meter.Float64Histogram(
		"secretless.tcp.connection.duration",
		metric.WithDescription("Total lifetime duration of TCP proxy connections"),
		metric.WithUnit("s"),
	)
	tcpConnectDur, _ := meter.Float64Histogram(
		"secretless.tcp.connect.duration",
		metric.WithDescription("Duration of TCP backend authentication and connection setup"),
		metric.WithUnit("s"),
	)
	tcpBytes, _ := meter.Int64Counter(
		"secretless.tcp.bytes",
		metric.WithDescription("Total bytes proxied over TCP connections"),
		metric.WithUnit("By"),
	)

	sshConns, _ := meter.Int64Counter(
		"secretless.ssh.connections",
		metric.WithDescription("Total number of SSH and SSH-Agent proxy connections"),
		metric.WithUnit("{connection}"),
	)
	sshActive, _ := meter.Int64UpDownCounter(
		"secretless.ssh.active_connections",
		metric.WithDescription("Number of active SSH and SSH-Agent proxy connections"),
		metric.WithUnit("{connection}"),
	)
	sshConnDur, _ := meter.Float64Histogram(
		"secretless.ssh.connection.duration",
		metric.WithDescription("Duration of SSH and SSH-Agent proxy connections"),
		metric.WithUnit("s"),
	)

	credResolves, _ := meter.Int64Counter(
		"secretless.credentials.resolve.total",
		metric.WithDescription("Total number of credential provider resolution calls"),
		metric.WithUnit("{resolution}"),
	)
	credResolveDur, _ := meter.Float64Histogram(
		"secretless.credentials.resolve.duration",
		metric.WithDescription("Duration of credential provider resolution calls"),
		metric.WithUnit("s"),
	)

	configReloads, _ := meter.Int64Counter(
		"secretless.config.reloads",
		metric.WithDescription("Total number of Secretless configuration loads and reloads"),
		metric.WithUnit("{reload}"),
	)

	return &Instruments{
		HTTPRequests:         httpReqs,
		HTTPRequestDuration:  httpReqDur,
		HTTPActiveRequests:   httpActive,
		HTTPUpstreamDur:      httpUpstreamDur,
		TCPConnections:       tcpConns,
		TCPActiveConnections: tcpActive,
		TCPConnectionDur:     tcpConnDur,
		TCPConnectDur:        tcpConnectDur,
		TCPBytes:             tcpBytes,
		SSHConnections:       sshConns,
		SSHActiveConnections: sshActive,
		SSHConnectionDur:     sshConnDur,
		CredentialResolves:   credResolves,
		CredentialResolveDur: credResolveDur,
		ConfigReloads:        configReloads,
	}
}

// RecordHTTPRequest records count and latency for a completed HTTP proxy request.
func RecordHTTPRequest(ctx context.Context, service, connector, method string, statusCode int, outcome string, d time.Duration) {
	inst := GetInstruments()
	normMethod := NormalizeHTTPMethod(method)
	inst.HTTPRequests.Add(ctx, 1, metric.WithAttributes(
		attribute.String("service", service),
		attribute.String("connector", connector),
		attribute.String("method", normMethod),
		attribute.Int("status_code", statusCode),
		attribute.String("outcome", outcome),
	))
	inst.HTTPRequestDuration.Record(ctx, d.Seconds(), metric.WithAttributes(
		attribute.String("service", service),
		attribute.String("connector", connector),
		attribute.String("method", normMethod),
		attribute.String("outcome", outcome),
	))
}

// AddHTTPActiveRequest adjusts the active HTTP proxy request gauge.
func AddHTTPActiveRequest(ctx context.Context, service, connector string, delta int64) {
	GetInstruments().HTTPActiveRequests.Add(ctx, delta, metric.WithAttributes(
		attribute.String("service", service),
		attribute.String("connector", connector),
	))
}

// RecordHTTPUpstream records the latency of an upstream HTTP round trip.
func RecordHTTPUpstream(ctx context.Context, service, connector, method string, statusCode int, outcome string, d time.Duration) {
	GetInstruments().HTTPUpstreamDur.Record(ctx, d.Seconds(), metric.WithAttributes(
		attribute.String("service", service),
		attribute.String("connector", connector),
		attribute.String("method", NormalizeHTTPMethod(method)),
		attribute.Int("status_code", statusCode),
		attribute.String("outcome", outcome),
	))
}

// AddTCPActiveConnection adjusts the active TCP proxy connection gauge.
func AddTCPActiveConnection(ctx context.Context, service, connector string, delta int64) {
	GetInstruments().TCPActiveConnections.Add(ctx, delta, metric.WithAttributes(
		attribute.String("service", service),
		attribute.String("connector", connector),
	))
}

// RecordTCPConnect records backend handshake/authentication duration for a TCP connection.
func RecordTCPConnect(ctx context.Context, service, connector, outcome string, d time.Duration) {
	GetInstruments().TCPConnectDur.Record(ctx, d.Seconds(), metric.WithAttributes(
		attribute.String("service", service),
		attribute.String("connector", connector),
		attribute.String("outcome", outcome),
	))
}

// RecordTCPConnection records completion count and total lifetime of a TCP proxy connection.
func RecordTCPConnection(ctx context.Context, service, connector, outcome string, d time.Duration) {
	inst := GetInstruments()
	attrs := metric.WithAttributes(
		attribute.String("service", service),
		attribute.String("connector", connector),
		attribute.String("outcome", outcome),
	)
	inst.TCPConnections.Add(ctx, 1, attrs)
	inst.TCPConnectionDur.Record(ctx, d.Seconds(), attrs)
}

// AddTCPBytes records bytes transferred in a direction ("client_to_target" or "target_to_client").
func AddTCPBytes(ctx context.Context, service, connector, direction string, n int64) {
	if n <= 0 {
		return
	}
	GetInstruments().TCPBytes.Add(ctx, n, metric.WithAttributes(
		attribute.String("service", service),
		attribute.String("connector", connector),
		attribute.String("direction", direction),
	))
}

// AddSSHActiveConnection adjusts the active SSH/SSH-Agent proxy connection gauge.
func AddSSHActiveConnection(ctx context.Context, service, connector string, delta int64) {
	GetInstruments().SSHActiveConnections.Add(ctx, delta, metric.WithAttributes(
		attribute.String("service", service),
		attribute.String("connector", connector),
	))
}

// RecordSSHConnection records completion count and duration for an SSH/SSH-Agent connection.
func RecordSSHConnection(ctx context.Context, service, connector, outcome string, d time.Duration) {
	inst := GetInstruments()
	attrs := metric.WithAttributes(
		attribute.String("service", service),
		attribute.String("connector", connector),
		attribute.String("outcome", outcome),
	)
	inst.SSHConnections.Add(ctx, 1, attrs)
	inst.SSHConnectionDur.Record(ctx, d.Seconds(), attrs)
}

// RecordCredentialResolve records count and latency for a credential provider resolution call.
func RecordCredentialResolve(ctx context.Context, provider, outcome string, d time.Duration) {
	inst := GetInstruments()
	attrs := metric.WithAttributes(
		attribute.String("provider", provider),
		attribute.String("outcome", outcome),
	)
	inst.CredentialResolves.Add(ctx, 1, attrs)
	inst.CredentialResolveDur.Record(ctx, d.Seconds(), attrs)
}

// RecordConfigReload records a configuration load/reload event.
func RecordConfigReload(ctx context.Context, outcome string) {
	GetInstruments().ConfigReloads.Add(ctx, 1, metric.WithAttributes(
		attribute.String("outcome", outcome),
	))
}
