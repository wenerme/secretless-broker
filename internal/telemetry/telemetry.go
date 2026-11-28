package telemetry

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"unicode"

	"go.opentelemetry.io/contrib/exporters/autoexport"
	"go.opentelemetry.io/contrib/propagators/autoprop"
	"go.opentelemetry.io/otel"
	nooplog "go.opentelemetry.io/otel/log/noop"
	"go.opentelemetry.io/otel/log/global"
	"go.opentelemetry.io/otel/metric"
	noopmetric "go.opentelemetry.io/otel/metric/noop"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.43.0"
	"go.opentelemetry.io/otel/trace"
	nooptrace "go.opentelemetry.io/otel/trace/noop"

	"github.com/cyberark/secretless-broker/pkg/secretless"
)

const (
	// DefaultServiceName is the default OpenTelemetry service.name attribute
	// when neither OTEL_SERVICE_NAME nor OTEL_RESOURCE_ATTRIBUTES sets it.
	DefaultServiceName = "secretless-broker"

	// InstrumentationScope is the default instrumentation scope name.
	InstrumentationScope = "github.com/cyberark/secretless-broker"
)

// Provider owns the OpenTelemetry SDK providers configured for the broker
// process and flushes them on shutdown.
type Provider struct {
	tracerProvider *sdktrace.TracerProvider
	meterProvider  *sdkmetric.MeterProvider
	loggerProvider *sdklog.LoggerProvider

	tracesEnabled  bool
	metricsEnabled bool
	logsEnabled    bool

	shutdownOnce sync.Once
	shutdownErr  error
}

// Enabled reports whether at least one OpenTelemetry signal exporter is active.
func (p *Provider) Enabled() bool {
	if p == nil {
		return false
	}
	return p.tracesEnabled || p.metricsEnabled || p.logsEnabled
}

// TracesEnabled reports whether trace exporting is active.
func (p *Provider) TracesEnabled() bool {
	return p != nil && p.tracesEnabled
}

// MetricsEnabled reports whether metric exporting is active.
func (p *Provider) MetricsEnabled() bool {
	return p != nil && p.metricsEnabled
}

// LogsEnabled reports whether log exporting is active.
func (p *Provider) LogsEnabled() bool {
	return p != nil && p.logsEnabled
}

// Summary returns a safe, human-readable summary of active signals without
// disclosing any environment variable values or headers.
func (p *Provider) Summary() string {
	if !p.Enabled() {
		return "disabled"
	}
	signals := make([]string, 0, 3)
	if p.tracesEnabled {
		signals = append(signals, "traces")
	}
	if p.metricsEnabled {
		signals = append(signals, "metrics")
	}
	if p.logsEnabled {
		signals = append(signals, "logs")
	}
	return "enabled: " + strings.Join(signals, ", ")
}

// Shutdown flushes and shuts down all active SDK providers. It is safe to call
// multiple times or on a nil receiver.
func (p *Provider) Shutdown(ctx context.Context) error {
	if p == nil {
		return nil
	}
	p.shutdownOnce.Do(func() {
		var errs []error
		if p.tracerProvider != nil {
			if err := p.tracerProvider.Shutdown(ctx); err != nil {
				errs = append(errs, fmt.Errorf("trace provider shutdown: %w", err))
			}
		}
		if p.meterProvider != nil {
			if err := p.meterProvider.Shutdown(ctx); err != nil {
				errs = append(errs, fmt.Errorf("meter provider shutdown: %w", err))
			}
		}
		if p.loggerProvider != nil {
			if err := p.loggerProvider.Shutdown(ctx); err != nil {
				errs = append(errs, fmt.Errorf("logger provider shutdown: %w", err))
			}
		}
		p.shutdownErr = errors.Join(errs...)
	})
	return p.shutdownErr
}

// Init configures global OpenTelemetry trace, metric, log, and propagator
// providers from standard OTEL_* environment variables.
//
// Supported standard environment variables include:
//   - OTEL_SDK_DISABLED
//   - OTEL_SERVICE_NAME, OTEL_RESOURCE_ATTRIBUTES
//   - OTEL_PROPAGATORS
//   - OTEL_TRACES_EXPORTER, OTEL_TRACES_SAMPLER, OTEL_TRACES_SAMPLER_ARG, OTEL_BSP_*
//   - OTEL_METRICS_EXPORTER, OTEL_METRIC_EXPORT_INTERVAL, OTEL_METRIC_EXPORT_TIMEOUT
//   - OTEL_LOGS_EXPORTER, OTEL_BLRP_*
//   - OTEL_EXPORTER_OTLP_*, OTEL_EXPORTER_PROMETHEUS_*
//
// When no exporter or OTLP endpoint environment variables are set, all signals
// default to no-op so unconfigured deployments emit no background export errors.
func Init(ctx context.Context) (*Provider, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	// Always configure propagators from OTEL_PROPAGATORS (defaulting to
	// tracecontext,baggage when unset).
	otel.SetTextMapPropagator(autoprop.NewTextMapPropagator())

	if isSDKDisabled() {
		setNoopProviders()
		return &Provider{}, nil
	}

	enableTraces := shouldConfigureSignal("OTEL_TRACES_EXPORTER", "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
	enableMetrics := shouldConfigureSignal("OTEL_METRICS_EXPORTER", "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT")
	enableLogs := shouldConfigureSignal("OTEL_LOGS_EXPORTER", "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT")

	if !enableTraces && !enableMetrics && !enableLogs {
		setNoopProviders()
		return &Provider{}, nil
	}

	// Pre-validate OTLP header environment variables before constructing SDK
	// exporters so malformed auth headers fail cleanly without being printed by
	// SDK diagnostic error logs.
	if err := validateOTLPHeaderEnvs(); err != nil {
		setNoopProviders()
		return nil, err
	}

	res, err := buildResource(ctx)
	if err != nil {
		setNoopProviders()
		return nil, fmt.Errorf("build OpenTelemetry resource: %w", err)
	}

	p := &Provider{}
	cleanupOnErr := func() {
		_ = p.Shutdown(context.Background())
		setNoopProviders()
	}

	if enableTraces {
		exp, err := autoexport.NewSpanExporter(ctx)
		if err != nil {
			cleanupOnErr()
			return nil, fmt.Errorf("create OpenTelemetry span exporter: %w", err)
		}
		if !autoexport.IsNoneSpanExporter(exp) {
			p.tracerProvider = sdktrace.NewTracerProvider(
				sdktrace.WithBatcher(exp),
				sdktrace.WithResource(res),
			)
			p.tracesEnabled = true
		}
	}

	if enableMetrics {
		reader, err := autoexport.NewMetricReader(ctx)
		if err != nil {
			cleanupOnErr()
			return nil, fmt.Errorf("create OpenTelemetry metric reader: %w", err)
		}
		if !autoexport.IsNoneMetricReader(reader) {
			p.meterProvider = sdkmetric.NewMeterProvider(
				sdkmetric.WithReader(reader),
				sdkmetric.WithResource(res),
			)
			p.metricsEnabled = true
		}
	}

	if enableLogs {
		exp, err := autoexport.NewLogExporter(ctx)
		if err != nil {
			cleanupOnErr()
			return nil, fmt.Errorf("create OpenTelemetry log exporter: %w", err)
		}
		if !autoexport.IsNoneLogExporter(exp) {
			p.loggerProvider = sdklog.NewLoggerProvider(
				sdklog.WithProcessor(sdklog.NewBatchProcessor(exp)),
				sdklog.WithResource(res),
			)
			p.logsEnabled = true
		}
	}

	if p.tracerProvider != nil {
		otel.SetTracerProvider(p.tracerProvider)
	} else {
		otel.SetTracerProvider(nooptrace.NewTracerProvider())
	}

	if p.meterProvider != nil {
		otel.SetMeterProvider(p.meterProvider)
	} else {
		otel.SetMeterProvider(noopmetric.NewMeterProvider())
	}

	if p.loggerProvider != nil {
		global.SetLoggerProvider(p.loggerProvider)
	} else {
		global.SetLoggerProvider(nooplog.NewLoggerProvider())
	}

	return p, nil
}

func setNoopProviders() {
	otel.SetTracerProvider(nooptrace.NewTracerProvider())
	otel.SetMeterProvider(noopmetric.NewMeterProvider())
	global.SetLoggerProvider(nooplog.NewLoggerProvider())
}

func isSDKDisabled() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv("OTEL_SDK_DISABLED")), "true")
}

func shouldConfigureSignal(exporterEnv, signalEndpointEnv string) bool {
	if strings.TrimSpace(os.Getenv(exporterEnv)) != "" {
		return true
	}
	if strings.TrimSpace(os.Getenv(signalEndpointEnv)) != "" {
		return true
	}
	if strings.TrimSpace(os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")) != "" {
		return true
	}
	return false
}

var otlpHeaderEnvKeys = []string{
	"OTEL_EXPORTER_OTLP_HEADERS",
	"OTEL_EXPORTER_OTLP_TRACES_HEADERS",
	"OTEL_EXPORTER_OTLP_METRICS_HEADERS",
	"OTEL_EXPORTER_OTLP_LOGS_HEADERS",
}

func validateOTLPHeaderEnvs() error {
	for _, envKey := range otlpHeaderEnvKeys {
		raw := os.Getenv(envKey)
		if raw == "" {
			continue
		}
		if err := validateHeaderList(envKey, raw); err != nil {
			return err
		}
	}
	return nil
}

// validateHeaderList validates an OTLP header list matching the OpenTelemetry
// envconfig parser rules without ever including raw header keys or values in
// returned error messages.
func validateHeaderList(envKey, raw string) error {
	for _, pair := range strings.Split(raw, ",") {
		k, v, found := strings.Cut(pair, "=")
		if !found {
			return fmt.Errorf("invalid %s: header entry missing '=' separator", envKey)
		}
		trimmedKey := strings.TrimSpace(k)
		if !isValidHeaderKey(trimmedKey) {
			return fmt.Errorf("invalid %s: invalid header key syntax", envKey)
		}
		if _, err := url.PathUnescape(v); err != nil {
			return fmt.Errorf("invalid %s: invalid percent-encoding in header value", envKey)
		}
	}
	return nil
}

func isValidHeaderKey(key string) bool {
	if key == "" {
		return false
	}
	for _, c := range key {
		if !isHeaderTokenChar(c) {
			return false
		}
	}
	return true
}

func isHeaderTokenChar(c rune) bool {
	return c <= unicode.MaxASCII && (unicode.IsLetter(c) ||
		unicode.IsDigit(c) ||
		c == '!' || c == '#' || c == '$' || c == '%' || c == '&' || c == '\'' || c == '*' ||
		c == '+' || c == '-' || c == '.' || c == '^' || c == '_' || c == '`' || c == '|' || c == '~')
}

func buildResource(ctx context.Context) (*resource.Resource, error) {
	base := resource.NewWithAttributes(
		semconv.SchemaURL,
		semconv.ServiceName(DefaultServiceName),
		semconv.ServiceVersion(secretless.FullVersionName),
	)

	// Intentionally omit process command args and owner to avoid leaking
	// flags or host user metadata into telemetry.
	detected, err := resource.New(
		ctx,
		resource.WithFromEnv(),
		resource.WithTelemetrySDK(),
		resource.WithHost(),
		resource.WithOS(),
		resource.WithProcessPID(),
		resource.WithProcessExecutableName(),
		resource.WithProcessRuntimeName(),
		resource.WithProcessRuntimeVersion(),
		resource.WithProcessRuntimeDescription(),
	)
	if err != nil && !errors.Is(err, resource.ErrPartialResource) && !errors.Is(err, resource.ErrSchemaURLConflict) {
		return nil, err
	}

	merged, mergeErr := resource.Merge(base, detected)
	if mergeErr != nil && !errors.Is(mergeErr, resource.ErrSchemaURLConflict) {
		return nil, mergeErr
	}
	return merged, nil
}

// Tracer returns an OpenTelemetry Tracer scoped with the broker version.
func Tracer(name string) trace.Tracer {
	if name == "" {
		name = InstrumentationScope
	}
	return otel.Tracer(name, trace.WithInstrumentationVersion(secretless.FullVersionName))
}

// Meter returns an OpenTelemetry Meter scoped with the broker version.
func Meter(name string) metric.Meter {
	if name == "" {
		name = InstrumentationScope
	}
	return otel.Meter(name, metric.WithInstrumentationVersion(secretless.FullVersionName))
}

// NormalizeHTTPMethod restricts HTTP method labels to standard RFC methods
// to avoid unbounded metric cardinality from arbitrary client input.
func NormalizeHTTPMethod(method string) string {
	switch method {
	case "GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH":
		return method
	default:
		return "_OTHER"
	}
}
