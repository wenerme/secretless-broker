package plugin

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	otellog "go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/log/global"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"

	plugin_v1 "github.com/cyberark/secretless-broker/internal/plugin/v1"
	config_v2 "github.com/cyberark/secretless-broker/pkg/secretless/config/v2"
)

type testContextProvider struct {
	name      string
	seenCtx   context.Context
	secretVal string
}

func (p *testContextProvider) GetName() string { return p.name }

func (p *testContextProvider) GetValues(ids ...string) (map[string]plugin_v1.ProviderResponse, error) {
	return p.GetValuesContext(context.Background(), ids...)
}

func (p *testContextProvider) GetValuesContext(ctx context.Context, ids ...string) (map[string]plugin_v1.ProviderResponse, error) {
	p.seenCtx = ctx
	resp := make(map[string]plugin_v1.ProviderResponse, len(ids))
	for _, id := range ids {
		resp[id] = plugin_v1.ProviderResponse{Value: []byte(p.secretVal)}
	}
	return resp, nil
}

func TestResolver_ResolveContextEmitsTelemetryWithoutLeakingSecrets(t *testing.T) {
	prevTP := otel.GetTracerProvider()
	prevMP := otel.GetMeterProvider()

	sr := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(sr))
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	otel.SetTracerProvider(tp)
	otel.SetMeterProvider(mp)
	t.Cleanup(func() {
		_ = tp.Shutdown(context.Background())
		_ = mp.Shutdown(context.Background())
		otel.SetTracerProvider(prevTP)
		otel.SetMeterProvider(prevMP)
	})

	provider := &testContextProvider{name: "literal", secretVal: "RESOLVED-SECRET-VAL"}
	resolver := NewResolver(
		map[string]func(plugin_v1.ProviderOptions) (plugin_v1.Provider, error){
			"literal": func(plugin_v1.ProviderOptions) (plugin_v1.Provider, error) {
				return provider, nil
			},
		},
		nil,
		nil,
	)

	parentCtx, parentSpan := otel.Tracer("test").Start(context.Background(), "parent")
	creds := []*config_v2.Credential{
		{Name: "token", From: "literal", Get: "LITERAL-SECRET-IN-GET"},
	}

	ctxResolver, ok := resolver.(plugin_v1.ContextResolver)
	require.True(t, ok)

	values, err := ctxResolver.ResolveContext(parentCtx, creds)
	parentSpan.End()
	require.NoError(t, err)
	assert.Equal(t, []byte("RESOLVED-SECRET-VAL"), values["token"])

	// ContextProvider should receive child span context linked to parent trace.
	require.NotNil(t, provider.seenCtx)
	assert.Equal(t,
		parentSpan.SpanContext().TraceID(),
		trace.SpanContextFromContext(provider.seenCtx).TraceID(),
	)

	// Verify provider span attributes contain safe metadata only.
	var foundProviderSpan bool
	for _, s := range sr.Ended() {
		if s.Name() == "secretless.provider.resolve" {
			foundProviderSpan = true
			attrs := map[string]string{}
			for _, kv := range s.Attributes() {
				attrs[string(kv.Key)] = kv.Value.Emit()
				assert.NotContains(t, kv.Value.Emit(), "LITERAL-SECRET-IN-GET")
				assert.NotContains(t, kv.Value.Emit(), "RESOLVED-SECRET-VAL")
			}
			assert.Equal(t, "literal", attrs["secretless.provider.id"])
			assert.Equal(t, "1", attrs["secretless.credential.count"])
		}
	}
	assert.True(t, foundProviderSpan)

	var rm metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(context.Background(), &rm))
	metricNames := map[string]bool{}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			metricNames[m.Name] = true
		}
	}
	assert.True(t, metricNames["secretless.credentials.resolve.total"])
	assert.True(t, metricNames["secretless.credentials.resolve.duration"])
}

type failingSecretProvider struct {
	name string
}

func (p *failingSecretProvider) GetName() string { return p.name }

func (p *failingSecretProvider) GetValues(ids ...string) (map[string]plugin_v1.ProviderResponse, error) {
	resp := make(map[string]plugin_v1.ProviderResponse, len(ids))
	for _, id := range ids {
		resp[id] = plugin_v1.ProviderResponse{
			Error: errors.New("missing secret " + id),
		}
	}
	return resp, nil
}

type memoryResolverLogExporter struct {
	mu      sync.Mutex
	records []sdklog.Record
}

func (e *memoryResolverLogExporter) Export(_ context.Context, records []sdklog.Record) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, r := range records {
		e.records = append(e.records, r.Clone())
	}
	return nil
}

func (e *memoryResolverLogExporter) Shutdown(context.Context) error   { return nil }
func (e *memoryResolverLogExporter) ForceFlush(context.Context) error { return nil }

func TestResolver_ErrorTelemetryDoesNotLeakRawGetIDOrProviderError(t *testing.T) {
	prevTP := otel.GetTracerProvider()
	prevLP := global.GetLoggerProvider()

	sr := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(sr))
	logExp := &memoryResolverLogExporter{}
	lp := sdklog.NewLoggerProvider(sdklog.WithProcessor(sdklog.NewSimpleProcessor(logExp)))
	otel.SetTracerProvider(tp)
	global.SetLoggerProvider(lp)
	t.Cleanup(func() {
		_ = tp.Shutdown(context.Background())
		_ = lp.Shutdown(context.Background())
		otel.SetTracerProvider(prevTP)
		global.SetLoggerProvider(prevLP)
	})

	resolver := NewResolver(
		map[string]func(plugin_v1.ProviderOptions) (plugin_v1.Provider, error){
			"env": func(plugin_v1.ProviderOptions) (plugin_v1.Provider, error) {
				return &failingSecretProvider{name: "env"}, nil
			},
		},
		nil,
		nil,
	)

	ctxResolver := resolver.(plugin_v1.ContextResolver)
	_, err := ctxResolver.ResolveContext(context.Background(), []*config_v2.Credential{
		{Name: "password", From: "env", Get: "RAW-SECRET-GET-IDENTIFIER"},
	})
	require.Error(t, err)

	for _, s := range sr.Ended() {
		assert.NotContains(t, s.Status().Description, "RAW-SECRET-GET-IDENTIFIER")
		for _, kv := range s.Attributes() {
			assert.NotContains(t, kv.Value.Emit(), "RAW-SECRET-GET-IDENTIFIER")
		}
	}

	logExp.mu.Lock()
	defer logExp.mu.Unlock()
	require.Len(t, logExp.records, 1)
	assert.Equal(t, "credential resolution failed", logExp.records[0].Body().AsString())
	logExp.records[0].WalkAttributes(func(kv otellog.KeyValue) bool {
		assert.NotContains(t, kv.Value.AsString(), "RAW-SECRET-GET-IDENTIFIER")
		return true
	})
}
