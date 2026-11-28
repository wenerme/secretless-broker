package entrypoint

import (
	"context"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/log/global"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	secretlessLog "github.com/cyberark/secretless-broker/internal/log"
	v2 "github.com/cyberark/secretless-broker/pkg/secretless/config/v2"
	"github.com/cyberark/secretless-broker/pkg/secretless/plugin/sharedobj"
)

type noopLogExporter struct {
	count int
}

func (e *noopLogExporter) Export(_ context.Context, records []sdklog.Record) error {
	e.count += len(records)
	return nil
}

func (e *noopLogExporter) Shutdown(context.Context) error   { return nil }
func (e *noopLogExporter) ForceFlush(context.Context) error { return nil }

func TestReloadConfig_ErrorRecordsTelemetryAndReturnsError(t *testing.T) {
	prevTP := otel.GetTracerProvider()
	prevMP := otel.GetMeterProvider()
	prevLP := global.GetLoggerProvider()

	sr := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(sr))
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	logExp := &noopLogExporter{}
	lp := sdklog.NewLoggerProvider(sdklog.WithProcessor(sdklog.NewSimpleProcessor(logExp)))

	otel.SetTracerProvider(tp)
	otel.SetMeterProvider(mp)
	global.SetLoggerProvider(lp)
	t.Cleanup(func() {
		_ = tp.Shutdown(context.Background())
		_ = mp.Shutdown(context.Background())
		_ = lp.Shutdown(context.Background())
		otel.SetTracerProvider(prevTP)
		otel.SetMeterProvider(prevMP)
		global.SetLoggerProvider(prevLP)
	})

	logger := secretlessLog.New(false)
	availPlugins, err := sharedobj.GetInternalPluginsFunc()
	require.NoError(t, err)
	configEnv := v2.NewConfigEnv(logger, availPlugins)

	badCfg := v2.Config{
		Services: []*v2.Service{
			{
				Name:      "bad-svc",
				Connector: "nonexistent_connector",
				ListenOn:  v2.NetworkAddress("tcp://127.0.0.1:0"),
			},
		},
	}

	svc, err := reloadConfig(badCfg, configEnv, availPlugins, logger)
	require.Error(t, err)
	assert.Nil(t, svc)

	spans := sr.Ended()
	require.Len(t, spans, 1)
	assert.Equal(t, "secretless.config.reload", spans[0].Name())
	assert.Equal(t, codes.Error, spans[0].Status().Code)

	var rm metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(context.Background(), &rm))
	var foundErrReload bool
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name == "secretless.config.reloads" {
				sum, ok := m.Data.(metricdata.Sum[int64])
				require.True(t, ok)
				for _, dp := range sum.DataPoints {
					if val, ok := dp.Attributes.Value("outcome"); ok && val.AsString() == "error" && dp.Value == 1 {
						foundErrReload = true
					}
				}
			}
		}
	}
	assert.True(t, foundErrReload)
	assert.Equal(t, 1, logExp.count)
}

func TestReloadConfig_OccupiedPortReturnsErrorAndRecordsTelemetry(t *testing.T) {
	prevTP := otel.GetTracerProvider()
	prevMP := otel.GetMeterProvider()
	prevLP := global.GetLoggerProvider()

	sr := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(sr))
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	logExp := &noopLogExporter{}
	lp := sdklog.NewLoggerProvider(sdklog.WithProcessor(sdklog.NewSimpleProcessor(logExp)))

	otel.SetTracerProvider(tp)
	otel.SetMeterProvider(mp)
	global.SetLoggerProvider(lp)
	t.Cleanup(func() {
		_ = tp.Shutdown(context.Background())
		_ = mp.Shutdown(context.Background())
		_ = lp.Shutdown(context.Background())
		otel.SetTracerProvider(prevTP)
		otel.SetMeterProvider(prevMP)
		global.SetLoggerProvider(prevLP)
	})

	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer occupied.Close()

	logger := secretlessLog.New(false)
	availPlugins, err := sharedobj.GetInternalPluginsFunc()
	require.NoError(t, err)
	configEnv := v2.NewConfigEnv(logger, availPlugins)

	cfg := v2.Config{
		Services: []*v2.Service{
			{
				Name:            "occupied-http",
				Connector:       "generic_http",
				ListenOn:        v2.NetworkAddress("tcp://" + occupied.Addr().String()),
				ConnectorConfig: []byte("authenticateURLsMatching:\n  - '^https://example[.]com'\n"),
				Credentials: []*v2.Credential{
					{Name: "token", From: "literal", Get: "dummy"},
				},
			},
		},
	}

	svc, err := reloadConfig(cfg, configEnv, availPlugins, logger)
	require.Error(t, err)
	assert.Nil(t, svc)

	spans := sr.Ended()
	require.Len(t, spans, 1)
	assert.Equal(t, "secretless.config.reload", spans[0].Name())
	assert.Equal(t, codes.Error, spans[0].Status().Code)

	var rm metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(context.Background(), &rm))
	var foundErrReload bool
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name == "secretless.config.reloads" {
				sum, ok := m.Data.(metricdata.Sum[int64])
				require.True(t, ok)
				for _, dp := range sum.DataPoints {
					if val, ok := dp.Attributes.Value("outcome"); ok && val.AsString() == "error" && dp.Value == 1 {
						foundErrReload = true
					}
				}
			}
		}
	}
	assert.True(t, foundErrReload)
	assert.Equal(t, 1, logExp.count)
}
