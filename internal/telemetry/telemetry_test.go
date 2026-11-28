package telemetry

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	otellog "go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.43.0"
)

var otelEnvVars = []string{
	"OTEL_SDK_DISABLED",
	"OTEL_SERVICE_NAME",
	"OTEL_RESOURCE_ATTRIBUTES",
	"OTEL_PROPAGATORS",
	"OTEL_TRACES_EXPORTER",
	"OTEL_TRACES_SAMPLER",
	"OTEL_TRACES_SAMPLER_ARG",
	"OTEL_METRICS_EXPORTER",
	"OTEL_METRIC_EXPORT_INTERVAL",
	"OTEL_LOGS_EXPORTER",
	"OTEL_EXPORTER_OTLP_ENDPOINT",
	"OTEL_EXPORTER_OTLP_PROTOCOL",
	"OTEL_EXPORTER_OTLP_HEADERS",
	"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
	"OTEL_EXPORTER_OTLP_TRACES_PROTOCOL",
	"OTEL_EXPORTER_OTLP_TRACES_HEADERS",
	"OTEL_EXPORTER_OTLP_METRICS_ENDPOINT",
	"OTEL_EXPORTER_OTLP_METRICS_PROTOCOL",
	"OTEL_EXPORTER_OTLP_METRICS_HEADERS",
	"OTEL_EXPORTER_OTLP_LOGS_ENDPOINT",
	"OTEL_EXPORTER_OTLP_LOGS_PROTOCOL",
	"OTEL_EXPORTER_OTLP_LOGS_HEADERS",
}

func clearOTELEnv(t *testing.T) {
	t.Helper()
	for _, key := range otelEnvVars {
		prev, existed := os.LookupEnv(key)
		require.NoError(t, os.Unsetenv(key))
		key, prev, existed := key, prev, existed
		t.Cleanup(func() {
			if existed {
				_ = os.Setenv(key, prev)
			} else {
				_ = os.Unsetenv(key)
			}
		})
	}
	t.Cleanup(setNoopProviders)
}

func TestInit_DisabledByDefaultWhenNoEnvSet(t *testing.T) {
	clearOTELEnv(t)

	p, err := Init(context.Background())
	require.NoError(t, err)
	require.NotNil(t, p)
	defer func() { require.NoError(t, p.Shutdown(context.Background())) }()

	assert.False(t, p.Enabled())
	assert.False(t, p.TracesEnabled())
	assert.False(t, p.MetricsEnabled())
	assert.False(t, p.LogsEnabled())
	assert.Equal(t, "disabled", p.Summary())
}

func TestInit_OTELSDKDisabledOverridesEverything(t *testing.T) {
	clearOTELEnv(t)
	t.Setenv("OTEL_SDK_DISABLED", "true")
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:4318")
	t.Setenv("OTEL_TRACES_EXPORTER", "console")
	t.Setenv("OTEL_METRICS_EXPORTER", "console")
	t.Setenv("OTEL_LOGS_EXPORTER", "console")

	p, err := Init(context.Background())
	require.NoError(t, err)
	defer func() { require.NoError(t, p.Shutdown(context.Background())) }()

	assert.False(t, p.Enabled())
	assert.Equal(t, "disabled", p.Summary())
}

func TestInit_NoneExportersDisableSignalsEvenWithEndpoint(t *testing.T) {
	clearOTELEnv(t)
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:4318")
	t.Setenv("OTEL_TRACES_EXPORTER", "none")
	t.Setenv("OTEL_METRICS_EXPORTER", "none")
	t.Setenv("OTEL_LOGS_EXPORTER", "none")

	p, err := Init(context.Background())
	require.NoError(t, err)
	defer func() { require.NoError(t, p.Shutdown(context.Background())) }()

	assert.False(t, p.Enabled())
}

func TestInit_PerSignalEndpointEnablesOnlyThatSignal(t *testing.T) {
	clearOTELEnv(t)
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "http://127.0.0.1:4318/v1/traces")

	p, err := Init(context.Background())
	require.NoError(t, err)
	defer func() { require.NoError(t, p.Shutdown(context.Background())) }()

	assert.True(t, p.Enabled())
	assert.True(t, p.TracesEnabled())
	assert.False(t, p.MetricsEnabled())
	assert.False(t, p.LogsEnabled())
	assert.Equal(t, "enabled: traces", p.Summary())
}

func TestInit_InvalidExporterReturnsError(t *testing.T) {
	clearOTELEnv(t)
	t.Setenv("OTEL_TRACES_EXPORTER", "nonexistent-exporter")

	p, err := Init(context.Background())
	require.Error(t, err)
	assert.Nil(t, p)
}

func TestInit_OTLPHTTPExportsTracesMetricsAndLogs(t *testing.T) {
	clearOTELEnv(t)

	var (
		mu       sync.Mutex
		paths    = map[string]int{}
		headers  = map[string]string{}
		payloads = map[string][]byte{}
	)

	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		paths[r.URL.Path]++
		if auth := r.Header.Get("X-Otel-Test"); auth != "" {
			headers[r.URL.Path] = auth
		}
		payloads[r.URL.Path] = append(payloads[r.URL.Path], body...)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer collector.Close()

	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", collector.URL)
	t.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "http/protobuf")
	t.Setenv("OTEL_EXPORTER_OTLP_HEADERS", "X-Otel-Test=ok-token")
	t.Setenv("OTEL_SERVICE_NAME", "custom-secretless")
	t.Setenv("OTEL_RESOURCE_ATTRIBUTES", "deployment.environment=test")

	p, err := Init(context.Background())
	require.NoError(t, err)
	assert.True(t, p.TracesEnabled())
	assert.True(t, p.MetricsEnabled())
	assert.True(t, p.LogsEnabled())
	assert.Equal(t, "enabled: traces, metrics, logs", p.Summary())

	// Emit one span, one metric, and one log record.
	ctx, span := Tracer("test-scope").Start(context.Background(), "test-op")
	RecordHTTPRequest(ctx, "feishu", "generic_http", "GET", 200, "ok", 10*time.Millisecond)
	span.End()

	EmitEvent(ctx, otellog.SeverityInfo, "hello-otel-log",
		attribute.String("secretless.service.name", "feishu"),
	)

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, p.Shutdown(shutdownCtx))

	mu.Lock()
	defer mu.Unlock()
	assert.GreaterOrEqual(t, paths["/v1/traces"], 1)
	assert.GreaterOrEqual(t, paths["/v1/metrics"], 1)
	assert.GreaterOrEqual(t, paths["/v1/logs"], 1)
	assert.Equal(t, "ok-token", headers["/v1/traces"])
	assert.Equal(t, "ok-token", headers["/v1/metrics"])
	assert.Equal(t, "ok-token", headers["/v1/logs"])
	assert.True(t, strings.Contains(string(payloads["/v1/traces"]), "custom-secretless"))
	assert.True(t, strings.Contains(string(payloads["/v1/logs"]), "hello-otel-log"))
}

func TestInit_ResourceServiceNameDefaultAndOverride(t *testing.T) {
	clearOTELEnv(t)

	res, err := buildResource(context.Background())
	require.NoError(t, err)
	assert.Equal(t, DefaultServiceName, resourceAttr(res, semconv.ServiceNameKey))

	t.Setenv("OTEL_SERVICE_NAME", "override-broker")
	t.Setenv("OTEL_RESOURCE_ATTRIBUTES", "deployment.environment=staging")
	res, err = buildResource(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "override-broker", resourceAttr(res, semconv.ServiceNameKey))
	assert.Equal(t, "staging", resourceAttr(res, attribute.Key("deployment.environment")))
}

func TestInit_PropagatorsAndSamplerEnv(t *testing.T) {
	clearOTELEnv(t)
	t.Setenv("OTEL_PROPAGATORS", "none")
	t.Setenv("OTEL_TRACES_EXPORTER", "console")
	t.Setenv("OTEL_TRACES_SAMPLER", "always_off")

	p, err := Init(context.Background())
	require.NoError(t, err)
	defer func() { require.NoError(t, p.Shutdown(context.Background())) }()

	// OTEL_TRACES_SAMPLER=always_off should produce non-sampled spans.
	_, span := Tracer("sampler-test").Start(context.Background(), "dropped-span")
	assert.False(t, span.SpanContext().IsSampled())
	span.End()

	// OTEL_PROPAGATORS=none should not inject traceparent.
	carrier := propagation.HeaderCarrier(http.Header{})
	otel.GetTextMapPropagator().Inject(context.Background(), carrier)
	assert.Empty(t, carrier.Get("traceparent"))
}

func TestInit_MalformedOTLPHeadersRejectedWithoutLeakingSecret(t *testing.T) {
	cases := map[string]struct {
		envKey string
		value  string
		secret string
	}{
		"missing equals": {
			envKey: "OTEL_EXPORTER_OTLP_HEADERS",
			value:  "Bearer SUPER-SECRET-OTLP-TOKEN",
			secret: "SUPER-SECRET-OTLP-TOKEN",
		},
		"invalid percent encoding": {
			envKey: "OTEL_EXPORTER_OTLP_TRACES_HEADERS",
			value:  "Authorization=Bearer%ZZSECRET-VAL",
			secret: "SECRET-VAL",
		},
		"invalid header key": {
			envKey: "OTEL_EXPORTER_OTLP_METRICS_HEADERS",
			value:  "Bad Key=TOP-SECRET-HDR",
			secret: "TOP-SECRET-HDR",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			clearOTELEnv(t)
			t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:4318")
			t.Setenv(tc.envKey, tc.value)

			var sdkErrors []string
			prevHandler := otel.GetErrorHandler()
			otel.SetErrorHandler(otel.ErrorHandlerFunc(func(err error) {
				sdkErrors = append(sdkErrors, err.Error())
			}))
			t.Cleanup(func() { otel.SetErrorHandler(prevHandler) })

			p, err := Init(context.Background())
			require.Error(t, err)
			assert.Nil(t, p)
			assert.Contains(t, err.Error(), tc.envKey)
			assert.NotContains(t, err.Error(), tc.secret)
			assert.Empty(t, sdkErrors, "SDK diagnostic error handler must not see malformed auth headers")
		})
	}
}

func TestNormalizeHTTPMethod(t *testing.T) {
	assert.Equal(t, "GET", NormalizeHTTPMethod("GET"))
	assert.Equal(t, "POST", NormalizeHTTPMethod("POST"))
	assert.Equal(t, "CONNECT", NormalizeHTTPMethod("CONNECT"))
	assert.Equal(t, "_OTHER", NormalizeHTTPMethod("CUSTOM_ARBITRARY_VERB"))
	assert.Equal(t, "_OTHER", NormalizeHTTPMethod(""))
}

func resourceAttr(res *resource.Resource, key attribute.Key) string {
	for _, kv := range res.Attributes() {
		if kv.Key == key {
			return kv.Value.AsString()
		}
	}
	return ""
}
