package http

import (
	"context"
	"net"
	gohttp "net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/log/global"
	"go.opentelemetry.io/otel/propagation"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"

	"github.com/cyberark/secretless-broker/internal/log"
	"github.com/cyberark/secretless-broker/internal/plugin/connectors/http/generic"
	"github.com/cyberark/secretless-broker/pkg/secretless/plugin/connector"
)

type memoryLogExporter struct {
	mu      sync.Mutex
	records []sdklog.Record
}

func (e *memoryLogExporter) Export(_ context.Context, records []sdklog.Record) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, r := range records {
		e.records = append(e.records, r.Clone())
	}
	return nil
}

func (e *memoryLogExporter) Shutdown(context.Context) error   { return nil }
func (e *memoryLogExporter) ForceFlush(context.Context) error { return nil }

func setupHTTPTestTelemetry(t *testing.T) (*tracetest.SpanRecorder, *sdkmetric.ManualReader, *memoryLogExporter) {
	t.Helper()
	prevTP := otel.GetTracerProvider()
	prevMP := otel.GetMeterProvider()
	prevLP := global.GetLoggerProvider()
	prevProp := otel.GetTextMapPropagator()

	sr := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(sr))
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	logExp := &memoryLogExporter{}
	lp := sdklog.NewLoggerProvider(sdklog.WithProcessor(sdklog.NewSimpleProcessor(logExp)))

	otel.SetTracerProvider(tp)
	otel.SetMeterProvider(mp)
	global.SetLoggerProvider(lp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	t.Cleanup(func() {
		_ = tp.Shutdown(context.Background())
		_ = mp.Shutdown(context.Background())
		_ = lp.Shutdown(context.Background())
		otel.SetTracerProvider(prevTP)
		otel.SetMeterProvider(prevMP)
		global.SetLoggerProvider(prevLP)
		otel.SetTextMapPropagator(prevProp)
	})

	return sr, reader, logExp
}

func TestHTTPProxyTelemetry_TracesMetricsPropagationAndNoSecretLeak(t *testing.T) {
	sr, reader, logExp := setupHTTPTestTelemetry(t)

	var upstreamTraceparent string
	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		upstreamTraceparent = r.Header.Get("Traceparent")
		w.WriteHeader(gohttp.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	upstreamURL, err := url.Parse(upstream.URL)
	require.NoError(t, err)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	var receivedCredCtx context.Context
	subservices := []Subservice{
		{
			ServiceName: "feishu-api",
			ConnectorID: "generic_http",
			Connector:   &fakeConnector{},
			RetrieveCredentialsContext: func(ctx context.Context) (map[string][]byte, error) {
				receivedCredCtx = ctx
				return map[string][]byte{"token": []byte("SUPER-SECRET-TOKEN-VALUE")}, nil
			},
			AuthenticateURLsMatching: []*regexp.Regexp{
				regexp.MustCompile("^" + regexp.QuoteMeta(upstream.URL)),
			},
			UpstreamURL: upstreamURL,
		},
	}

	svc, err := NewProxyService(subservices, listener, log.New(false))
	require.NoError(t, err)
	require.NoError(t, svc.Start())
	defer svc.Stop()

	proxyURL, _ := url.Parse("http://" + listener.Addr().String())
	client := &gohttp.Client{
		Transport: &gohttp.Transport{
			Proxy: gohttp.ProxyURL(proxyURL),
		},
	}

	// Send incoming traceparent, a path-embedded webhook token, and a sensitive
	// query param to verify propagation works and path/query secrets are never
	// captured in telemetry.
	req, err := gohttp.NewRequest(gohttp.MethodGet, upstream.URL+"/open-apis/bot/v2/hook/PATH-WEBHOOK-SECRET?access_token=QUERY-SECRET-VALUE", nil)
	require.NoError(t, err)
	const incomingTraceID = "4bf92f3577b34da6a3ce929d0e0e4736"
	req.Header.Set("Traceparent", "00-"+incomingTraceID+"-00f067aa0ba902b7-01")

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, gohttp.StatusOK, resp.StatusCode)

	// Verify trace context reached credential retriever and upstream server.
	require.NotNil(t, receivedCredCtx)
	assert.Equal(t, incomingTraceID, trace.SpanContextFromContext(receivedCredCtx).TraceID().String())
	assert.True(t, strings.HasPrefix(upstreamTraceparent, "00-"+incomingTraceID+"-"),
		"upstream traceparent should preserve trace ID, got %q", upstreamTraceparent)

	// Verify expected spans and absence of any secret values (including path tokens).
	spans := sr.Ended()
	spanNames := map[string]bool{}
	var upstreamSpanID string
	for _, s := range spans {
		spanNames[s.Name()] = true
		if s.Name() == "secretless.http.upstream" {
			upstreamSpanID = s.SpanContext().SpanID().String()
		}
		assert.Equal(t, incomingTraceID, s.SpanContext().TraceID().String())
		for _, attr := range s.Attributes() {
			assert.NotEqual(t, "url.path", string(attr.Key), "raw URL path must not be recorded on spans")
			val := attr.Value.Emit()
			assert.NotContains(t, val, "SUPER-SECRET-TOKEN-VALUE")
			assert.NotContains(t, val, "secret-credential")
			assert.NotContains(t, val, "QUERY-SECRET-VALUE")
			assert.NotContains(t, val, "PATH-WEBHOOK-SECRET")
		}
	}
	assert.True(t, spanNames["secretless.http.proxy"])
	assert.True(t, spanNames["secretless.credentials.resolve"])
	assert.True(t, spanNames["secretless.connector.authenticate"])
	assert.True(t, spanNames["secretless.http.upstream"])
	require.NotEmpty(t, upstreamSpanID)
	assert.Equal(t, "00-"+incomingTraceID+"-"+upstreamSpanID+"-01", upstreamTraceparent,
		"upstream traceparent must use secretless.http.upstream SpanID as parent")
	assert.Empty(t, logExp.records)

	// Verify metrics recorded and active requests returned to 0.
	var rm metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(context.Background(), &rm))
	metricNames := map[string]metricdata.Metrics{}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			metricNames[m.Name] = m
		}
	}

	assert.Contains(t, metricNames, "secretless.http.requests")
	assert.Contains(t, metricNames, "secretless.http.request.duration")
	assert.Contains(t, metricNames, "secretless.http.active_requests")
	assert.Contains(t, metricNames, "secretless.http.upstream.duration")

	activeSum, ok := metricNames["secretless.http.active_requests"].Data.(metricdata.Sum[int64])
	require.True(t, ok)
	require.Len(t, activeSum.DataPoints, 1)
	assert.Equal(t, int64(0), activeSum.DataPoints[0].Value)
}

func TestHTTPProxyTelemetry_RejectedRequestRecordedWithoutPathLeak(t *testing.T) {
	sr, reader, logExp := setupHTTPTestTelemetry(t)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	subservices := []Subservice{
		{
			ServiceName: "feishu-api",
			ConnectorID: "generic_http",
			Connector:   &fakeConnector{},
			RetrieveCredentials: func() (map[string][]byte, error) {
				return map[string][]byte{"token": []byte("tok")}, nil
			},
			AuthenticateURLsMatching: []*regexp.Regexp{
				regexp.MustCompile(`^https://open\.feishu\.cn`),
			},
		},
	}

	svc, err := NewProxyService(subservices, listener, log.New(false))
	require.NoError(t, err)
	require.NoError(t, svc.Start())
	defer svc.Stop()

	proxyURL, _ := url.Parse("http://" + listener.Addr().String())
	client := &gohttp.Client{
		Transport: &gohttp.Transport{
			Proxy: gohttp.ProxyURL(proxyURL),
		},
	}

	resp, err := client.Get("http://unmatched.example/webhook/REJECTED-PATH-SECRET")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, gohttp.StatusForbidden, resp.StatusCode)

	var foundProxySpan bool
	for _, s := range sr.Ended() {
		if s.Name() == "secretless.http.proxy" {
			foundProxySpan = true
			attrs := map[string]string{}
			for _, kv := range s.Attributes() {
				attrs[string(kv.Key)] = kv.Value.Emit()
				assert.NotContains(t, kv.Value.Emit(), "REJECTED-PATH-SECRET")
			}
			assert.Equal(t, "403", attrs["http.response.status_code"])
			assert.Equal(t, "no_matching_service", attrs["secretless.rejection.reason"])
		}
	}
	assert.True(t, foundProxySpan)

	// Curated OTel rejection log should be emitted without path secrets.
	logExp.mu.Lock()
	require.Len(t, logExp.records, 1)
	assert.Equal(t, "http proxy request rejected", logExp.records[0].Body().AsString())
	assert.NotContains(t, logExp.records[0].Body().AsString(), "REJECTED-PATH-SECRET")
	logExp.mu.Unlock()

	var rm metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(context.Background(), &rm))
	var foundRejected bool
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name == "secretless.http.requests" {
				sum, ok := m.Data.(metricdata.Sum[int64])
				require.True(t, ok)
				for _, dp := range sum.DataPoints {
					if val, ok := dp.Attributes.Value("outcome"); ok && val.AsString() == "rejected" {
						foundRejected = true
					}
				}
			}
		}
	}
	assert.True(t, foundRejected)
}

func TestHTTPProxyTelemetry_ConnectorHeadersTakePrecedenceOverPropagation(t *testing.T) {
	_, _, _ = setupHTTPTestTelemetry(t)

	var gotTraceparent, gotAuth string
	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		gotTraceparent = r.Header.Get("Traceparent")
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(gohttp.StatusOK)
	}))
	defer upstream.Close()

	upstreamURL, err := url.Parse(upstream.URL)
	require.NoError(t, err)

	// Real generic_http connector overriding Traceparent and injecting Bearer auth.
	cfgYAML := []byte("forceSSL: false\nheaders:\n  Authorization: 'Bearer {{ .token }}'\n  Traceparent: 'connector-owned-value'\n")
	conn := generic.GetHTTPPlugin().NewConnector(connector.NewResources(cfgYAML, log.New(false)))

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	subservices := []Subservice{
		{
			ServiceName: "generic-override",
			ConnectorID: "generic_http",
			Connector:   conn,
			RetrieveCredentials: func() (map[string][]byte, error) {
				return map[string][]byte{"token": []byte("real-bearer-tok")}, nil
			},
			AuthenticateURLsMatching: []*regexp.Regexp{
				regexp.MustCompile("^" + regexp.QuoteMeta(upstream.URL)),
			},
			UpstreamURL: upstreamURL,
		},
	}

	svc, err := NewProxyService(subservices, listener, log.New(false))
	require.NoError(t, err)
	require.NoError(t, svc.Start())
	defer svc.Stop()

	proxyURL, _ := url.Parse("http://" + listener.Addr().String())
	client := &gohttp.Client{
		Transport: &gohttp.Transport{
			Proxy: gohttp.ProxyURL(proxyURL),
		},
	}

	resp, err := client.Get(upstream.URL + "/check")
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, gohttp.StatusOK, resp.StatusCode)

	assert.Equal(t, "Bearer real-bearer-tok", gotAuth)
	assert.Equal(t, "connector-owned-value", gotTraceparent,
		"connector-configured headers must take precedence over broker-injected trace headers")
}
