package tcp

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"

	"github.com/cyberark/secretless-broker/internal/log"
	"github.com/cyberark/secretless-broker/pkg/secretless/plugin/connector"
)

type echoTCPConnector struct {
	targetAddr string
}

func (c *echoTCPConnector) Connect(_ net.Conn, _ connector.CredentialValuesByID) (net.Conn, error) {
	return net.Dial("tcp", c.targetAddr)
}

func TestTCPProxyTelemetry_SpansAndMetrics(t *testing.T) {
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

	// Start an echo backend.
	backendListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer backendListener.Close()

	go func() {
		conn, err := backendListener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = io.Copy(conn, conn)
	}()

	proxyListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	var credSpanCtx trace.SpanContext
	svc, err := NewProxyServiceWithOptions(ProxyServiceOptions{
		ServiceName: "mysql-prod",
		ConnectorID: "mysql",
		Connector:   &echoTCPConnector{targetAddr: backendListener.Addr().String()},
		Listener:    proxyListener,
		Logger:      log.New(false),
		RetrieveCredentialsContext: func(ctx context.Context) (map[string][]byte, error) {
			credSpanCtx = trace.SpanContextFromContext(ctx)
			return map[string][]byte{"password": []byte("super-secret-db-pass")}, nil
		},
	})
	require.NoError(t, err)
	require.NoError(t, svc.Start())
	defer svc.Stop()

	clientConn, err := net.Dial("tcp", proxyListener.Addr().String())
	require.NoError(t, err)

	payload := []byte("hello-tcp-proxy")
	_, err = clientConn.Write(payload)
	require.NoError(t, err)

	buf := make([]byte, len(payload))
	_, err = io.ReadFull(clientConn, buf)
	require.NoError(t, err)
	assert.Equal(t, payload, buf)
	require.NoError(t, clientConn.Close())

	// Wait for proxy connection goroutine to finish recording spans and metrics.
	require.Eventually(t, func() bool {
		for _, s := range sr.Ended() {
			if s.Name() == "secretless.tcp.connection" {
				return true
			}
		}
		return false
	}, 3*time.Second, 20*time.Millisecond)

	assert.True(t, credSpanCtx.IsValid())

	spanNames := map[string]bool{}
	for _, s := range sr.Ended() {
		spanNames[s.Name()] = true
		for _, attr := range s.Attributes() {
			assert.NotContains(t, attr.Value.Emit(), "super-secret-db-pass")
		}
	}
	assert.True(t, spanNames["secretless.tcp.connection"])
	assert.True(t, spanNames["secretless.credentials.resolve"])
	assert.True(t, spanNames["secretless.tcp.connect"])

	var rm metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(context.Background(), &rm))
	metricsByName := map[string]metricdata.Metrics{}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			metricsByName[m.Name] = m
		}
	}

	assert.Contains(t, metricsByName, "secretless.tcp.connections")
	assert.Contains(t, metricsByName, "secretless.tcp.active_connections")
	assert.Contains(t, metricsByName, "secretless.tcp.connection.duration")
	assert.Contains(t, metricsByName, "secretless.tcp.connect.duration")
	assert.Contains(t, metricsByName, "secretless.tcp.bytes")

	activeSum, ok := metricsByName["secretless.tcp.active_connections"].Data.(metricdata.Sum[int64])
	require.True(t, ok)
	require.Len(t, activeSum.DataPoints, 1)
	assert.Equal(t, int64(0), activeSum.DataPoints[0].Value)
}
