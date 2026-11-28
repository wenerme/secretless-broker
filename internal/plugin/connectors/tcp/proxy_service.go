package tcp

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"time"

	validation "github.com/go-ozzo/ozzo-validation"
	"github.com/pkg/errors"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	otellog "go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/trace"

	"github.com/cyberark/secretless-broker/internal"
	"github.com/cyberark/secretless-broker/internal/telemetry"
	"github.com/cyberark/secretless-broker/pkg/secretless/log"
	"github.com/cyberark/secretless-broker/pkg/secretless/plugin/connector/tcp"
)

const (
	closedConnectionErrString = "use of closed network connection"
	tcpTelemetryScope         = "github.com/cyberark/secretless-broker/internal/plugin/connectors/tcp"
)

func duplexStream(
	ctx context.Context,
	serviceName string,
	connectorID string,
	source io.ReadWriter,
	destination io.ReadWriter,
) (sourceErrorChan <-chan error, destinationErrorChan <-chan error) {
	_sourceErrorChan := make(chan error, 1)
	_destinationErrorChan := make(chan error, 1)

	go func() {
		n, err := stream(source, destination)
		telemetry.AddTCPBytes(ctx, serviceName, connectorID, "client_to_target", n)
		_sourceErrorChan <- err
	}()
	go func() {
		n, err := stream(destination, source)
		telemetry.AddTCPBytes(ctx, serviceName, connectorID, "target_to_client", n)
		_destinationErrorChan <- err
	}()

	sourceErrorChan = _sourceErrorChan
	destinationErrorChan = _destinationErrorChan
	return
}

func stream(source io.Reader, destination io.Writer) (int64, error) {
	return io.Copy(destination, source)
}

// ProxyServiceOptions configures a TCP ProxyService with optional telemetry metadata.
type ProxyServiceOptions struct {
	ServiceName                string
	ConnectorID                string
	Connector                  tcp.Connector
	Listener                   net.Listener
	Logger                     log.Logger
	RetrieveCredentials        internal.CredentialsRetriever
	RetrieveCredentialsContext internal.ContextCredentialsRetriever
}

type proxyService struct {
	serviceName                string
	connectorID                string
	connector                  tcp.Connector
	done                       atomic.Bool
	listener                   net.Listener
	logger                     log.Logger
	retrieveCredentials        internal.CredentialsRetriever
	retrieveCredentialsContext internal.ContextCredentialsRetriever
}

// NewProxyService constructs a new instance of a TCP ProxyService. The
// constructor takes a TCP Connector, CredentialResolver and Listener.
// A TCP ProxyService is able to Connect with Credentials then subsequently stream
// bytes between client and target service
func NewProxyService(
	connector tcp.Connector,
	listener net.Listener,
	logger log.Logger,
	retrieveCredentials internal.CredentialsRetriever,
) (internal.Service, error) {
	return NewProxyServiceWithOptions(ProxyServiceOptions{
		Connector:           connector,
		Listener:            listener,
		Logger:              logger,
		RetrieveCredentials: retrieveCredentials,
	})
}

// NewProxyServiceWithOptions constructs a TCP ProxyService with optional
// telemetry metadata and context-aware credential retrieval.
func NewProxyServiceWithOptions(opts ProxyServiceOptions) (internal.Service, error) {
	errs := validation.Errors{}

	if opts.Connector == nil {
		errs["connector"] = fmt.Errorf("connector cannot be nil")
	}
	if opts.RetrieveCredentials == nil && opts.RetrieveCredentialsContext == nil {
		errs["retrieveCredentials"] = fmt.Errorf("retrieveCredentials cannot be nil")
	}
	if opts.Listener == nil {
		errs["logger"] = fmt.Errorf("logger cannot be nil")
	}
	if opts.Logger == nil {
		errs["listener"] = fmt.Errorf("listener cannot be nil")
	}

	if err := errs.Filter(); err != nil {
		return nil, err
	}

	serviceName := opts.ServiceName
	if serviceName == "" {
		serviceName = opts.Logger.Prefix()
	}
	if serviceName == "" {
		serviceName = "tcp"
	}
	connectorID := opts.ConnectorID
	if connectorID == "" {
		connectorID = "tcp"
	}

	return &proxyService{
		serviceName:                serviceName,
		connectorID:                connectorID,
		connector:                  opts.Connector,
		retrieveCredentials:        opts.RetrieveCredentials,
		retrieveCredentialsContext: opts.RetrieveCredentialsContext,
		listener:                   opts.Listener,
		logger:                     opts.Logger,
	}, nil
}

func (proxy *proxyService) fetchCredentials(ctx context.Context) (map[string][]byte, error) {
	if proxy.retrieveCredentialsContext != nil {
		return proxy.retrieveCredentialsContext(ctx)
	}
	return proxy.retrieveCredentials()
}

func closeConn(conn net.Conn, connDescription string, logger log.Logger) {
	if conn == nil {
		return
	}
	err := conn.Close()
	if err != nil {
		logger.Warnf("Failed on closing %s connection: %s", connDescription, err)
	}
}

func (proxy *proxyService) handleConnection(clientConn net.Conn) error {
	var targetConn net.Conn
	logger := proxy.logger
	start := time.Now()
	tracer := telemetry.Tracer(tcpTelemetryScope)

	ctx, span := tracer.Start(
		context.Background(),
		"secretless.tcp.connection",
		trace.WithSpanKind(trace.SpanKindServer),
		trace.WithAttributes(
			attribute.String("secretless.service.name", proxy.serviceName),
			attribute.String("secretless.connector.id", proxy.connectorID),
			attribute.String("network.transport", "tcp"),
		),
	)
	telemetry.AddTCPActiveConnection(ctx, proxy.serviceName, proxy.connectorID, 1)

	outcome := "ok"
	defer func() {
		closeConn(clientConn, "client", logger)
		closeConn(targetConn, "target", logger)
		telemetry.AddTCPActiveConnection(ctx, proxy.serviceName, proxy.connectorID, -1)
		telemetry.RecordTCPConnection(ctx, proxy.serviceName, proxy.connectorID, outcome, time.Since(start))
		span.End()
	}()

	credCtx, credSpan := tracer.Start(
		ctx,
		"secretless.credentials.resolve",
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(
			attribute.String("secretless.service.name", proxy.serviceName),
			attribute.String("secretless.connector.id", proxy.connectorID),
		),
	)
	backendCredentials, err := proxy.fetchCredentials(credCtx)
	// zeroize credentials if we exit early due to an error
	defer internal.ZeroizeCredentials(backendCredentials)
	if err != nil {
		credSpan.SetStatus(codes.Error, "credential retrieval failed")
		credSpan.End()
		outcome = "credential_error"
		span.SetStatus(codes.Error, "credential retrieval failed")
		telemetry.EmitEvent(ctx, otellog.SeverityError, "tcp proxy credential retrieval failed",
			otellog.String("secretless.service.name", proxy.serviceName),
			otellog.String("secretless.connector.id", proxy.connectorID),
		)
		return errors.Wrap(err, "failed on retrieve credentials")
	}
	credSpan.End()

	logger.Debugf("New connection on %v.\n", clientConn.LocalAddr())

	connectStart := time.Now()
	_, connectSpan := tracer.Start(
		ctx,
		"secretless.tcp.connect",
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(
			attribute.String("secretless.service.name", proxy.serviceName),
			attribute.String("secretless.connector.id", proxy.connectorID),
		),
	)
	targetConn, err = proxy.connector.Connect(clientConn, backendCredentials)
	if err != nil {
		connectSpan.SetStatus(codes.Error, "backend connect failed")
		connectSpan.End()
		telemetry.RecordTCPConnect(ctx, proxy.serviceName, proxy.connectorID, "error", time.Since(connectStart))
		outcome = "connect_error"
		span.SetStatus(codes.Error, "backend connect failed")
		telemetry.EmitEvent(ctx, otellog.SeverityError, "tcp proxy backend connect failed",
			otellog.String("secretless.service.name", proxy.serviceName),
			otellog.String("secretless.connector.id", proxy.connectorID),
		)
		return errors.Wrap(err, "failed on connect")
	}
	connectSpan.End()
	telemetry.RecordTCPConnect(ctx, proxy.serviceName, proxy.connectorID, "ok", time.Since(connectStart))

	// immediately zeroize credentials after connecting
	internal.ZeroizeCredentials(backendCredentials)

	logger.Debugf("Proxying connection on %v to %v.\n", clientConn.LocalAddr(), targetConn.RemoteAddr())

	clientErrChan, destErrChan := duplexStream(ctx, proxy.serviceName, proxy.connectorID, clientConn, targetConn)

	var closer string
	select {
	case err = <-clientErrChan:
		closer = "client"
	case err = <-destErrChan:
		closer = "target"
	}

	if err != nil {
		outcome = "stream_error"
		span.SetStatus(codes.Error, "stream failed")
		return errors.Wrap(
			err,
			fmt.Sprintf(
				`connection on %v failed while streaming from %s connection`,
				clientConn.LocalAddr(),
				closer,
			),
		)
	}

	logger.Debugf("Connection on %v closed by %s.\n", clientConn.LocalAddr(), closer)
	return nil
}

// Start initiates the net.Listener to listen for incoming connections
func (proxy *proxyService) Start() error {
	logger := proxy.logger

	logger.Infof("Starting service")

	if proxy.done.Load() {
		return fmt.Errorf("cannot call Start on stopped ProxyService")
	}

	go func() { // n go routines for n tcp ProxyServices
		for !proxy.done.Load() {
			// TODO: can accepts happen in parallel ?
			conn, err := proxy.listener.Accept()

			if opErr, ok := err.(*net.OpError); ok && opErr.Err.Error() == closedConnectionErrString {
				logger.Info("Listener closed")
				return
			}
			if err != nil {
				logger.Errorf("Failed on accept connection: %s", err)
				return
			}
			go func() {
				err := proxy.handleConnection(conn)

				if err == nil {
					return
				}

				// io.EOF means connection was closed
				if errors.Cause(err) == io.EOF {
					err = errors.Wrap(
						err,
						fmt.Sprintf(
							"connection closed early on %v\n",
							conn.LocalAddr(),
						),
					)
				}

				logger.Errorf("Failed on handle connection: %s", err)
			}()
		}
	}()

	return nil
}

// Stop terminates proxyService by closing the listening net.Listener
func (proxy *proxyService) Stop() error {
	proxy.logger.Infof("Stopping service")
	proxy.done.Store(true)

	return proxy.listener.Close()
}
