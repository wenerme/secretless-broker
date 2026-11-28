package telemetry

import (
	"context"
	"time"

	"go.opentelemetry.io/otel/attribute"
	otellog "go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/log/global"
)

// EmitEvent emits an audited, structured OpenTelemetry log record correlated
// with ctx when an OpenTelemetry LoggerProvider is enabled.
//
// Callers must pass only low-sensitivity structured attributes (such as service
// name, connector ID, provider ID, status code, or static outcome/reason) and
// must never pass credential values, raw error strings, URL paths/queries, or
// raw credential identifiers.
func EmitEvent(ctx context.Context, severity otellog.Severity, body string, attrs ...attribute.KeyValue) {
	if ctx == nil {
		ctx = context.Background()
	}
	logger := global.GetLoggerProvider().Logger(InstrumentationScope)
	if !logger.Enabled(ctx, otellog.EnabledParameters{Severity: severity}) {
		return
	}

	var rec otellog.Record
	rec.SetTimestamp(time.Now())
	rec.SetSeverity(severity)
	rec.SetBody(attribute.StringValue(body))
	if len(attrs) > 0 {
		rec.AddAttributes(attrs...)
	}
	logger.Emit(ctx, rec)
}
