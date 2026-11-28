# OpenTelemetry Instrumentation

Secretless Broker supports OpenTelemetry traces, metrics, and logs configured through standard `OTEL_*` environment variables.

## Default behavior

When no exporter or OTLP endpoint environment variables are set (or when `OTEL_SDK_DISABLED=true`), all OpenTelemetry signals default to no-op providers so unconfigured deployments emit no background export errors and bind no extra ports.

## Supported environment variables

Common OpenTelemetry SDK environment variables are respected automatically:

| Category | Environment variables |
| --- | --- |
| General | `OTEL_SDK_DISABLED`, `OTEL_SERVICE_NAME` (default `secretless-broker`), `OTEL_RESOURCE_ATTRIBUTES`, `OTEL_PROPAGATORS` (default `tracecontext,baggage`) |
| Traces | `OTEL_TRACES_EXPORTER` (`otlp`, `console`, `none`), `OTEL_TRACES_SAMPLER`, `OTEL_TRACES_SAMPLER_ARG`, `OTEL_BSP_*` |
| Metrics | `OTEL_METRICS_EXPORTER` (`otlp`, `prometheus`, `console`, `none`), `OTEL_METRIC_EXPORT_INTERVAL`, `OTEL_METRIC_EXPORT_TIMEOUT`, `OTEL_EXPORTER_PROMETHEUS_HOST`, `OTEL_EXPORTER_PROMETHEUS_PORT` |
| Logs | `OTEL_LOGS_EXPORTER` (`otlp`, `console`, `none`), `OTEL_BLRP_*` |
| OTLP exporter | `OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_EXPORTER_OTLP_PROTOCOL` (`http/protobuf` or `grpc`), `OTEL_EXPORTER_OTLP_HEADERS`, `OTEL_EXPORTER_OTLP_TIMEOUT`, `OTEL_EXPORTER_OTLP_COMPRESSION`, `OTEL_EXPORTER_OTLP_INSECURE`, `OTEL_EXPORTER_OTLP_CERTIFICATE`, plus per-signal `OTEL_EXPORTER_OTLP_{TRACES,METRICS,LOGS}_*` overrides |

Setting `OTEL_EXPORTER_OTLP_ENDPOINT` activates OTLP exporting for traces, metrics, and logs unless an individual signal is explicitly disabled (for example `OTEL_LOGS_EXPORTER=none`). Setting only a per-signal endpoint (for example `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`) enables only that signal.

## Quick start examples

### Send all signals to an OTLP/HTTP collector

```sh
OTEL_SERVICE_NAME=secretless-broker \
OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318 \
OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf \
secretless-broker -f secretless.yml
```

### Send traces via OTLP/gRPC and expose Prometheus metrics

```sh
OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=http://127.0.0.1:4317 \
OTEL_EXPORTER_OTLP_TRACES_PROTOCOL=grpc \
OTEL_METRICS_EXPORTER=prometheus \
OTEL_EXPORTER_PROMETHEUS_PORT=9464 \
OTEL_LOGS_EXPORTER=none \
secretless-broker -f secretless.yml
```

### Local debugging to stdout

```sh
OTEL_TRACES_EXPORTER=console \
OTEL_METRICS_EXPORTER=none \
OTEL_LOGS_EXPORTER=none \
secretless-broker -f secretless.yml
```

## Emitted signals

### Spans

- `secretless.http.proxy` (`SERVER`): extracts incoming trace context, tracks request routing, rejection reasons, and status code.
  - `secretless.credentials.resolve` (`INTERNAL`): credential resolution phase.
    - `secretless.provider.resolve` (`CLIENT` for remote providers such as `vault`/`conjur`/`aws`/`kubernetes`, `INTERNAL` for local providers).
  - `secretless.connector.authenticate` (`INTERNAL`): connector request signing / header injection phase. Broker trace context propagation is injected before connector authentication so signing connectors sign the final headers and connector-configured headers take precedence; set `OTEL_PROPAGATORS=none` to prevent the broker from extracting or injecting propagation headers (client-supplied headers already on the incoming request are not stripped).
  - `secretless.http.upstream` (`CLIENT`): upstream round trip.
- `secretless.tcp.connection` (`SERVER`): TCP proxy session lifecycle (`secretless.credentials.resolve` + `secretless.tcp.connect`).
- `secretless.ssh.connection` / `secretless.ssh_agent.connection` (`SERVER`): SSH and SSH-Agent proxy sessions.
- `secretless.config.reload` (`INTERNAL`): configuration load and reload lifecycle.

### Metrics

- HTTP: `secretless.http.requests`, `secretless.http.request.duration`, `secretless.http.active_requests`, `secretless.http.upstream.duration`
- TCP: `secretless.tcp.connections`, `secretless.tcp.active_connections`, `secretless.tcp.connection.duration`, `secretless.tcp.connect.duration`, `secretless.tcp.bytes`
- SSH / SSH-Agent: `secretless.ssh.connections`, `secretless.ssh.active_connections`, `secretless.ssh.connection.duration`
- Credential providers: `secretless.credentials.resolve.total`, `secretless.credentials.resolve.duration`
- Configuration: `secretless.config.reloads`

### Logs

When `OTEL_LOGS_EXPORTER` or `OTEL_EXPORTER_OTLP[_LOGS]_ENDPOINT` is configured, Secretless emits curated, trace-correlated OpenTelemetry log records for audited broker events (configuration reloads, HTTP proxy rejections/failures, TCP failures, and credential resolution failures). Raw legacy `internal/log` lines and raw provider error strings are intentionally not forwarded to OTel logs.

## Security boundaries

- Credential values, `Authorization` headers, URL paths (which may embed webhook tokens), URL query parameters, URL userinfo, raw error text, and raw credential `get` identifiers (which hold literal values for `from: literal`) are never recorded in span attributes, metric labels, or OTel log records.
- `OTEL_EXPORTER_OTLP[_*]_HEADERS` values are validated before constructing SDK exporters so malformed auth headers fail cleanly without exposing raw header values in SDK diagnostic logs.
- Process command-line arguments are omitted from OpenTelemetry resource attributes.
- Initialization failures in OpenTelemetry configuration log an error and fall back to no-op telemetry rather than blocking broker startup.
