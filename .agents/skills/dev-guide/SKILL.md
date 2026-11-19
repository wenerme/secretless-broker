---
name: dev-guide
description: Use when developing, reviewing, testing, or extending this Secretless Broker fork, especially credential providers, HTTP/TCP connectors, proxy routing, CI, or the Tencent TC3 connector.
---

# Secretless Broker Development Guide

This is a repository-local development skill for `wenerme/secretless-broker`.
The repository's default working branch is `develop`; the `fork` remote points
to `wenerme/secretless-broker` and `origin` points to the CyberArk upstream.

## Start safely

Run these checks before editing:

```bash
git status --short --branch
git remote -v
git submodule update --init --recursive
go version
```

Expected conditions:

- Work on `develop` unless the task explicitly names another branch.
- Keep unrelated dirty files untouched.
- Use Go 1.27.3 or a compatible newer Go toolchain. The CI runs Go 1.27.3.
- Keep `third_party/go-mssqldb` initialized; it is a repository submodule.
- Never put real API keys, Vault/OpenBao tokens, database passwords, or test
  credentials into tracked files, fixtures, logs, or commit messages.

Completion criterion: `git status` and the intended scope are recorded before
the first edit, and the submodule is initialized.

## Architecture map

| Area | Source of truth | Responsibility |
| --- | --- | --- |
| CLI/server entry | `cmd/secretless-broker/` | Process startup and config loading |
| v2 config | `pkg/secretless/config/v2/` | YAML parsing, validation, grouping |
| Proxy lifecycle | `internal/proxyservice/` | Service construction and listener lifecycle |
| HTTP proxy | `internal/plugin/connectors/http/proxy_service.go` | URL matching, upstream pinning, credential retrieval, request forwarding |
| Built-in HTTP connectors | `internal/plugin/connectors/http/<name>/` | Protocol-specific request decoration |
| Built-in TCP connectors | `internal/plugin/connectors/tcp/<name>/` | Protocol-specific connection/auth handshake |
| Credential providers | `internal/providers/<name>/` | Read credential values from a source |
| Plugin registry | `pkg/secretless/plugin/sharedobj/internal_plugins.go` | Make built-in connectors discoverable |
| Connector/provider tests | `internal/.../*_test.go`, `test/` | Unit, integration, and platform tests |

Do not confuse a provider with a connector:

```text
provider: where credentials come from
connector: how a target protocol receives credentials
```

## HTTP routing model

Multiple HTTP service entries may share one `listenOn`; v2 configuration groups
them into one HTTP proxy. A subservice is selected by
`authenticateURLsMatching`. Matching is URL-regex based, not username based.
If multiple subservices match, Secretless logs a warning and uses the first
match. If none matches, the request is rejected rather than forwarded as an
open proxy.

When a service handles credentials, set `upstreamURL` whenever possible. The
HTTP proxy then verifies scheme and host before fetching credentials, preventing
credential injection to an attacker-controlled destination. Do not treat
`generic_http` as a general hostname router: `upstreamURL` pins one target and
the matcher only selects authentication behavior.

Completion criterion: every new HTTP service has a non-overlapping matcher and
an explicit upstream trust boundary, or the design documents why it cannot.

## Add an HTTP connector

Use the existing HTTP connector interface and keep the implementation small:

1. Create `internal/plugin/connectors/http/<connector-id>/`.
2. Add `plugin.go` with `PluginInfo`, `NewConnector`, and `GetHTTPPlugin`.
3. Implement `Connect(request, credentials)` in the connector. Preserve the
   request body, validate the destination, and avoid logging credential values.
4. Parse connector-specific configuration in `config.go`; reject ambiguous or
   unsafe targets at startup rather than accepting arbitrary destinations.
5. Register the plugin in
   `pkg/secretless/plugin/sharedobj/internal_plugins.go` and update its test.
6. Add deterministic tests for canonicalization/signatures, malformed config,
   body preservation, header replacement, and security boundary failures.
7. Add a connector README with YAML, provider field names, protocol scope,
   limitations, and a safe local invocation example.

For request-signing connectors, derive the timestamp and canonical date in the
broker, sign the exact bytes that will be sent, and remove client-supplied
authorization/signature headers before signing. Use an official test vector or
an independently implemented reference calculation.

Completion criterion: the connector is registered, targeted tests pass, the
README states unsupported protocol variants, and a reviewer can identify the
credential exfiltration boundary from the code and tests.

## Tencent TC3 connector

The current `tencent_tc3` connector is intentionally limited to:

- Tencent Cloud API v3;
- HTTPS endpoint pinned by `upstreamURL` and `service`;
- root-path JSON `POST` requests;
- `SecretId`, `SecretKey`, and optional STS token from a provider;
- TC3-HMAC-SHA256 signing of `content-type;host;x-tc-action`.

It does not implement COS signing, CLS protobuf/log upload, TC3 GET/form/
multipart requests, STS acquisition, or token renewal. Do not broaden the
scope silently; add protocol-specific tests and documentation first.

## Add a credential provider

1. Add the provider package under `internal/providers/<provider-id>/`.
2. Implement the provider factory and the repository's provider interface.
3. Register the factory in `internal/providers/providers.go`.
4. Test missing values, malformed identifiers, multiple retrievals, and error
   handling without real credentials.
5. Document required environment/configuration names and lifecycle behavior.

Providers should return only what the connector needs. Do not make a provider
perform protocol signing; that belongs to the connector.

Completion criterion: the provider is registered, can be selected by the YAML
`from` field, and tests prove that failures do not leak credential values.

## Validation loop

For a connector or registry change, run the narrow loop first:

```bash
GOTOOLCHAIN=go1.27.3+auto go test ./internal/plugin/connectors/http/tencent_tc3 \
  ./pkg/secretless/plugin/sharedobj \
  ./internal/plugin/connectors/http \
  ./internal/proxyservice \
  ./pkg/secretless/config/v2

GOTOOLCHAIN=go1.27.3+auto go vet \
  ./internal/plugin/connectors/http/tencent_tc3 \
  ./pkg/secretless/plugin/sharedobj

git diff --check
```

For the repository-level checks:

```bash
./bin/test_unit
./bin/build
./bin/test
```

The CI build can skip the Red Hat image when the external UBI registry is not
available:

```bash
SKIP_REDHAT_IMAGE=1 ./bin/build
```

This skips only `secretless-broker-redhat`; it does not skip the main image,
dev image, quick-start image, coverage image, or integration tests.

The macOS Keychain test is separate and mutates the current user's temporary
Keychain entries. Run it only when explicitly needed, and always execute its
cleanup:

```bash
cd test/providers/keychain
./start && ./test && ./stop
```

Completion criterion: report exact commands and results; distinguish unit,
integration, platform, live-provider, and live-upstream tests.

## CI and Git workflow

`.github/workflows/ci.yml` runs on pushes and supports manual dispatch. The
required jobs are:

- Unit Tests on `ubuntu-latest`;
- Linux build and integration tests on `ubuntu-latest`;
- macOS Keychain tests on `macos-15-intel`.

Before pushing:

```bash
git diff --check
git status --short --branch
git log -1 --oneline
```

Commit focused changes with a Chinese commit message, push `develop` to the
fork, and inspect the GitHub Actions run for the pushed SHA. Do not claim CI
success from local tests alone.

Completion criterion: the fork branch is clean, the pushed SHA is confirmed,
and all required CI jobs are successful or the remaining failure is explicitly
reported with its external cause.

## Security review checklist

- Is the target endpoint fixed or strictly validated before credentials are
  fetched?
- Are client-supplied auth/signature headers ignored or replaced?
- Is TLS verification preserved? Never add an insecure-skip-verify default.
- Are request bodies restored after hashing or inspection?
- Can logs, errors, tests, or metrics reveal credentials?
- Are provider tokens scoped to the minimum target permissions?
- Is rotation/expiry behavior documented rather than implied?
- Are unsupported protocol modes rejected instead of silently forwarded?

For OpenBao/Bao integration, keep deployment, token handling, network exposure,
and recovery evidence in the infrastructure repository's `context/sec` scope.
This repository documents the connector contract only; it must not receive
OpenBao recovery keys, root tokens, PINs, or production secret values.
