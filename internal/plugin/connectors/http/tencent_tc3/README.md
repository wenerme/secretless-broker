# Tencent Cloud API v3 authentication

The built-in `tencent_tc3` HTTP connector signs Tencent Cloud API v3 requests
using TC3-HMAC-SHA256. Applications send unsigned JSON requests to Secretless;
only the broker retrieves `secretId`, `secretKey` and an optional temporary
credential `token` from a credential provider. The initial use case is the CLS
JSON management/query API, such as `DescribeTopics` and `SearchLog`.

## Configuration with Vault KV v2

This complete `secretless.yml` uses a KV v2 engine mounted at `secret/`, with
the secret `tencent/cls` containing string fields `secretId` and `secretKey`:

```yaml
version: 2
services:
  tencent_cls:
    connector: tencent_tc3
    listenOn: tcp://127.0.0.1:8080
    credentials:
      secretId:
        from: vault
        get: secret/data/tencent/cls#data.secretId
      secretKey:
        from: vault
        get: secret/data/tencent/cls#data.secretKey
      # For temporary STS credentials, also store the matching token in Vault
      # and uncomment this credential. Omit it for permanent API keys.
      # token:
      #   from: vault
      #   get: secret/data/tencent/cls#data.token
    config:
      upstreamURL: https://cls.tencentcloudapi.com
      service: cls
      authenticateURLsMatching:
        - '^https://cls[.]tencentcloudapi[.]com/?$'
```

KV v2 uses the API path `secret/data/tencent/cls` and the nested response field
`data.secretId`, hence the `#data.secretId` suffix. The CLI path for managing
this same secret is `secret/tencent/cls`. Grant the broker's Vault token `read`
on `secret/data/tencent/cls`. Supply `VAULT_ADDR`, `VAULT_TOKEN` and, for a private
CA, `VAULT_CACERT` to the broker through your deployment's secret mechanism:

```sh
secretless-broker -f secretless.yml
```

The application needs neither Tencent credentials nor the Vault token. Restrict
access to the broker listener: callers can invoke any API action permitted by
the configured Tencent principal. Use a dedicated CAM principal with only the
CLS permissions and resources the application needs. Action/version/region
syntax is checked, but this connector does not provide an action allowlist or
validate each action's business parameters.

## Send an unsigned CLS request

Secretless is an HTTP forward proxy and does not support HTTPS `CONNECT`.
With curl, send an absolute HTTPS request target over the local HTTP connection:

```sh
curl --noproxy '*' \
  --request-target 'https://cls.tencentcloudapi.com/' \
  'http://127.0.0.1:8080/' \
  --header 'Host: cls.tencentcloudapi.com' \
  --header 'Content-Type: application/json' \
  --header 'X-TC-Action: DescribeTopics' \
  --header 'X-TC-Version: 2020-10-16' \
  --header 'X-TC-Region: ap-guangzhou' \
  --data-binary '{"Limit":1}'
```

For an application, connect to the broker and send the same absolute HTTPS
target in its HTTP request line, for example
`POST https://cls.tencentcloudapi.com/ HTTP/1.1`. The broker connects to Tencent
over verified TLS. The application's connection to the listener is plain HTTP;
keep it on loopback or an appropriately protected private channel. Setting
`HTTPS_PROXY` on an ordinary client typically attempts `CONNECT` and is not
sufficient for this flow.

The connector requires exactly one each of `Content-Type`, `X-TC-Action`,
`X-TC-Version` (a valid `YYYY-MM-DD` date), and `X-TC-Region` (for example
`ap-guangzhou`). It replaces incoming `Authorization`, `X-TC-Timestamp` and
`X-TC-Token`, removes `X-TC-Content-SHA256`, and pins the outgoing Host to the
configured endpoint. If no broker token is configured, a client token is removed.
The timestamp comes from the broker's clock, and the credential-scope date is
derived in UTC. Keep the broker clock synchronized.

The exact body bytes are hashed and forwarded without JSON re-encoding.
Content-Type is normalized to `application/json; charset=utf-8`. The canonical
signed headers are `content-type;host;x-tc-action`, with a lowercase canonical
action value, as specified by the
[official TC3 algorithm](https://cloud.tencent.com/document/api/213/30654).

## Endpoint and protocol boundaries

Both `upstreamURL` and `service` are mandatory. Only an HTTPS origin with host
`<service>.tencentcloudapi.com` or
`<service>.<region>.tencentcloudapi.com` is accepted; the service and host must
agree. Hosts must be lowercase, without a trailing dot or explicit port.
No URL userinfo, query, fragment or non-root path is accepted. A trailing `/`
is allowed. For a supported regional endpoint, pin that exact endpoint and
update `authenticateURLsMatching` to match it. Arbitrary custom hosts are not
supported. Requests to any other host or scheme are rejected before signing;
client Host headers cannot redirect credentials. The proxy uses a single
upstream round trip and does not follow redirects with injected credentials.

This implementation supports only `POST /`, no query string, and an unencoded
JSON object body of at most 16 MiB. It accepts `application/json` with an optional
UTF-8 charset and rejects other media types/parameters, compression and trailers.
The size limit bounds signing memory; the Tencent API may impose a lower limit.
Other Tencent API v3 services using this same JSON POST protocol can be configured
with their own fixed service/endpoint, but have not been integration-tested here.

There is **no token renewal**: the connector does not call STS, assume roles,
refresh temporary Tencent credentials, or renew the Vault authentication token.
Your deployment must renew the Vault token and update all three matching STS
credential fields before expiry, in accordance with the provider's retrieval
and caching behavior. Optional means the `token` credential is omitted, not that
Vault lookup errors for a configured token are ignored.

There is **no COS support**, no CLS protobuf/log-upload protocol, no presigned
URLs, no TC3 GET/form/multipart support, and no general Tencent SDK compatibility
claim. Use a separate connector/protocol implementation for those APIs.

## Tests

```sh
go test ./internal/plugin/connectors/http/tencent_tc3
go test ./pkg/secretless/plugin/sharedobj
```

Tests cover the official walkthrough request with an independently calculated
deterministic signature, UTC date boundaries, credential-header replacement,
body preservation, and malformed configuration/request rejection. They use dummy
credentials and do not make live Tencent or Vault requests.
