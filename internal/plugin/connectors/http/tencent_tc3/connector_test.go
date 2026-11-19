package tencent_tc3

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cyberark/secretless-broker/pkg/secretless/plugin/connector"
	"github.com/stretchr/testify/require"
)

func testCredentials() connector.CredentialValuesByID {
	return connector.CredentialValuesByID{
		"secretId": []byte("AKIDEXAMPLE"), "secretKey": []byte("SECRETKEYEXAMPLE"),
	}
}

func testConnector(t *testing.T) *Connector {
	t.Helper()
	cfg, err := newConfig([]byte(clsConfig))
	require.NoError(t, err)
	return &Connector{config: cfg}
}

func testRequest(t *testing.T, body string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, "https://cls.tencentcloudapi.com/", strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-TC-Action", "DescribeTopics")
	req.Header.Set("X-TC-Version", "2020-10-16")
	req.Header.Set("X-TC-Region", "ap-guangzhou")
	return req
}

// The request, payload hash and canonical-request hash are from the official
// TC3 walkthrough: https://cloud.tencent.com/document/api/213/30654 . Its current
// credentials are redacted, so the complete signature below uses dummy keys and
// was independently calculated using Python hashlib/hmac and the documented
// pseudocode (not this connector). Keep the literal payload bytes unchanged.
func TestOfficialTC3RequestWithIndependentSignature(t *testing.T) {
	const body = `{"Limit": 1, "Filters": [{"Values": ["\u672a\u547d\u540d"], "Name": "instance-name"}]}`
	require.Equal(t, "35e9c5b0e3ae67532d3c9f17ead6c90222632e5b1ff7f6e89887f1398934f064", hashHex([]byte(body)))
	cfg, err := newConfig([]byte("service: cvm\nupstreamURL: https://cvm.tencentcloudapi.com\n"))
	require.NoError(t, err)
	c := &Connector{config: cfg}
	req := testRequest(t, body)
	req.URL.Host = cfg.host
	req.Header.Set("X-TC-Action", "DescribeInstances")
	req.Header.Set("X-TC-Version", "2017-03-12")
	req.Host = "attacker.example"
	req.Header.Set("Host", "attacker.example")
	req.Header["authorization"] = []string{"untrusted"}
	req.Header.Set("Authorization", "also-untrusted")
	req.Header["x-tc-timestamp"] = []string{"1"}
	req.Header.Set("X-TC-Token", "client-token")
	req.Header.Set("X-TC-Content-SHA256", "UNSIGNED-PAYLOAD")
	req.Header.Set("X-Custom", "preserved")
	credentials := testCredentials()
	credentials["token"] = []byte("broker-token")
	// Local date is Feb 26, whereas TC3 must use the UTC date Feb 25.
	now := time.Unix(1551113065, 0).In(time.FixedZone("UTC+8", 8*60*60))
	require.NoError(t, c.connectAt(req, credentials, now))
	require.Equal(t,
		"TC3-HMAC-SHA256 Credential=AKIDEXAMPLE/2019-02-25/cvm/tc3_request, "+
			"SignedHeaders=content-type;host;x-tc-action, "+
			"Signature=8cd2b6c0a8c5b1e6aa358096ca9df41f14b09d4b3a5f85014a31f8c0947410f5",
		req.Header.Get("Authorization"))
	require.Len(t, headerValues(req.Header, "Authorization"), 1)
	require.Equal(t, []string{"1551113065"}, headerValues(req.Header, "X-TC-Timestamp"))
	require.Equal(t, "broker-token", req.Header.Get("X-TC-Token"))
	require.Empty(t, headerValues(req.Header, "X-TC-Content-SHA256"))
	require.Empty(t, headerValues(req.Header, "Host"))
	require.Equal(t, cfg.host, req.Host)
	require.Equal(t, "DescribeInstances", req.Header.Get("X-TC-Action"))
	require.Equal(t, jsonContentType, req.Header.Get("Content-Type"))
	require.Equal(t, "preserved", req.Header.Get("X-Custom"))
	assertBody(t, req, body)
	replayed, err := req.GetBody()
	require.NoError(t, err)
	defer replayed.Close()
	replayedBytes, err := io.ReadAll(replayed)
	require.NoError(t, err)
	require.Equal(t, body, string(replayedBytes))
	require.Equal(t, []byte("SECRETKEYEXAMPLE"), credentials["secretKey"])
}

func TestConnectUsesCurrentTimeAndRemovesClientToken(t *testing.T) {
	req := testRequest(t, " {\n  \"TopicName\": \"日志\", \"Limit\": 1\n}\n")
	req.Header.Set("X-TC-Timestamp", "1551113065")
	req.Header["x-tc-token"] = []string{"stale"}
	before := time.Now().Unix()
	require.NoError(t, testConnector(t).Connect(req, testCredentials()))
	stamp, err := strconv.ParseInt(req.Header.Get("X-TC-Timestamp"), 10, 64)
	require.NoError(t, err)
	require.GreaterOrEqual(t, stamp, before)
	require.LessOrEqual(t, stamp, time.Now().Unix())
	require.Contains(t, req.Header.Get("Authorization"), "/"+time.Unix(stamp, 0).UTC().Format("2006-01-02")+"/cls/tc3_request")
	require.Empty(t, headerValues(req.Header, "X-TC-Token"))
	assertBody(t, req, " {\n  \"TopicName\": \"日志\", \"Limit\": 1\n}\n")
}

func TestRejectUnsupportedRequest(t *testing.T) {
	for name, mutate := range map[string]func(*http.Request){
		"HTTP":                   func(r *http.Request) { r.URL.Scheme = "http" },
		"other host":             func(r *http.Request) { r.URL.Host = "evil.example" },
		"other Tencent service":  func(r *http.Request) { r.URL.Host = "cvm.tencentcloudapi.com" },
		"suffix attack":          func(r *http.Request) { r.URL.Host += ".evil.example" },
		"IP":                     func(r *http.Request) { r.URL.Host = "127.0.0.1" },
		"port":                   func(r *http.Request) { r.URL.Host += ":443" },
		"userinfo":               func(r *http.Request) { r.URL.User = url.User("evil") },
		"opaque":                 func(r *http.Request) { r.URL.Opaque = "//evil.example/" },
		"GET":                    func(r *http.Request) { r.Method = http.MethodGet },
		"path":                   func(r *http.Request) { r.URL.Path = "/api" },
		"encoded path":           func(r *http.Request) { r.URL.RawPath = "/%2f" },
		"query":                  func(r *http.Request) { r.URL.RawQuery = "Action=Other" },
		"empty query":            func(r *http.Request) { r.URL.ForceQuery = true },
		"fragment":               func(r *http.Request) { r.URL.Fragment = "foo" },
		"missing content type":   func(r *http.Request) { r.Header.Del("Content-Type") },
		"form":                   func(r *http.Request) { r.Header.Set("Content-Type", "application/x-www-form-urlencoded") },
		"charset":                func(r *http.Request) { r.Header.Set("Content-Type", "application/json; charset=latin1") },
		"unknown parameter":      func(r *http.Request) { r.Header.Set("Content-Type", "application/json; foo=bar") },
		"multiple parameters":    func(r *http.Request) { r.Header.Set("Content-Type", "application/json; charset=utf-8; foo=bar") },
		"malformed content type": func(r *http.Request) { r.Header.Set("Content-Type", "application/json; charset") },
		"duplicate content type": func(r *http.Request) { r.Header.Add("Content-Type", "application/json") },
		"missing action":         func(r *http.Request) { r.Header.Del("X-TC-Action") },
		"invalid action":         func(r *http.Request) { r.Header.Set("X-TC-Action", "DescribeTopics\nInjected") },
		"duplicate action":       func(r *http.Request) { r.Header["x-tc-action"] = []string{"Other"} },
		"missing version":        func(r *http.Request) { r.Header.Del("X-TC-Version") },
		"invalid version":        func(r *http.Request) { r.Header.Set("X-TC-Version", "2024-02-31") },
		"missing region":         func(r *http.Request) { r.Header.Del("X-TC-Region") },
		"invalid region":         func(r *http.Request) { r.Header.Set("X-TC-Region", "ap guangzhou") },
		"duplicate region":       func(r *http.Request) { r.Header.Add("X-TC-Region", "ap-beijing") },
		"trailers":               func(r *http.Request) { r.Trailer = http.Header{"X-TC-Action": {"Other"}} },
		"trailer header":         func(r *http.Request) { r.Header.Set("Trailer", "X-TC-Action") },
		"compressed":             func(r *http.Request) { r.Header.Set("Content-Encoding", "gzip") },
		"nil body":               func(r *http.Request) { r.Body = nil },
		"declared oversize":      func(r *http.Request) { r.ContentLength = maxRequestBodyBytes + 1 },
	} {
		t.Run(name, func(t *testing.T) {
			req := testRequest(t, `{}`)
			mutate(req)
			require.Error(t, testConnector(t).Connect(req, testCredentials()))
			require.Empty(t, req.Header.Get("Authorization"))
		})
	}
	c := testConnector(t)
	require.Error(t, c.Connect(nil, testCredentials()))
	require.Error(t, c.Connect(&http.Request{}, testCredentials()))
	require.Error(t, (&Connector{}).Connect(testRequest(t, `{}`), testCredentials()))
}

func TestRejectInvalidCredentials(t *testing.T) {
	for name, mutate := range map[string]func(connector.CredentialValuesByID){
		"missing ID":      func(c connector.CredentialValuesByID) { delete(c, "secretId") },
		"empty ID":        func(c connector.CredentialValuesByID) { c["secretId"] = nil },
		"ID injection":    func(c connector.CredentialValuesByID) { c["secretId"] = []byte("id/other,header\r\n") },
		"missing key":     func(c connector.CredentialValuesByID) { delete(c, "secretKey") },
		"empty key":       func(c connector.CredentialValuesByID) { c["secretKey"] = nil },
		"token injection": func(c connector.CredentialValuesByID) { c["token"] = []byte("token\r\n") },
		"token space":     func(c connector.CredentialValuesByID) { c["token"] = []byte(" token ") },
	} {
		t.Run(name, func(t *testing.T) {
			creds := testCredentials()
			mutate(creds)
			req := testRequest(t, `{}`)
			require.Error(t, testConnector(t).Connect(req, creds))
			require.Empty(t, req.Header.Get("Authorization"))
			assertBody(t, req, `{}`)
		})
	}
}

func TestRejectInvalidJSONAndPreserveBody(t *testing.T) {
	for _, body := range []string{"", "null", "[]", "true", "{", "{} {}", "{\"x\":}"} {
		t.Run(body, func(t *testing.T) {
			req := testRequest(t, body)
			require.Error(t, testConnector(t).Connect(req, testCredentials()))
			assertBody(t, req, body)
		})
	}
}

func TestRejectOversizeUnknownLengthAndPreserveStream(t *testing.T) {
	body := strings.Repeat(" ", maxRequestBodyBytes+2)
	req := testRequest(t, body)
	req.ContentLength = -1
	req.GetBody = nil
	require.ErrorContains(t, testConnector(t).Connect(req, testCredentials()), "exceeds 16 MiB")
	assertBody(t, req, body)
}

type failOnceReader struct {
	*bytes.Reader
	failed bool
}

func (r *failOnceReader) Read(p []byte) (int, error) {
	if !r.failed {
		r.failed = true
		n, _ := r.Reader.Read(p[:1])
		return n, errors.New("temporary body read failure")
	}
	return r.Reader.Read(p)
}

func TestBodyReadErrorPreservesStream(t *testing.T) {
	req := testRequest(t, `{ "Limit": 1 }`)
	req.Body = io.NopCloser(&failOnceReader{Reader: bytes.NewReader([]byte(`{ "Limit": 1 }`))})
	require.ErrorContains(t, testConnector(t).Connect(req, testCredentials()), "could not read request body")
	assertBody(t, req, `{ "Limit": 1 }`)
}

func assertBody(t *testing.T, req *http.Request, expected string) {
	t.Helper()
	body, err := io.ReadAll(req.Body)
	require.NoError(t, err)
	require.NoError(t, req.Body.Close())
	require.Equal(t, expected, string(body))
}
