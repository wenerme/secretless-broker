package tencent_tc3

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/cyberark/secretless-broker/pkg/secretless/plugin/connector"
)

const (
	algorithm           = "TC3-HMAC-SHA256"
	signedHeaders       = "content-type;host;x-tc-action"
	jsonContentType     = "application/json; charset=utf-8"
	maxRequestBodyBytes = 16 << 20
)

// Connector signs JSON POST requests to a fixed Tencent Cloud API v3 endpoint.
// It does not acquire or renew temporary credentials.
type Connector struct {
	config *config
}

// Connect validates and signs a request using secretId, secretKey and, when
// configured, token. Time is always supplied by the broker, never the caller.
func (c *Connector) Connect(req *http.Request, credentials connector.CredentialValuesByID) error {
	return c.connectAt(req, credentials, time.Now())
}

func (c *Connector) connectAt(req *http.Request, credentials connector.CredentialValuesByID, now time.Time) error {
	if c.config == nil {
		return fmt.Errorf("tencent_tc3: connector has no valid configuration")
	}
	if req == nil || req.URL == nil {
		return fmt.Errorf("tencent_tc3: request URL is required")
	}
	u := req.URL
	if u.Scheme != "https" || u.Host != c.config.host || u.User != nil || u.Opaque != "" {
		return fmt.Errorf("tencent_tc3: request must target the configured HTTPS upstream")
	}
	if req.Method != http.MethodPost || (u.Path != "" && u.Path != "/") ||
		u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return fmt.Errorf("tencent_tc3: only POST / without query or fragment is supported")
	}
	if len(req.Trailer) != 0 || len(headerValues(req.Header, "Trailer")) != 0 ||
		len(headerValues(req.Header, "Content-Encoding")) != 0 {
		return fmt.Errorf("tencent_tc3: trailers and encoded bodies are not supported")
	}
	contentType, err := requiredHeader(req.Header, "Content-Type")
	if err != nil {
		return err
	}
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil || mediaType != "application/json" || len(params) > 1 ||
		(len(params) == 1 && !strings.EqualFold(params["charset"], "utf-8")) {
		return fmt.Errorf("tencent_tc3: Content-Type must be application/json with optional UTF-8 charset")
	}
	action, err := requiredHeader(req.Header, "X-TC-Action")
	if err != nil {
		return err
	}
	if !actionPattern.MatchString(action) {
		return fmt.Errorf("tencent_tc3: invalid X-TC-Action")
	}
	version, err := requiredHeader(req.Header, "X-TC-Version")
	if err != nil {
		return err
	}
	if _, err := time.Parse("2006-01-02", version); err != nil {
		return fmt.Errorf("tencent_tc3: X-TC-Version must be a valid YYYY-MM-DD date")
	}
	region, err := requiredHeader(req.Header, "X-TC-Region")
	if err != nil {
		return err
	}
	if len(region) > 63 || !regionPattern.MatchString(region) {
		return fmt.Errorf("tencent_tc3: invalid X-TC-Region")
	}
	secretID := string(credentials["secretId"])
	if !validSecretID(secretID) {
		return fmt.Errorf("tencent_tc3: secretId must be a nonempty alphanumeric credential")
	}
	if len(credentials["secretKey"]) == 0 {
		return fmt.Errorf("tencent_tc3: secretKey is required")
	}
	token := string(credentials["token"])
	if !validToken(token) {
		return fmt.Errorf("tencent_tc3: token must contain only visible ASCII characters")
	}
	if req.Body == nil || req.ContentLength > maxRequestBodyBytes {
		return fmt.Errorf("tencent_tc3: a JSON object body of at most 16 MiB is required")
	}

	// Read a bounded amount, and restore the original stream even on error.
	// This also preserves bytes/whitespace rather than re-encoding JSON.
	originalBody := req.Body
	body, err := io.ReadAll(io.LimitReader(originalBody, maxRequestBodyBytes+1))
	req.Body = struct {
		io.Reader
		io.Closer
	}{io.MultiReader(bytes.NewReader(body), originalBody), originalBody}
	if err != nil {
		return fmt.Errorf("tencent_tc3: could not read request body")
	}
	if len(body) > maxRequestBodyBytes {
		return fmt.Errorf("tencent_tc3: request body exceeds 16 MiB")
	}
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 || trimmed[0] != '{' || !json.Valid(body) {
		return fmt.Errorf("tencent_tc3: request body must be a JSON object")
	}
	_ = originalBody.Close()
	req.Body = io.NopCloser(bytes.NewReader(body))
	req.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(body)), nil
	}
	req.ContentLength = int64(len(body))
	req.TransferEncoding = nil

	// Replace all spellings, including non-canonical keys in programmatically
	// constructed requests, so duplicate client authentication cannot survive.
	for _, name := range []string{"Authorization", "X-TC-Timestamp", "X-TC-Token", "X-TC-Content-SHA256", "Host", "Content-Type", "X-TC-Action", "X-TC-Version", "X-TC-Region"} {
		deleteHeader(req.Header, name)
	}
	u.Path = "/"
	req.Host = c.config.host
	req.Header.Set("Content-Type", jsonContentType)
	req.Header.Set("X-TC-Action", action)
	req.Header.Set("X-TC-Version", version)
	req.Header.Set("X-TC-Region", region)
	timestamp := strconv.FormatInt(now.Unix(), 10)
	req.Header.Set("X-TC-Timestamp", timestamp)
	if token != "" {
		req.Header.Set("X-TC-Token", token)
	}
	req.Header.Set("Authorization", authorization(c.config, secretID, credentials["secretKey"], action, timestamp, now.UTC().Format("2006-01-02"), body))
	return nil
}

func authorization(cfg *config, secretID string, secretKey []byte, action, timestamp, date string, body []byte) string {
	canonicalHeaders := "content-type:" + jsonContentType + "\nhost:" + cfg.host + "\nx-tc-action:" + strings.ToLower(action) + "\n"
	canonicalRequest := "POST\n/\n\n" + canonicalHeaders + "\n" + signedHeaders + "\n" + hashHex(body)
	scope := date + "/" + cfg.service + "/tc3_request"
	stringToSign := algorithm + "\n" + timestamp + "\n" + scope + "\n" + hashHex([]byte(canonicalRequest))
	key := append([]byte("TC3"), secretKey...)
	dateKey := hmacSHA256(key, date)
	serviceKey := hmacSHA256(dateKey, cfg.service)
	signingKey := hmacSHA256(serviceKey, "tc3_request")
	signature := hex.EncodeToString(hmacSHA256(signingKey, stringToSign))
	clear(key)
	clear(dateKey)
	clear(serviceKey)
	clear(signingKey)
	return algorithm + " Credential=" + secretID + "/" + scope + ", SignedHeaders=" + signedHeaders + ", Signature=" + signature
}

func hashHex(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

func hmacSHA256(key []byte, value string) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(value))
	return mac.Sum(nil)
}

func headerValues(headers http.Header, name string) []string {
	var values []string
	for key, value := range headers {
		if strings.EqualFold(key, name) {
			values = append(values, value...)
		}
	}
	return values
}

func requiredHeader(headers http.Header, name string) (string, error) {
	values := headerValues(headers, name)
	if len(values) != 1 || values[0] == "" || values[0] != strings.TrimSpace(values[0]) {
		return "", fmt.Errorf("tencent_tc3: exactly one nonempty %s header is required", name)
	}
	return values[0], nil
}

func deleteHeader(headers http.Header, name string) {
	for key := range headers {
		if strings.EqualFold(key, name) {
			delete(headers, key)
		}
	}
}

func validSecretID(value string) bool {
	if value == "" {
		return false
	}
	for _, ch := range value {
		if !(ch >= 'A' && ch <= 'Z' || ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9') {
			return false
		}
	}
	return true
}

func validToken(value string) bool {
	for _, ch := range value {
		if ch < '!' || ch > '~' {
			return false
		}
	}
	return true
}
