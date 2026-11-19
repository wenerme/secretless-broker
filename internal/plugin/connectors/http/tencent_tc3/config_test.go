package tencent_tc3

import (
	"io"
	"testing"

	"github.com/cyberark/secretless-broker/internal/log"
	"github.com/cyberark/secretless-broker/pkg/secretless/plugin/connector"
	"github.com/stretchr/testify/require"
)

const clsConfig = "service: cls\nupstreamURL: https://cls.tencentcloudapi.com\n"

func TestConfig(t *testing.T) {
	for _, raw := range []string{
		clsConfig,
		clsConfig + "authenticateURLsMatching: '^https://cls[.]tencentcloudapi[.]com/'\n",
		clsConfig + "authenticateURLsMatching: ['^https://']\n",
		"service: cls\nupstreamURL: https://cls.ap-guangzhou.tencentcloudapi.com/\n",
	} {
		cfg, err := newConfig([]byte(raw))
		require.NoError(t, err)
		require.Equal(t, "cls", cfg.service)
		require.NotEmpty(t, cfg.host)
	}
}

func TestRejectMalformedConfig(t *testing.T) {
	for name, raw := range map[string]string{
		"empty":           "",
		"null":            "null",
		"not mapping":     "[]",
		"malformed YAML":  "[",
		"missing URL":     "service: cls",
		"missing service": "upstreamURL: https://cls.tencentcloudapi.com",
		"invalid service": "service: CLS\nupstreamURL: https://cls.tencentcloudapi.com",
		"unknown field":   clsConfig + "endpoint: https://evil.example\n",
		"duplicate field": clsConfig + "service: cvm\n",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := newConfig([]byte(raw))
			require.Error(t, err)
		})
	}
	for _, endpoint := range []string{
		"http://cls.tencentcloudapi.com", "https://evil.example", "https://127.0.0.1",
		"https://cls.tencentcloudapi.com.evil.example", "https://evil-tencentcloudapi.com",
		"https://cvm.tencentcloudapi.com", "https://tencentcloudapi.com", "https://cls.tencentcloudapi.com.",
		"https://cls.tencentcloudapi.com:443", "https://cls.tencentcloudapi.com:8443",
		"https://user:pass@cls.tencentcloudapi.com", "https://cls.tencentcloudapi.com/api",
		"https://cls.tencentcloudapi.com?", "https://cls.tencentcloudapi.com?x=y",
		"https://cls.tencentcloudapi.com#", "https://cls.tencentcloudapi.com#fragment",
		"https://cls.tencentcloudapi.com/%2f", "https://cls.tencentcloudapi.com/%2e%2e/",
		"https://cls.foo.bar.tencentcloudapi.com", "https://cls..tencentcloudapi.com",
		"https://cls.-ap-guangzhou.tencentcloudapi.com", "https://cls.TENCENTCLOUDAPI.com",
		"//cls.tencentcloudapi.com", "https:cls.tencentcloudapi.com", "https://[::1]", ":bad",
	} {
		t.Run(endpoint, func(t *testing.T) {
			_, err := newConfig([]byte("service: cls\nupstreamURL: " + endpoint + "\n"))
			require.Error(t, err)
		})
	}
}

func TestPlugin(t *testing.T) {
	resources := connector.NewResources([]byte(clsConfig), log.NewWithOptions(io.Discard, "", false))
	require.IsType(t, &Connector{}, GetHTTPPlugin().NewConnector(resources))
	require.Equal(t, "tencent_tc3", PluginInfo()["id"])
	require.Equal(t, "connector.http", PluginInfo()["type"])
	require.Panics(t, func() {
		NewConnector(connector.NewResources(nil, resources.Logger()))
	})
}
