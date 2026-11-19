// Package tencent_tc3 signs Tencent Cloud API v3 JSON requests with TC3-HMAC-SHA256.
package tencent_tc3

import (
	"github.com/cyberark/secretless-broker/pkg/secretless/plugin/connector"
	"github.com/cyberark/secretless-broker/pkg/secretless/plugin/connector/http"
)

// PluginInfo returns the metadata required by the Secretless plugin API.
func PluginInfo() map[string]string {
	return map[string]string{
		"pluginAPIVersion": "0.1.0",
		"type":             "connector.http",
		"id":               "tencent_tc3",
		"description":      "signs Tencent Cloud API v3 JSON requests with TC3-HMAC-SHA256",
	}
}

// NewConnector creates a connector with an operator-configured, fixed upstream.
// The plugin constructor API cannot return an error; invalid configuration is a
// startup error, as with the other configurable built-in HTTP connectors.
func NewConnector(resources connector.Resources) http.Connector {
	cfg, err := newConfig(resources.Config())
	if err != nil {
		resources.Logger().Panicf("can't create tencent_tc3 connector: %s", err)
		return nil
	}
	return &Connector{config: cfg}
}

// GetHTTPPlugin returns the built-in HTTP plugin.
func GetHTTPPlugin() http.Plugin {
	return http.NewConnectorFunc(NewConnector)
}
