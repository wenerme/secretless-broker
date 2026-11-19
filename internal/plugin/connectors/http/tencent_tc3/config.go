package tencent_tc3

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"gopkg.in/yaml.v2"
)

var (
	servicePattern = regexp.MustCompile(`^[a-z][a-z0-9]{0,62}$`)
	regionPattern  = regexp.MustCompile(`^[a-z][a-z0-9]*(?:-[a-z0-9]+)+$`)
	actionPattern  = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]{0,127}$`)
)

type config struct {
	host    string
	service string
}

func newConfig(raw []byte) (*config, error) {
	var input struct {
		UpstreamURL string `yaml:"upstreamURL"`
		Service     string `yaml:"service"`
		// This shared proxy setting may be a string or a list of strings. The
		// framework validates it separately; allow it in the strict decoder.
		AuthenticateURLsMatching interface{} `yaml:"authenticateURLsMatching"`
	}
	if err := yaml.UnmarshalStrict(raw, &input); err != nil {
		return nil, fmt.Errorf("invalid YAML configuration: %w", err)
	}
	if !servicePattern.MatchString(input.Service) {
		return nil, fmt.Errorf("service must be a lowercase Tencent Cloud service name")
	}
	u, err := url.Parse(input.UpstreamURL)
	if err != nil || u.Scheme != "https" || u.Opaque != "" || u.User != nil ||
		u.RawQuery != "" || u.ForceQuery || strings.Contains(input.UpstreamURL, "#") ||
		(u.Path != "" && u.Path != "/") || u.RawPath != "" || u.Port() != "" {
		return nil, fmt.Errorf("upstreamURL must be an HTTPS origin without credentials, port, query, fragment or non-root path")
	}

	// Bind the credential scope to the endpoint as well as checking the DNS
	// suffix. Never derive the service or destination from client headers.
	globalHost := input.Service + ".tencentcloudapi.com"
	if u.Host != globalHost {
		prefix := input.Service + "."
		const suffix = ".tencentcloudapi.com"
		if !strings.HasPrefix(u.Host, prefix) || !strings.HasSuffix(u.Host, suffix) {
			return nil, fmt.Errorf("upstreamURL host must match service.tencentcloudapi.com or service.region.tencentcloudapi.com")
		}
		region := strings.TrimSuffix(strings.TrimPrefix(u.Host, prefix), suffix)
		if !regionPattern.MatchString(region) {
			return nil, fmt.Errorf("upstreamURL has an invalid regional endpoint")
		}
	}
	return &config{host: u.Host, service: input.Service}, nil
}
