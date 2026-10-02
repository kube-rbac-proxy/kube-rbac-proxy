/*
Copyright 2022 the kube-rbac-proxy maintainers. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package options

import (
	"fmt"
	"net/url"
	"os"
	"path"

	"github.com/ghodss/yaml"
	"github.com/spf13/pflag"

	serverconfig "k8s.io/apiserver/pkg/server"
	"k8s.io/klog/v2"

	"github.com/brancz/kube-rbac-proxy/pkg/authn"
	"github.com/brancz/kube-rbac-proxy/pkg/authn/identityheaders"
	authz "github.com/brancz/kube-rbac-proxy/pkg/authorization"
	"github.com/brancz/kube-rbac-proxy/pkg/server"
)

// ProxyOptions are options specific to the kube-rbac-proxy.
type ProxyOptions struct {
	Upstream         string
	UpstreamForceH2C bool

	UpstreamCAFile         string
	UpstreamClientCertFile string
	UpstreamClientKeyFile  string

	UpstreamHeader *identityheaders.AuthnHeaderConfig

	ConfigFileName string
	AllowPaths     []string
	IgnorePaths    []string

	ProxyEndpointsPort int

	OIDC           *authn.OIDCConfig
	TokenAudiences []string
}

func (o *ProxyOptions) AddFlags(flagset *pflag.FlagSet) {
	flagset.StringVar(&o.Upstream, "upstream", "", "The upstream URL to proxy to once requests have successfully been authenticated and authorized.")
	flagset.BoolVar(&o.UpstreamForceH2C, "upstream-force-h2c", false, "Force h2c to communicate with the upstream. This is required when the upstream speaks h2c(http/2 cleartext - insecure variant of http/2) only. For example, go-grpc server in the insecure mode, such as helm's tiller w/o TLS, speaks h2c only")

	// upstream tls options
	flagset.StringVar(&o.UpstreamCAFile, "upstream-ca-file", "", "The CA the upstream uses for TLS connection. This is required when the upstream uses TLS and its own CA certificate")
	flagset.StringVar(&o.UpstreamClientCertFile, "upstream-client-cert-file", "", "If set, the client will be used to authenticate the proxy to upstream. Requires --upstream-client-key-file to be set, too.")
	flagset.StringVar(&o.UpstreamClientKeyFile, "upstream-client-key-file", "", "The key matching the certificate from --upstream-client-cert-file. If set, requires --upstream-client-cert-file to be set, too.")

	flagset.StringVar(&o.ConfigFileName, "config-file", "", "Configuration file to configure kube-rbac-proxy.")
	flagset.StringSliceVar(&o.AllowPaths, "allow-paths", nil, "Comma-separated list of paths against which kube-rbac-proxy pattern-matches the incoming request. If the request doesn't match, kube-rbac-proxy responds with a 404 status code. If omitted, the incoming request path isn't checked. Cannot be used with --ignore-paths.")
	flagset.StringSliceVar(&o.IgnorePaths, "ignore-paths", nil, "Comma-separated list of paths against which kube-rbac-proxy pattern-matches the incoming request. If the requst matches, it will proxy the request without performing an authentication or authorization check. Cannot be used with --allow-paths.")

	// upstream header options
	flagset.StringVar(&o.UpstreamHeader.UserFieldName, "auth-header-user-field-name", "x-remote-user", "The name of the field inside a http(2) request header to tell the upstream server about the user's name")
	flagset.StringVar(&o.UpstreamHeader.GroupsFieldName, "auth-header-groups-field-name", "x-remote-groups", "The name of the field inside a http(2) request header to tell the upstream server about the user's groups")
	flagset.StringVar(&o.UpstreamHeader.GroupSeparator, "auth-header-groups-field-separator", "|", "The separator string used for concatenating multiple group names in a groups header field's value")

	//Authn OIDC flags
	flagset.StringVar(&o.OIDC.IssuerURL, "oidc-issuer", "", "The URL of the OpenID issuer, only HTTPS scheme will be accepted. If set, it will be used to verify the OIDC JSON Web Token (JWT).")
	flagset.StringVar(&o.OIDC.ClientID, "oidc-clientID", "", "The client ID for the OpenID Connect client, must be set if oidc-issuer-url is set.")
	flagset.StringVar(&o.OIDC.GroupsClaim, "oidc-groups-claim", "groups", "Identifier of groups in JWT claim, by default set to 'groups'")
	flagset.StringVar(&o.OIDC.UsernameClaim, "oidc-username-claim", "email", "Identifier of the user in JWT claim, by default set to 'email'")
	flagset.StringVar(&o.OIDC.GroupsPrefix, "oidc-groups-prefix", "", "If provided, all groups will be prefixed with this value to prevent conflicts with other authentication strategies.")
	flagset.StringArrayVar(&o.OIDC.SupportedSigningAlgs, "oidc-sign-alg", []string{"RS256"}, "Supported signing algorithms, default RS256")
	flagset.StringVar(&o.OIDC.CAFile, "oidc-ca-file", "", "If set, the OpenID server's certificate will be verified by one of the authorities in the oidc-ca-file, otherwise the host's root CA set will be used.")

	flagset.StringSliceVar(&o.TokenAudiences, "auth-token-audiences", []string{}, "Comma-separated list of token audiences to accept. By default a token does not have to have any specific audience. It is recommended to set a specific audience.")

	// proxy endpoints flag
	flagset.IntVar(&o.ProxyEndpointsPort, "proxy-endpoints-port", 0, "The port to securely serve proxy-specific endpoints (such as '/healthz'). Uses the host from the '--secure-listen-address'.")
}

func (o *ProxyOptions) Validate() []error {
	var errs []error

	if len(o.UpstreamHeader.GroupSeparator) > 0 && len(o.UpstreamHeader.GroupsFieldName) == 0 {
		errs = append(errs, fmt.Errorf("--auth-header-groups-field-name must be set along with --auth-header-groups-field-separator"))
	}

	if len(o.AllowPaths) > 0 && len(o.IgnorePaths) > 0 {
		errs = append(errs, fmt.Errorf("cannot use --allow-paths and --ignore-paths together"))
	}

	for _, pathAllowed := range o.AllowPaths {
		if _, err := path.Match(pathAllowed, ""); err != nil {
			errs = append(errs, fmt.Errorf("failed to verify allow path: %s", pathAllowed))
		}
	}

	for _, pathIgnored := range o.IgnorePaths {
		if _, err := path.Match(pathIgnored, ""); err != nil {
			errs = append(errs, fmt.Errorf("failed to verify ignored path: %s", pathIgnored))
		}
	}

	return errs
}

func (o *ProxyOptions) ApplyTo(c *server.KubeRBACProxyInfo, a *serverconfig.AuthenticationInfo) error {
	var err error

	c.UpstreamURL, err = url.Parse(o.Upstream)
	if err != nil {
		return fmt.Errorf("failed to parse upstream URL: %w", err)
	}

	if err := c.SetUpstreamTransport(o.UpstreamCAFile, o.UpstreamClientCertFile, o.UpstreamClientKeyFile); err != nil {
		return fmt.Errorf("failed to setup transport for upstream: %w", err)
	}

	if configFileName := o.ConfigFileName; len(configFileName) > 0 {
		c.Authorization, err = parseAuthorizationConfigFile(configFileName)
		if err != nil {
			return fmt.Errorf("failed to read the config file: %w", err)
		}
	}

	c.UpstreamForceH2C = o.UpstreamForceH2C
	c.OIDC = o.OIDC
	c.IgnorePaths = o.IgnorePaths
	c.AllowPaths = o.AllowPaths
	a.APIAudiences = o.TokenAudiences

	return nil
}

type configfile struct {
	AuthorizationConfig *authz.AuthzConfig `json:"authorization,omitempty"`
}

func parseAuthorizationConfigFile(filePath string) (*authz.AuthzConfig, error) {
	klog.Infof("Reading config file: %s", filePath)
	b, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read resource-attribute file: %w", err)
	}

	configFile := configfile{}
	if err := yaml.Unmarshal(b, &configFile); err != nil {
		return nil, fmt.Errorf("failed to parse config file content: %w", err)
	}

	return configFile.AuthorizationConfig, nil
}
