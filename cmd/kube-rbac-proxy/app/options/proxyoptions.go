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

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog/v2"

	"github.com/brancz/kube-rbac-proxy/pkg/authn"
	"github.com/brancz/kube-rbac-proxy/pkg/authz"
	"github.com/brancz/kube-rbac-proxy/pkg/server"
)

// ProxyOptions are options specific to the kube-rbac-proxy.
type ProxyOptions struct {
	Upstream         string
	UpstreamForceH2C bool

	UpstreamCAFile         string
	UpstreamClientCertFile string
	UpstreamClientKeyFile  string

	ConfigFileName string
	AllowPaths     []string
	IgnorePaths    []string

	KubeconfigLocation string
	ProxyEndpointsPort int

	Authentication *authn.AuthnConfig
}

func (o *ProxyOptions) AddFlags(flagset *pflag.FlagSet) {
	flagset.StringVar(&o.Upstream, "upstream", "", "The upstream URL to proxy to once requests have successfully been authenticated and authorized.")
	flagset.BoolVar(&o.UpstreamForceH2C, "upstream-force-h2c", false, "Force h2c to communicate with the upstream. This is required when the upstream speaks h2c(http/2 cleartext - insecure variant of http/2) only. For example, go-grpc server in the insecure mode, such as helm's tiller w/o TLS, speaks h2c only")

	// upstream tls options
	flagset.StringVar(&o.UpstreamCAFile, "upstream-ca-file", "", "The CA the upstream uses for TLS connection. This is required when the upstream uses TLS and its own CA certificate")
	flagset.StringVar(&o.UpstreamClientCertFile, "upstream-client-cert-file", "", "If set, the client will be used to authenticate the proxy to upstream. Requires --upstream-client-key-file to be set, too.")
	flagset.StringVar(&o.UpstreamClientKeyFile, "upstream-client-key-file", "", "The key matching the certificate from --upstream-client-cert-file. If set, requires --upstream-client-cert-file to be set, too.")

	// Auth flags
	flagset.StringVar(&o.Authentication.X509.ClientCAFile, "client-ca-file", "", "If set, any request presenting a client certificate signed by one of the authorities in the client-ca-file is authenticated with an identity corresponding to the CommonName of the client certificate.")
	flagset.BoolVar(&o.Authentication.Header.Enabled, "auth-header-fields-enabled", false, "When set to true, kube-rbac-proxy adds auth-related fields to the headers of http requests sent to the upstream")
	flagset.StringVar(&o.Authentication.Header.UserFieldName, "auth-header-user-field-name", "x-remote-user", "The name of the field inside a http(2) request header to tell the upstream server about the user's name")
	flagset.StringVar(&o.Authentication.Header.GroupsFieldName, "auth-header-groups-field-name", "x-remote-groups", "The name of the field inside a http(2) request header to tell the upstream server about the user's groups")
	flagset.StringVar(&o.Authentication.Header.GroupSeparator, "auth-header-groups-field-separator", "|", "The separator string used for concatenating multiple group names in a groups header field's value")
	flagset.StringSliceVar(&o.Authentication.Token.Audiences, "auth-token-audiences", []string{}, "Comma-separated list of token audiences to accept. By default a token does not have to have any specific audience. It is recommended to set a specific audience.")

	//Authn OIDC flags
	flagset.StringVar(&o.Authentication.OIDC.IssuerURL, "oidc-issuer", "", "The URL of the OpenID issuer, only HTTPS scheme will be accepted. If set, it will be used to verify the OIDC JSON Web Token (JWT).")
	flagset.StringVar(&o.Authentication.OIDC.ClientID, "oidc-clientID", "", "The client ID for the OpenID Connect client, must be set if oidc-issuer-url is set.")
	flagset.StringVar(&o.Authentication.OIDC.GroupsClaim, "oidc-groups-claim", "groups", "Identifier of groups in JWT claim, by default set to 'groups'")
	flagset.StringVar(&o.Authentication.OIDC.UsernameClaim, "oidc-username-claim", "email", "Identifier of the user in JWT claim, by default set to 'email'")
	flagset.StringVar(&o.Authentication.OIDC.UsernamePrefix, "oidc-username-prefix", "", "If provided, the username will be prefixed with this value to prevent conflicts with other authentication strategies.")
	flagset.StringVar(&o.Authentication.OIDC.GroupsPrefix, "oidc-groups-prefix", "", "If provided, all groups will be prefixed with this value to prevent conflicts with other authentication strategies.")
	flagset.StringArrayVar(&o.Authentication.OIDC.SupportedSigningAlgs, "oidc-sign-alg", []string{"RS256"}, "Supported signing algorithms, default RS256")
	flagset.StringVar(&o.Authentication.OIDC.CAFile, "oidc-ca-file", "", "If set, the OpenID server's certificate will be verified by one of the authorities in the oidc-ca-file, otherwise the host's root CA set will be used.")

	flagset.StringVar(&o.ConfigFileName, "config-file", "", "Configuration file to configure kube-rbac-proxy.")
	flagset.StringSliceVar(&o.AllowPaths, "allow-paths", nil, "Comma-separated list of paths against which kube-rbac-proxy pattern-matches the incoming request. If the request doesn't match, kube-rbac-proxy responds with a 404 status code. If omitted, the incoming request path isn't checked. Cannot be used with --ignore-paths.")
	flagset.StringSliceVar(&o.IgnorePaths, "ignore-paths", nil, "Comma-separated list of paths against which kube-rbac-proxy pattern-matches the incoming request. If the requst matches, it will proxy the request without performing an authentication or authorization check. Cannot be used with --allow-paths.")

	//Kubeconfig flag
	flagset.StringVar(&o.KubeconfigLocation, "kubeconfig", "", "Path to a kubeconfig file, specifying how to connect to the API server. If unset, in-cluster configuration will be used")

	// proxy endpoints flag
	flagset.IntVar(&o.ProxyEndpointsPort, "proxy-endpoints-port", 0, "The port to securely serve proxy-specific endpoints (such as '/healthz'). Uses the host from the '--secure-listen-address'.")
}

func (o *ProxyOptions) Validate() []error {
	var errs []error

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

func (o *ProxyOptions) ApplyTo(c *server.KubeRBACProxyInfo) error {
	var err error

	c.UpstreamURL, err = url.Parse(o.Upstream)
	if err != nil {
		return fmt.Errorf("failed to parse upstream URL: %w", err)
	}

	if err := c.SetUpstreamTransport(o.UpstreamCAFile, o.UpstreamClientCertFile, o.UpstreamClientKeyFile); err != nil {
		return fmt.Errorf("failed to setup transport for upstream: %w", err)
	}

	if configFileName := o.ConfigFileName; len(configFileName) > 0 {
		c.Auth.Authorization, err = parseAuthorizationConfigFile(configFileName)
		if err != nil {
			return fmt.Errorf("failed to read the config file: %w", err)
		}
	}

	kubeconfig, err := initKubeConfig(o.KubeconfigLocation)
	if err != nil {
		return fmt.Errorf("failed to load kubeconfig: %w", err)
	}

	c.KubeClient, err = kubernetes.NewForConfig(kubeconfig)
	if err != nil {
		return fmt.Errorf("failed to instantiate Kubernetes client: %w", err)
	}

	if o.Authentication != nil {
		c.Auth.Authentication = o.Authentication
	}

	c.UpstreamForceH2C = o.UpstreamForceH2C
	c.AllowPaths = o.AllowPaths
	c.IgnorePaths = o.IgnorePaths

	return nil
}

type configfile struct {
	AuthorizationConfig *authz.Config `json:"authorization,omitempty"`
}

func parseAuthorizationConfigFile(filePath string) (*authz.Config, error) {
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

func initKubeConfig(kcLocation string) (*rest.Config, error) {
	if kcLocation != "" {
		kubeConfig, err := clientcmd.BuildConfigFromFlags("", kcLocation)
		if err != nil {
			return nil, fmt.Errorf("unable to build rest config based on provided path to kubeconfig file: %w", err)
		}
		return kubeConfig, nil
	}

	kubeConfig, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("cannot find Service Account in pod to build in-cluster rest config: %w", err)
	}

	return kubeConfig, nil
}
