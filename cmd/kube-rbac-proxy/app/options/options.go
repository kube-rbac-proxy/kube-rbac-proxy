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
	"path"
	"time"

	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	k8sapiflag "k8s.io/component-base/cli/flag"
	"k8s.io/klog/v2"

	"github.com/brancz/kube-rbac-proxy/pkg/authn"
	"github.com/brancz/kube-rbac-proxy/pkg/authz"
	"github.com/brancz/kube-rbac-proxy/pkg/proxy"
	"github.com/spf13/pflag"
)

type ProxyRunOptions struct {
	ConfigFileName string

	InsecureListenAddress string
	SecureListenAddress   string
	ProxyEndpointsPort    int

	Upstream           string
	UpstreamForceH2C   bool
	UpstreamCAFile     string
	Auth               *proxy.Config
	TLS                *TLSConfig
	KubeconfigLocation string
	AllowPaths         []string
	IgnorePaths        []string

	HTTP2Disable              bool
	HTTP2MaxConcurrentStreams uint32
	HTTP2MaxSize              uint32

	QPS   float32
	Burst int

	flagSet *pflag.FlagSet
}

type TLSConfig struct {
	CertFile         string
	KeyFile          string
	MinVersion       string
	CipherSuites     []string
	CurvePreferences []int32
	ReloadInterval   time.Duration

	UpstreamClientCertFile string
	UpstreamClientKeyFile  string
}

func NewProxyRunOptions() *ProxyRunOptions {
	return &ProxyRunOptions{
		Auth: &proxy.Config{
			Authentication: &authn.AuthnConfig{
				X509:   &authn.X509Config{},
				Header: &authn.AuthnHeaderConfig{},
				OIDC:   &authn.OIDCConfig{},
				Token:  &authn.TokenConfig{},
			},
			Authorization: &authz.Config{},
		},
		TLS: &TLSConfig{},
	}
}

func (o *ProxyRunOptions) Flags() k8sapiflag.NamedFlagSets {
	namedFlagSets := k8sapiflag.NamedFlagSets{}
	flagset := namedFlagSets.FlagSet("kube-rbac-proxy")

	// kube-rbac-proxy flags
	flagset.StringVar(&o.InsecureListenAddress, "insecure-listen-address", "", "[DEPRECATED] The address the kube-rbac-proxy HTTP server should listen on.")
	flagset.StringVar(&o.SecureListenAddress, "secure-listen-address", "", "The address the kube-rbac-proxy HTTPs server should listen on.")
	flagset.StringVar(&o.Upstream, "upstream", "", "The upstream URL to proxy to once requests have successfully been authenticated and authorized.")
	flagset.BoolVar(&o.UpstreamForceH2C, "upstream-force-h2c", false, "Force h2c to communiate with the upstream. This is required when the upstream speaks h2c(http/2 cleartext - insecure variant of http/2) only. For example, go-grpc server in the insecure mode, such as helm's tiller w/o TLS, speaks h2c only")
	flagset.StringVar(&o.UpstreamCAFile, "upstream-ca-file", "", "The CA the upstream uses for TLS connection. This is required when the upstream uses TLS and its own CA certificate")
	flagset.StringVar(&o.ConfigFileName, "config-file", "", "Configuration file to configure kube-rbac-proxy.")
	flagset.StringSliceVar(&o.AllowPaths, "allow-paths", nil, "Comma-separated list of paths against which kube-rbac-proxy pattern-matches the incoming request. If the request doesn't match, kube-rbac-proxy responds with a 404 status code. If omitted, the incoming request path isn't checked. Cannot be used with --ignore-paths.")
	flagset.StringSliceVar(&o.IgnorePaths, "ignore-paths", nil, "Comma-separated list of paths against which kube-rbac-proxy pattern-matches the incoming request. If the requst matches, it will proxy the request without performing an authentication or authorization check. Cannot be used with --allow-paths.")
	flagset.IntVar(&o.ProxyEndpointsPort, "proxy-endpoints-port", 0, "The port to securely serve proxy-specific endpoints (such as '/healthz'). Uses the host from the '--secure-listen-address'.")

	// TLS flags
	flagset.StringVar(&o.TLS.CertFile, "tls-cert-file", "", "File containing the default x509 Certificate for HTTPS. (CA cert, if any, concatenated after server cert)")
	flagset.StringVar(&o.TLS.KeyFile, "tls-private-key-file", "", "File containing the default x509 private key matching --tls-cert-file.")
	flagset.StringVar(&o.TLS.MinVersion, "tls-min-version", "VersionTLS12", "Minimum TLS version supported. Value must match version names from https://golang.org/pkg/crypto/tls/#pkg-constants.")
	flagset.StringSliceVar(&o.TLS.CipherSuites, "tls-cipher-suites", nil, "Comma-separated list of cipher suites for the server. Values are from tls package constants (https://golang.org/pkg/crypto/tls/#pkg-constants). If omitted, the default Go cipher suites will be used")
	flagset.Int32SliceVar(&o.TLS.CurvePreferences, "tls-curve-preferences", nil, "Comma-separated list of numeric Go crypto/tls CurveID values, as the allowed key exchange mechanisms for the server. The supported values depend on the Go version used. See https://pkg.go.dev/crypto/tls#CurveID for values supported for each Go version. The order of the list is ignored, and key exchange mechanisms are chosen by Go from this list using an internal preference order. If omitted, the default Go curves will be used.")
	flagset.DurationVar(&o.TLS.ReloadInterval, "tls-reload-interval", time.Minute, "[DEPRECATED] The interval at which to watch for TLS certificate changes, by default set to 1 minute.")
	flagset.StringVar(&o.TLS.UpstreamClientCertFile, "upstream-client-cert-file", "", "If set, the client will be used to authenticate the proxy to upstream. Requires --upstream-client-key-file to be set, too.")
	flagset.StringVar(&o.TLS.UpstreamClientKeyFile, "upstream-client-key-file", "", "The key matching the certificate from --upstream-client-cert-file. If set, requires --upstream-client-cert-file to be set, too.")

	// Auth flags
	flagset.StringVar(&o.Auth.Authentication.X509.ClientCAFile, "client-ca-file", "", "If set, any request presenting a client certificate signed by one of the authorities in the client-ca-file is authenticated with an identity corresponding to the CommonName of the client certificate.")
	flagset.BoolVar(&o.Auth.Authentication.Header.Enabled, "auth-header-fields-enabled", false, "When set to true, kube-rbac-proxy adds auth-related fields to the headers of http requests sent to the upstream")
	flagset.StringVar(&o.Auth.Authentication.Header.UserFieldName, "auth-header-user-field-name", "x-remote-user", "The name of the field inside a http(2) request header to tell the upstream server about the user's name")
	flagset.StringVar(&o.Auth.Authentication.Header.GroupsFieldName, "auth-header-groups-field-name", "x-remote-groups", "The name of the field inside a http(2) request header to tell the upstream server about the user's groups")
	flagset.StringVar(&o.Auth.Authentication.Header.GroupSeparator, "auth-header-groups-field-separator", "|", "The separator string used for concatenating multiple group names in a groups header field's value")
	flagset.StringSliceVar(&o.Auth.Authentication.Token.Audiences, "auth-token-audiences", []string{}, "Comma-separated list of token audiences to accept. By default a token does not have to have any specific audience. It is recommended to set a specific audience.")

	//Authn OIDC flags
	flagset.StringVar(&o.Auth.Authentication.OIDC.IssuerURL, "oidc-issuer", "", "The URL of the OpenID issuer, only HTTPS scheme will be accepted. If set, it will be used to verify the OIDC JSON Web Token (JWT).")
	flagset.StringVar(&o.Auth.Authentication.OIDC.ClientID, "oidc-clientID", "", "The client ID for the OpenID Connect client, must be set if oidc-issuer-url is set.")
	flagset.StringVar(&o.Auth.Authentication.OIDC.GroupsClaim, "oidc-groups-claim", "groups", "Identifier of groups in JWT claim, by default set to 'groups'")
	flagset.StringVar(&o.Auth.Authentication.OIDC.UsernameClaim, "oidc-username-claim", "email", "Identifier of the user in JWT claim, by default set to 'email'")
	flagset.StringVar(&o.Auth.Authentication.OIDC.UsernamePrefix, "oidc-username-prefix", "", "If provided, the username will be prefixed with this value to prevent conflicts with other authentication strategies.")
	flagset.StringVar(&o.Auth.Authentication.OIDC.GroupsPrefix, "oidc-groups-prefix", "", "If provided, all groups will be prefixed with this value to prevent conflicts with other authentication strategies.")
	flagset.StringArrayVar(&o.Auth.Authentication.OIDC.SupportedSigningAlgs, "oidc-sign-alg", []string{"RS256"}, "Supported signing algorithms, default RS256")
	flagset.StringVar(&o.Auth.Authentication.OIDC.CAFile, "oidc-ca-file", "", "If set, the OpenID server's certificate will be verified by one of the authorities in the oidc-ca-file, otherwise the host's root CA set will be used.")

	//Kubeconfig flag
	flagset.StringVar(&o.KubeconfigLocation, "kubeconfig", "", "Path to a kubeconfig file, specifying how to connect to the API server. If unset, in-cluster configuration will be used")
	flagset.Float32Var(&o.QPS, "kube-api-qps", 0, "queries per second to the api, kube-client starts client-side throttling, when breached")
	flagset.IntVar(&o.Burst, "kube-api-burst", 0, "kube-api burst value; needed when kube-api-qps is set")

	// HTTP2 flags
	flagset.BoolVar(&o.HTTP2Disable, "http2-disable", false, "Disable HTTP/2 support")
	flagset.Uint32Var(&o.HTTP2MaxConcurrentStreams, "http2-max-concurrent-streams", 100, "The maximum number of concurrent streams per HTTP/2 connection.")
	flagset.Uint32Var(&o.HTTP2MaxSize, "http2-max-size", 256*1024, "The maximum number of bytes that the server will accept for frame size and buffer per stream in a HTTP/2 request.")

	// disabled flags
	o.addDisabledFlags(flagset)

	return namedFlagSets
}

func (o *ProxyRunOptions) Validate() error {
	var errs []error

	hasCerts := (o.TLS.CertFile != "") && (o.TLS.KeyFile != "")
	hasInsecureListenAddress := o.InsecureListenAddress != ""
	if !hasCerts || hasInsecureListenAddress {
		klog.Warning(`
==== Deprecation Warning ======================

Insecure listen address will be removed.
Using --insecure-listen-address won't be possible!

The ability to run kube-rbac-proxy without TLS certificates will be removed.
Not using --tls-cert-file and --tls-private-key-file won't be possible!

For more information, please go to https://github.com/brancz/kube-rbac-proxy/issues/187

===============================================

		`)
	}

	if o.TLS.ReloadInterval != time.Minute {
		klog.Warning(`
==== Deprecation Warning ======================

tls-reload-interval will be removed.
Using --tls-reload-interval won't be possible!

For more information, please go to https://github.com/brancz/kube-rbac-proxy/issues/196

===============================================
		`)

	}

	if len(o.AllowPaths) > 0 && len(o.IgnorePaths) > 0 {
		errs = append(errs, fmt.Errorf("cannot use --allow-paths and --ignore-paths together"))
	}

	for _, pathAllowed := range o.AllowPaths {
		_, err := path.Match(pathAllowed, "")
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to verify allow path: %s", pathAllowed))
		}
	}

	for _, pathIgnored := range o.IgnorePaths {
		_, err := path.Match(pathIgnored, "")
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to verify ignored path: %s", pathIgnored))
		}
	}

	// Removed upstream flags shouldn't be use
	if err := o.validateDisabledFlags(); err != nil {
		errs = append(errs, err)
	}

	return utilerrors.NewAggregate(errs)
}
