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

package server

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"

	serverconfig "k8s.io/apiserver/pkg/server"
	"k8s.io/apiserver/pkg/server/dynamiccertificates"
	"k8s.io/client-go/kubernetes"

	"github.com/brancz/kube-rbac-proxy/pkg/authn"
	"github.com/brancz/kube-rbac-proxy/pkg/authz"
	"github.com/brancz/kube-rbac-proxy/pkg/proxy"
)

// KubeRBACProxyConfig stores the configuration for running the proxy server and kube-rbac-proxy specific configuration.
type KubeRBACProxyConfig struct {
	SecureServing *serverconfig.SecureServingInfo

	KubeRBACProxyInfo *KubeRBACProxyInfo
}

// KubeRBACProxyInfo stores the kube-rbac-proxy specific configuration and serving configuration for the proxy endpoints server.
type KubeRBACProxyInfo struct {
	InsecureListenAddress string // DEPRECATED

	UpstreamURL       *url.URL
	UpstreamForceH2C  bool
	UpstreamTransport http.RoundTripper

	ProxyEndpointsSecureServing *serverconfig.SecureServingInfo

	Auth *proxy.Config

	KubeClient *kubernetes.Clientset

	AllowPaths  []string
	IgnorePaths []string
}

func NewConfig() *KubeRBACProxyConfig {
	return &KubeRBACProxyConfig{
		SecureServing: &serverconfig.SecureServingInfo{},
		KubeRBACProxyInfo: &KubeRBACProxyInfo{
			Auth: &proxy.Config{
				Authentication: &authn.AuthnConfig{
					X509:   &authn.X509Config{},
					Header: &authn.AuthnHeaderConfig{},
					OIDC:   &authn.OIDCConfig{},
					Token:  &authn.TokenConfig{},
				},
				Authorization: &authz.Config{},
			},
		},
	}
}

// SetUpstreamTransport configures the transport to use when talking to upstream
// with a CA and/or client cert/key pair.
// An empty string on `upstreamCAPath` means system cert pool will be used.
func (i *KubeRBACProxyInfo) SetUpstreamTransport(upstreamCAPath, upstreamClientCertPath, upstreamClientKeyPath string) error {
	transport := http.DefaultTransport.(*http.Transport).Clone()

	if len(upstreamCAPath) > 0 {
		upstreamCAPEM, err := os.ReadFile(upstreamCAPath)
		if err != nil {
			return fmt.Errorf("failed to read the upstream CA file: %w", err)
		}

		upstreamCACertPool := x509.NewCertPool()
		if ok := upstreamCACertPool.AppendCertsFromPEM(upstreamCAPEM); !ok {
			return errors.New("error parsing upstream CA certificate")
		}

		transport.ForceAttemptHTTP2 = false
		transport.TLSClientConfig = &tls.Config{RootCAs: upstreamCACertPool}
	}

	if len(upstreamClientCertPath) > 0 {
		certKeyPair, err := tls.LoadX509KeyPair(upstreamClientCertPath, upstreamClientKeyPath)
		if err != nil {
			return fmt.Errorf("failed to read upstream client cert/key: %w", err)
		}

		transport.ForceAttemptHTTP2 = false
		if transport.TLSClientConfig == nil {
			transport.TLSClientConfig = &tls.Config{}
		}
		transport.TLSClientConfig.Certificates = []tls.Certificate{certKeyPair}
	}

	i.UpstreamTransport = transport
	return nil
}

// GetClientCAProvider returns the provider which dynamically loads and reloads the client CA certificate.
func (i *KubeRBACProxyConfig) GetClientCAProvider() (dynamiccertificates.CAContentProvider, error) {
	clientCAFile := i.KubeRBACProxyInfo.Auth.Authentication.X509.ClientCAFile
	if len(clientCAFile) == 0 {
		return nil, nil
	}

	return dynamiccertificates.NewDynamicCAContentFromFile("client-ca-bundle", clientCAFile)
}
