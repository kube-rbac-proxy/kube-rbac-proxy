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

package app

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"path"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ghodss/yaml"
	"github.com/oklog/run"
	"github.com/spf13/cobra"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c" //nolint:staticcheck // deprecated in x/net >= v0.55.0, migration to http.Server.Protocols tracked in #446

	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authorization/union"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	certutil "k8s.io/client-go/util/cert"
	k8sapiflag "k8s.io/component-base/cli/flag"
	"k8s.io/component-base/cli/globalflag"
	"k8s.io/component-base/logs"
	"k8s.io/component-base/term"
	"k8s.io/component-base/version/verflag"
	"k8s.io/klog/v2"

	"github.com/brancz/kube-rbac-proxy/cmd/kube-rbac-proxy/app/options"
	"github.com/brancz/kube-rbac-proxy/pkg/authn"
	"github.com/brancz/kube-rbac-proxy/pkg/authz"
	"github.com/brancz/kube-rbac-proxy/pkg/filters"
	"github.com/brancz/kube-rbac-proxy/pkg/proxy"
	rbac_proxy_tls "github.com/brancz/kube-rbac-proxy/pkg/tls"
)

func NewKubeRBACProxyCommand() *cobra.Command {
	o := options.NewProxyRunOptions()
	cmd := &cobra.Command{
		Use: "kube-rbac-proxy",
		Long: `The kube-rbac-proxy is a small HTTP proxy for a single upstream
that can perform RBAC authorization against the Kubernetes API using SubjectAccessReview.`,

		// stop printing usage when the command errors
		SilenceUsage: true,
		PersistentPreRunE: func(*cobra.Command, []string) error {
			klog.SetLogFilter(&SanitizingFilter{})

			// silence client-go warnings.
			// kube-apiserver loopback clients should not log self-issued warnings.
			rest.SetDefaultWarningHandler(rest.NoWarnings{})
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			verflag.PrintAndExitIfRequested()

			fs := cmd.Flags()

			k8sapiflag.PrintFlags(fs)

			if err := o.Validate(); err != nil {
				return err
			}

			// set default options
			completedOptions, err := Complete(o)
			if err != nil {
				return err
			}

			return Run(completedOptions)
		},
		Args: func(cmd *cobra.Command, args []string) error {
			for _, arg := range args {
				if len(arg) > 0 {
					return fmt.Errorf("%q does not take any arguments, got %q", cmd.CommandPath(), args)
				}
			}
			return nil
		},
	}

	fs := cmd.Flags()
	namedFlagSets := o.Flags()
	verflag.AddFlags(namedFlagSets.FlagSet("global"))
	globalflag.AddGlobalFlags(namedFlagSets.FlagSet("global"), cmd.Name(), logs.SkipLoggingConfigurationFlags())
	for _, f := range namedFlagSets.FlagSets {
		fs.AddFlagSet(f)
	}

	cols, _, _ := term.TerminalSize(cmd.OutOrStdout())
	k8sapiflag.SetUsageAndHelpFunc(cmd, namedFlagSets, cols)

	return cmd
}

type configfile struct {
	AuthorizationConfig *authz.Config `json:"authorization,omitempty"`
}

type completedProxyRunOptions struct {
	insecureListenAddress string // DEPRECATED
	secureListenAddress   string
	proxyEndpointsPort    int

	upstreamURL      *url.URL
	upstreamForceH2C bool
	upstreamCABundle *x509.CertPool

	http2Disable              bool
	http2MaxConcurrentStreams uint32
	http2MaxSize              uint32

	auth *proxy.Config
	tls  *options.TLSConfig

	kubeClient *kubernetes.Clientset

	allowPaths  []string
	ignorePaths []string
}

func Complete(o *options.ProxyRunOptions) (*completedProxyRunOptions, error) {
	var err error
	completed := &completedProxyRunOptions{
		insecureListenAddress: o.InsecureListenAddress,
		secureListenAddress:   o.SecureListenAddress,
		proxyEndpointsPort:    o.ProxyEndpointsPort,
		upstreamForceH2C:      o.UpstreamForceH2C,

		allowPaths:  o.AllowPaths,
		ignorePaths: o.IgnorePaths,
	}

	completed.upstreamURL, err = url.Parse(o.Upstream)
	if err != nil {
		return nil, fmt.Errorf("failed to parse upstream URL: %w", err)
	}

	if upstreamCAPath := o.UpstreamCAFile; len(upstreamCAPath) > 0 {
		upstreamCAPEM, err := os.ReadFile(upstreamCAPath)
		if err != nil {
			return nil, err
		}

		upstreamCACertPool := x509.NewCertPool()
		if ok := upstreamCACertPool.AppendCertsFromPEM(upstreamCAPEM); !ok {
			return nil, errors.New("error parsing upstream CA certificate")
		}
		completed.upstreamCABundle = upstreamCACertPool
	}

	completed.auth = o.Auth
	completed.tls = o.TLS

	if configFileName := o.ConfigFileName; len(configFileName) > 0 {
		completed.auth.Authorization, err = parseAuthorizationConfigFile(configFileName)
		if err != nil {
			return nil, fmt.Errorf("failed to read the config file: %w", err)
		}
	}

	kubeconfig, err := initKubeConfig(o.KubeconfigLocation)
	if err != nil {
		return nil, fmt.Errorf("failed to load kubeconfig: %w", err)
	}

	if o.QPS > 0 {
		kubeconfig.QPS = o.QPS
	}
	if o.Burst > 0 {
		kubeconfig.Burst = o.Burst
	}

	completed.kubeClient, err = kubernetes.NewForConfig(kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate Kubernetes client: %w", err)
	}

	completed.http2Disable = o.HTTP2Disable
	completed.http2MaxConcurrentStreams = o.HTTP2MaxConcurrentStreams
	completed.http2MaxSize = o.HTTP2MaxSize

	return completed, nil
}

// newHTTP2Server returns a new *http2.Server on every call, because
// http2.ConfigureServer stores per-server state in it. With Go < 1.27 a
// shared one breaks graceful shutdown; with Go >= 1.27 golang.org/x/net
// panics when a shared one, or a copy of a configured one, is configured
// again (#450).
func newHTTP2Server(maxConcurrentStreams, maxSize uint32) *http2.Server {
	return &http2.Server{
		IdleTimeout:                  90 * time.Second,
		MaxConcurrentStreams:         maxConcurrentStreams,
		MaxReadFrameSize:             maxSize,
		MaxUploadBufferPerStream:     int32(maxSize),
		MaxUploadBufferPerConnection: int32(maxSize) * int32(maxConcurrentStreams),
	}
}

func Run(cfg *completedProxyRunOptions) error {
	var authenticator authenticator.Request
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// If OIDC configuration provided, use oidc authenticator
	if cfg.auth.Authentication.OIDC.IssuerURL != "" {
		oidcAuthenticator, err := authn.NewOIDCAuthenticator(ctx, cfg.auth.Authentication.OIDC)
		if err != nil {
			return fmt.Errorf("failed to instantiate OIDC authenticator: %w", err)
		}

		go oidcAuthenticator.Run(ctx)
		authenticator = oidcAuthenticator
	} else {
		//Use Delegating authenticator
		klog.Infof("Valid token audiences: %s", strings.Join(cfg.auth.Authentication.Token.Audiences, ", "))

		tokenClient := cfg.kubeClient.AuthenticationV1()
		delegatingAuthenticator, err := authn.NewDelegatingAuthenticator(tokenClient, cfg.auth.Authentication)
		if err != nil {
			return fmt.Errorf("failed to instantiate delegating authenticator: %w", err)
		}

		go delegatingAuthenticator.Run(ctx)
		authenticator = delegatingAuthenticator
	}

	sarClient := cfg.kubeClient.AuthorizationV1()
	sarAuthorizer, err := authz.NewSarAuthorizer(sarClient)
	if err != nil {
		return fmt.Errorf("failed to create sar authorizer: %w", err)
	}

	staticAuthorizer, err := authz.NewStaticAuthorizer(cfg.auth.Authorization.Static)
	if err != nil {
		return fmt.Errorf("failed to create static authorizer: %w", err)
	}

	authorizer := union.New(
		staticAuthorizer,
		sarAuthorizer,
	)

	upstreamTransport, err := initTransport(cfg.upstreamCABundle, cfg.tls.UpstreamClientCertFile, cfg.tls.UpstreamClientKeyFile)
	if err != nil {
		return fmt.Errorf("failed to set up upstream TLS connection: %w", err)
	}

	proxy := httputil.NewSingleHostReverseProxy(cfg.upstreamURL)
	proxy.Transport = upstreamTransport

	if cfg.upstreamForceH2C {
		// Force http/2 for connections to the upstream i.e. do not start with HTTP1.1 UPGRADE req to
		// initialize http/2 session.
		// See https://github.com/golang/go/issues/14141#issuecomment-219212895 for more context
		proxy.Transport = &http2.Transport{
			// Allow http schema. This doesn't automatically disable TLS
			AllowHTTP: true,
			// Do disable TLS.
			// In combination with the schema check above. We could enforce h2c against the upstream server
			DialTLS: func(netw, addr string, cfg *tls.Config) (net.Conn, error) {
				return net.Dial(netw, addr)
			},
		}
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		ignorePathFound := false
		for _, pathIgnored := range cfg.ignorePaths {
			ignorePathFound, err = path.Match(pathIgnored, req.URL.Path)
			if err != nil {
				http.Error(
					w,
					http.StatusText(http.StatusInternalServerError),
					http.StatusInternalServerError,
				)
				return
			}
			if ignorePathFound {
				break
			}
		}

		if !ignorePathFound {
			handlerFunc := proxy.ServeHTTP
			handlerFunc = filters.WithAuthHeaders(cfg.auth.Authentication.Header, handlerFunc)
			handlerFunc = filters.WithAuthorization(authorizer, cfg.auth.Authorization, handlerFunc)
			handlerFunc = filters.WithAuthentication(authenticator, cfg.auth.Authentication.Token.Audiences, handlerFunc)
			handlerFunc(w, req)

			return
		}

		proxy.ServeHTTP(w, req)
	})
	handler = filters.WithAllowPaths(cfg.allowPaths, handler)

	mux := http.NewServeMux()
	mux.Handle("/", handler)

	var gr run.Group
	{
		if cfg.secureListenAddress != "" {
			srv := &http.Server{
				Handler:   mux,
				TLSConfig: &tls.Config{},
			}

			if cfg.tls.CertFile == "" && cfg.tls.KeyFile == "" {
				klog.Info("Generating self signed cert as no cert is provided")
				host, err := os.Hostname()
				if err != nil {
					return fmt.Errorf("failed to retrieve hostname for self-signed cert: %w", err)
				}
				certBytes, keyBytes, err := certutil.GenerateSelfSignedCertKey(host, nil, nil)
				if err != nil {
					return fmt.Errorf("failed to generate self signed cert and key: %w", err)
				}
				cert, err := tls.X509KeyPair(certBytes, keyBytes)
				if err != nil {
					return fmt.Errorf("failed to load generated self signed cert and key: %w", err)
				}

				srv.TLSConfig.Certificates = []tls.Certificate{cert}
			} else {
				klog.Info("Reading certificate files")
				r, err := rbac_proxy_tls.NewCertReloader(cfg.tls.CertFile, cfg.tls.KeyFile, cfg.tls.ReloadInterval)
				if err != nil {
					return fmt.Errorf("failed to initialize certificate reloader: %w", err)
				}

				srv.TLSConfig.GetCertificate = r.GetCertificate

				ctx, cancel := context.WithCancel(context.Background())
				gr.Add(func() error {
					return r.Watch(ctx)
				}, func(error) {
					cancel()
				})
			}

			version, err := k8sapiflag.TLSVersion(cfg.tls.MinVersion)
			if err != nil {
				return fmt.Errorf("TLS version invalid: %w", err)
			}

			cipherSuiteIDs, err := k8sapiflag.TLSCipherSuites(cfg.tls.CipherSuites)
			if err != nil {
				return fmt.Errorf("failed to convert TLS cipher suite name to ID: %w", err)
			}

			srv.TLSConfig.CipherSuites = cipherSuiteIDs
			srv.TLSConfig.MinVersion = version
			srv.TLSConfig.ClientAuth = tls.RequestClientCert

			if cfg.http2Disable {
				// HTTP/2 is temporarily disabled due to CVE-2023-44487
				// Programs that must disable HTTP/2 can do so by setting
				// Transport.TLSNextProto (for clients) or Server.TLSNextProto
				// (for servers) to a non-nil, empty map.
				// https://pkg.go.dev/net/http
				srv.TLSNextProto = make(map[string]func(*http.Server, *tls.Conn, http.Handler))

				// For reference:
				// https://github.com/kubernetes/kubernetes/blob/de054fbf9422d778568946de21a48c7330a6c1b7/staging/src/k8s.io/apiserver/pkg/server/secure_serving.go#L55-L59
				srv.TLSConfig.NextProtos = []string{"http/1.1"}
			} else {
				if err := http2.ConfigureServer(srv, newHTTP2Server(cfg.http2MaxConcurrentStreams, cfg.http2MaxSize)); err != nil {
					return fmt.Errorf("failed to configure http2 server: %w", err)
				}
			}

			gr.Add(func() error {
				klog.Infof("Starting TCP socket on %v", cfg.secureListenAddress)
				l, err := net.Listen("tcp", cfg.secureListenAddress)
				if err != nil {
					return fmt.Errorf("failed to listen on secure address: %w", err)
				}
				defer l.Close()

				klog.Infof("Listening securely on %v", cfg.secureListenAddress)
				tlsListener := tls.NewListener(l, srv.TLSConfig)
				return srv.Serve(tlsListener)
			}, func(err error) {
				if err := srv.Shutdown(context.Background()); err != nil {
					klog.Errorf("failed to gracefully shutdown server: %+v", err)
				}
			})

			if cfg.proxyEndpointsPort != 0 {
				proxyEndpointsMux := http.NewServeMux()
				proxyEndpointsMux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) })

				proxyEndpointsSrv := &http.Server{
					Handler:   proxyEndpointsMux,
					TLSConfig: srv.TLSConfig.Clone(),
				}

				if cfg.http2Disable {
					// HTTP/2 is temporarily disabled due to CVE-2023-44487
					// Programs that must disable HTTP/2 can do so by setting
					// Transport.TLSNextProto (for clients) or Server.TLSNextProto
					// (for servers) to a non-nil, empty map.
					// https://pkg.go.dev/net/http
					proxyEndpointsSrv.TLSNextProto = make(map[string]func(*http.Server, *tls.Conn, http.Handler))
					// For reference:
					// https://github.com/kubernetes/kubernetes/blob/de054fbf9422d778568946de21a48c7330a6c1b7/staging/src/k8s.io/apiserver/pkg/server/secure_serving.go#L55-L59
					proxyEndpointsSrv.TLSConfig.NextProtos = []string{"http/1.1"}
				} else {
					if err := http2.ConfigureServer(proxyEndpointsSrv, newHTTP2Server(cfg.http2MaxConcurrentStreams, cfg.http2MaxSize)); err != nil {
						return fmt.Errorf("failed to configure http2 server: %w", err)
					}
				}

				gr.Add(func() error {
					host, _, err := net.SplitHostPort(cfg.secureListenAddress)
					if err != nil {
						return fmt.Errorf("failed to split %q into host and port: %w", cfg.secureListenAddress, err)
					}
					endpointsAddr := net.JoinHostPort(host, strconv.Itoa(cfg.proxyEndpointsPort))

					klog.Infof("Starting TCP socket on %v", endpointsAddr)
					proxyListener, err := net.Listen("tcp", endpointsAddr)
					if err != nil {
						return fmt.Errorf("failed to listen on secure address: %w", err)
					}
					defer proxyListener.Close()

					klog.Infof("Listening securely on %v for proxy endpoints", endpointsAddr)
					tlsListener := tls.NewListener(proxyListener, proxyEndpointsSrv.TLSConfig)
					return proxyEndpointsSrv.Serve(tlsListener)
				}, func(err error) {
					if err := proxyEndpointsSrv.Shutdown(context.Background()); err != nil {
						klog.Errorf("failed to gracefully shutdown proxy endpoints server: %+v", err)
					}
				})
			}
		}
	}
	{
		if cfg.insecureListenAddress != "" {
			srv := &http.Server{}
			if cfg.http2Disable {
				srv.Handler = mux
			} else {
				srv.Handler = h2c.NewHandler(mux, newHTTP2Server(cfg.http2MaxConcurrentStreams, cfg.http2MaxSize)) //nolint:staticcheck // see h2c import comment, #446
			}

			l, err := net.Listen("tcp", cfg.insecureListenAddress)
			if err != nil {
				return fmt.Errorf("failed to listen on insecure address: %w", err)
			}

			gr.Add(func() error {
				klog.Infof("Listening insecurely on %v", cfg.insecureListenAddress)
				return srv.Serve(l)
			}, func(err error) {
				if err := srv.Shutdown(context.Background()); err != nil {
					klog.Errorf("failed to gracefully shutdown server: %+v", err)
				}
				if err := l.Close(); err != nil {
					klog.Errorf("failed to gracefully close listener: %+v", err)
				}
			})
		}
	}
	{
		sig := make(chan os.Signal, 1)
		gr.Add(func() error {
			signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
			<-sig
			klog.Info("received interrupt, shutting down")
			return nil
		}, func(err error) {
			close(sig)
		})
	}

	if len(cfg.secureListenAddress) == 0 && len(cfg.insecureListenAddress) == 0 {
		return fmt.Errorf("no listen address provided")
	}

	if err := gr.Run(); err != nil {
		return fmt.Errorf("failed to run groups: %w", err)
	}

	return nil
}

// Returns intiliazed config, allows local usage (outside cluster) based on provided kubeconfig or in-cluter
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
