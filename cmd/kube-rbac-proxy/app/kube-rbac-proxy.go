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
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/oklog/run"
	"github.com/spf13/cobra"
	"golang.org/x/net/http2"

	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/authorization/union"
	kubefilters "k8s.io/apiserver/pkg/endpoints/filters"
	"k8s.io/apiserver/pkg/endpoints/request"
	serverconfig "k8s.io/apiserver/pkg/server"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	k8sapiflag "k8s.io/component-base/cli/flag"
	"k8s.io/component-base/cli/globalflag"
	"k8s.io/component-base/logs"
	"k8s.io/component-base/term"
	"k8s.io/component-base/version/verflag"
	"k8s.io/klog/v2"

	"github.com/brancz/kube-rbac-proxy/cmd/kube-rbac-proxy/app/options"
	"github.com/brancz/kube-rbac-proxy/pkg/authn"
	"github.com/brancz/kube-rbac-proxy/pkg/authn/identityheaders"
	"github.com/brancz/kube-rbac-proxy/pkg/authorization/path"
	"github.com/brancz/kube-rbac-proxy/pkg/authorization/rewrite"
	"github.com/brancz/kube-rbac-proxy/pkg/authorization/static"
	"github.com/brancz/kube-rbac-proxy/pkg/filters"
	"github.com/brancz/kube-rbac-proxy/pkg/server"
)

func NewKubeRBACProxyCommand() *cobra.Command {
	o := options.NewProxyRunOptions()
	cmd := &cobra.Command{
		Use: "kube-rbac-proxy",
		Long: `The kube-rbac-proxy is a small HTTP proxy for a single upstream
that can perform RBAC authorization against the Kubernetes API using SubjectAccessReview.`,

		SilenceUsage: true,
		PersistentPreRunE: func(*cobra.Command, []string) error {
			klog.SetLogFilter(&SanitizingFilter{})
			rest.SetDefaultWarningHandler(rest.NoWarnings{})
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			verflag.PrintAndExitIfRequested()

			// convert previous version of options
			if err := o.LegacyOptions.ConvertToNewOptions(
				o.SecureServing,
				o.DelegatingAuthentication,
				o.DelegatingAuthorization,
			); err != nil {
				return err
			}

			fs := cmd.Flags()
			k8sapiflag.PrintFlags(fs)

			// set default options
			completedOptions, err := Complete(o)
			if err != nil {
				return err
			}

			if errs := completedOptions.Validate(); len(errs) != 0 {
				return utilerrors.NewAggregate(errs)
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

type completedProxyRunOptions struct {
	*options.ProxyRunOptions
}

func (o *completedProxyRunOptions) Validate() []error {
	var errs []error
	errs = append(errs, o.SecureServing.Validate()...)
	errs = append(errs, o.DelegatingAuthentication.Validate()...)
	errs = append(errs, o.DelegatingAuthorization.Validate()...)
	errs = append(errs, o.ProxyOptions.Validate()...)
	errs = append(errs, o.LegacyOptions.Validate()...)

	return errs
}

// Complete sets defaults for the ProxyRunOptions.
// Should be called after the flags are parsed.
func Complete(o *options.ProxyRunOptions) (*completedProxyRunOptions, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve hostname for self-signed cert: %w", err)
	}

	if err := o.SecureServing.MaybeDefaultWithSelfSignedCerts(hostname, nil, nil); err != nil {
		return nil, fmt.Errorf("error creating self-signed certificates: %v", err)
	}

	if o.ProxyOptions.ProxyEndpointsPort != 0 {
		proxySecureServing := *o.SecureServing
		proxySecureServing.BindPort = o.ProxyOptions.ProxyEndpointsPort
		o.ProxySecureServing = &proxySecureServing
	}

	return &completedProxyRunOptions{ProxyRunOptions: o}, nil
}

func Run(opts *completedProxyRunOptions) error {
	cfg, err := createKubeRBACProxyConfig(opts)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var authenticator authenticator.Request
	// If OIDC configuration provided, use oidc authenticator
	if cfg.KubeRBACProxyInfo.OIDC.IssuerURL != "" {
		oidcAuthenticator, err := authn.NewOIDCAuthenticator(ctx, cfg.KubeRBACProxyInfo.OIDC)
		if err != nil {
			return fmt.Errorf("failed to instantiate OIDC authenticator: %w", err)
		}

		go oidcAuthenticator.Run(ctx)
		authenticator = oidcAuthenticator
	} else {
		authenticator = cfg.DelegatingAuthentication.Authenticator
	}

	authz, err := setupAuthorizer(cfg.KubeRBACProxyInfo, cfg.DelegatingAuthorization)
	if err != nil {
		return fmt.Errorf("failed to setup an authorizer: %v", err)
	}

	proxy := httputil.NewSingleHostReverseProxy(cfg.KubeRBACProxyInfo.UpstreamURL)
	proxy.Transport = cfg.KubeRBACProxyInfo.UpstreamTransport
	if cfg.KubeRBACProxyInfo.UpstreamForceH2C {
		proxy.Transport = &http2.Transport{
			AllowHTTP: true,
			DialTLSContext: func(ctx context.Context, netw, addr string, _ *tls.Config) (net.Conn, error) {
				dialer := &net.Dialer{
					Timeout:   30 * time.Second,
					KeepAlive: 30 * time.Second,
				}
				return dialer.DialContext(ctx, netw, addr)
			},
		}
	}

	handler := identityheaders.WithAuthHeaders(proxy, cfg.KubeRBACProxyInfo.UpstreamHeaders)
	handler = kubefilters.WithAuthorization(handler, authz, scheme.Codecs)
	handler = kubefilters.WithAuthentication(handler, authenticator, http.HandlerFunc(filters.UnauthorizedHandler), cfg.DelegatingAuthentication.APIAudiences, cfg.DelegatingAuthentication.RequestHeaderConfig)
	handler = kubefilters.WithRequestInfo(handler, &request.RequestInfoFactory{})
	handler = rewrite.WithKubeRBACProxyParamsHandler(handler, cfg.KubeRBACProxyInfo.Authorization.RewriteAttributesConfig)

	mux := http.NewServeMux()
	mux.Handle("/", handler)

	gr := &run.Group{}
	if len(opts.LegacyOptions.SecureListenAddress) > 0 {
		gr.Add(secureServerRunner(ctx, cfg.SecureServing, mux))

		if cfg.KubeRBACProxyInfo.ProxyEndpointsSecureServing != nil {
			proxyEndpointsMux := http.NewServeMux()
			proxyEndpointsMux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) })

			gr.Add(secureServerRunner(ctx, cfg.KubeRBACProxyInfo.ProxyEndpointsSecureServing, proxyEndpointsMux))
		}
	}
	{
		sig := make(chan os.Signal, 1)
		gr.Add(func() error {
			signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
			<-sig
			klog.Info("received interrupt, shutting down")
			return nil
		}, func(error) {
			close(sig)
		})
	}

	if err := gr.Run(); err != nil {
		return fmt.Errorf("failed to run groups: %w", err)
	}

	return nil
}

func createKubeRBACProxyConfig(opts *completedProxyRunOptions) (*server.KubeRBACProxyConfig, error) {
	proxyConfig := server.NewConfig()
	if err := opts.SecureServing.ApplyTo(&proxyConfig.SecureServing); err != nil {
		return nil, err
	}

	if opts.ProxySecureServing != nil {
		if err := opts.ProxySecureServing.ApplyTo(&proxyConfig.KubeRBACProxyInfo.ProxyEndpointsSecureServing); err != nil {
			return nil, err
		}
	}
	if err := opts.DelegatingAuthentication.ApplyTo(
		proxyConfig.DelegatingAuthentication,
		proxyConfig.SecureServing,
		nil,
	); err != nil {
		return nil, err
	}

	if err := opts.DelegatingAuthorization.ApplyTo(proxyConfig.DelegatingAuthorization); err != nil {
		return nil, err
	}

	if err := opts.ProxyOptions.ApplyTo(proxyConfig.KubeRBACProxyInfo, proxyConfig.DelegatingAuthentication); err != nil {
		return nil, err
	}

	if err := opts.LegacyOptions.ApplyTo(proxyConfig.KubeRBACProxyInfo); err != nil {
		return nil, err
	}

	return proxyConfig, nil
}

func secureServerRunner(
	ctx context.Context,
	config *serverconfig.SecureServingInfo,
	handler http.Handler,
) (func() error, func(error)) {
	serverStopCtx, serverCtxCancel := context.WithCancel(ctx)

	runner := func() error {
		stoppedCh, listenerStoppedCh, err := config.Serve(handler, 10*time.Second, serverStopCtx.Done())
		if err != nil {
			serverCtxCancel()
			return err
		}

		<-listenerStoppedCh
		<-stoppedCh
		return nil
	}

	interrupter := func(error) {
		serverCtxCancel()
	}

	return runner, interrupter
}

func setupAuthorizer(krbInfo *server.KubeRBACProxyInfo, delegatedAuthz *serverconfig.AuthorizationInfo) (authorizer.Authorizer, error) {
	staticAuthorizer, err := static.NewStaticAuthorizer(krbInfo.Authorization.Static)
	if err != nil {
		return nil, fmt.Errorf("failed to create static authorizer: %w", err)
	}

	baseAuthorizers, err := union.New(
		union.NamedAuthorizer{AuthorizerName: "static", Authorizer: staticAuthorizer},
		union.NamedAuthorizer{AuthorizerName: "delegating", Authorizer: delegatedAuthz.Authorizer},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create authorizer: %w", err)
	}

	var authz authorizer.Authorizer = rewrite.NewRewritingAuthorizer(
		baseAuthorizers,
		krbInfo.Authorization.RewriteAttributesConfig,
	)

	if allowPaths := krbInfo.AllowPaths; len(allowPaths) > 0 {
		authz, err = union.New(
			union.NamedAuthorizer{AuthorizerName: "allowPaths", Authorizer: path.NewAllowPathAuthorizer(allowPaths)},
			union.NamedAuthorizer{AuthorizerName: "krpAuthorizerNoAllowPaths", Authorizer: authz},
		)
		if err != nil {
			return nil, fmt.Errorf("failed to add allowPaths authorizer: %w", err)
		}
	}

	if ignorePaths := krbInfo.IgnorePaths; len(ignorePaths) > 0 {
		authz, err = union.New(
			union.NamedAuthorizer{AuthorizerName: "alwaysAllowPath", Authorizer: path.NewAlwaysAllowPathAuthorizer(ignorePaths)},
			union.NamedAuthorizer{AuthorizerName: "krpAuthorizerNoAlwaysAllowPath", Authorizer: authz},
		)
		if err != nil {
			return nil, fmt.Errorf("failed to add ignorePaths authorizer: %w", err)
		}
	}

	return authz, nil
}
