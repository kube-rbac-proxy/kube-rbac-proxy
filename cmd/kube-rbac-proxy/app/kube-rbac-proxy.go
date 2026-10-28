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
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"time"

	"github.com/spf13/cobra"

	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	waitgroup "k8s.io/apimachinery/pkg/util/waitgroup"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/authorization/union"
	kubefilters "k8s.io/apiserver/pkg/endpoints/filters"
	"k8s.io/apiserver/pkg/endpoints/request"
	serverconfig "k8s.io/apiserver/pkg/server"
	"k8s.io/client-go/kubernetes/scheme"
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
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			klog.SetLogFilter(&SanitizingFilter{})
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			verflag.PrintAndExitIfRequested()

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

			// create the KubeRBACProxyConfig based on the completed options
			proxyCfg, err := completedOptions.ProxyConfig()
			if err != nil {
				return err
			}

			return Run(proxyCfg)
		},
		Args: cobra.NoArgs,
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
	errs = append(errs, o.OIDCOptions.Validate()...)
	errs = append(errs, o.ExtraValidate()...)

	return errs
}

func (opts *completedProxyRunOptions) ProxyConfig() (*server.KubeRBACProxyConfig, error) {
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

	if err := opts.ProxyOptions.ApplyTo(proxyConfig.KubeRBACProxyInfo, proxyConfig.DelegatingAuthentication, proxyConfig.SecureServing); err != nil {
		return nil, err
	}

	if err := opts.OIDCOptions.ApplyTo(proxyConfig.KubeRBACProxyInfo); err != nil {
		return nil, err
	}

	return proxyConfig, nil
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

func Run(cfg *server.KubeRBACProxyConfig) error {
	ctx := serverconfig.SetupSignalContext()

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

	proxy := setupProxyHandler(cfg.KubeRBACProxyInfo)

	handler := identityheaders.WithAuthHeaders(proxy, cfg.KubeRBACProxyInfo.UpstreamHeaders)
	handler = kubefilters.WithAuthorization(handler, authz, scheme.Codecs)
	handler = kubefilters.WithAuthentication(handler, authenticator, http.HandlerFunc(filters.UnauthorizedHandler), cfg.DelegatingAuthentication.APIAudiences, cfg.DelegatingAuthentication.RequestHeaderConfig)
	// passing an empty RequestInfoFactory results in attaching a non-resource RequestInfo to the context
	handler = kubefilters.WithRequestInfo(handler, &request.RequestInfoFactory{})
	handler = rewrite.WithKubeRBACProxyParamsHandler(handler, cfg.KubeRBACProxyInfo.Authorization.RewriteAttributesConfig)

	var wg waitgroup.SafeWaitGroup
	serverCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// listener for proxying HTTPS with authentication and authorization (on port --secure-port)
	mux := http.NewServeMux()
	mux.Handle("/", handler)

	if err := wg.Add(1); err != nil {
		return err
	}

	go func() {
		defer wg.Done()
		defer cancel()

		stoppedCh, listenerStoppedCh, err := cfg.SecureServing.Serve(mux, 10*time.Second, serverCtx.Done())
		if err != nil {
			klog.Errorf("%v", err)
			return
		}

		<-listenerStoppedCh
		<-stoppedCh
	}()

	if cfg.KubeRBACProxyInfo.ProxyEndpointsSecureServing != nil {
		// we need a second listener in order to serve proxy-specific endpoints
		// on a different port (--proxy-endpoints-port)
		proxyEndpointsMux := http.NewServeMux()
		proxyEndpointsMux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) })

		if err := wg.Add(1); err != nil {
			return err
		}

		go func() {
			defer wg.Done()
			defer cancel()

			stoppedCh, listenerStoppedCh, err := cfg.KubeRBACProxyInfo.ProxyEndpointsSecureServing.Serve(proxyEndpointsMux, 10*time.Second, serverCtx.Done())
			if err != nil {
				klog.Errorf("%v", err)
				return
			}

			<-listenerStoppedCh
			<-stoppedCh
		}()
	}

	wg.Wait()

	return nil
}

// setupAuthorizer runs different authorization checks based on the configuration.
func setupAuthorizer(krbInfo *server.KubeRBACProxyInfo, delegatedAuthz *serverconfig.AuthorizationInfo) (authorizer.Authorizer, error) {
	// pathAuthorizer is running before any other authorizer.
	// It works outside of the default authorizers.
	var pathAuthorizer authorizer.Authorizer
	var err error
	// AllowPaths are the only paths that are not denied.
	// IgnorePaths bypass all authorization checks.
	switch {
	case len(krbInfo.AllowPaths) > 0:
		pathAuthorizer, err = path.NewAllowedPathsAuthorizer(krbInfo.AllowPaths)
		if err != nil {
			return nil, fmt.Errorf("failed to create allow path authorizer: %w", err)
		}
	case len(krbInfo.IgnorePaths) > 0:
		pathAuthorizer, err = path.NewPassthroughAuthorizer(krbInfo.IgnorePaths)
		if err != nil {
			return nil, fmt.Errorf("failed to create ignore path authorizer: %w", err)
		}
	}

	// Delegated authorizers are running after the pathAuthorizer
	// and after the attributes have been rewritten.
	var delegated []union.NamedAuthorizer
	// Static authorization authorizes against a static file is ran before the SubjectAccessReview.
	if krbInfo.Authorization.Static != nil {
		staticAuthorizer, err := static.NewStaticAuthorizer(krbInfo.Authorization.Static)
		if err != nil {
			return nil, fmt.Errorf("failed to create static authorizer: %w", err)
		}

		delegated = append(delegated, union.NamedAuthorizer{AuthorizerName: "static", Authorizer: staticAuthorizer})
	}
	delegated = append(delegated, union.NamedAuthorizer{AuthorizerName: "delegating", Authorizer: delegatedAuthz.Authorizer})

	// Rewriting attributes such that they fit the given use-case.
	var attrsGenerator rewrite.AttributesGenerator
	switch {
	case krbInfo.Authorization.ResourceAttributes != nil && krbInfo.Authorization.Rewrites == nil:
		attrsGenerator = rewrite.NewResourceAttributesGenerator(
			krbInfo.Authorization.ResourceAttributes,
		)
	case krbInfo.Authorization.ResourceAttributes != nil && krbInfo.Authorization.Rewrites != nil:
		attrsGenerator = rewrite.NewTemplatedResourceAttributesGenerator(
			krbInfo.Authorization.ResourceAttributes,
		)
	default:
		attrsGenerator = &rewrite.NonResourceAttributesGenerator{}
	}

	authzUnion, err := union.New(delegated...)
	if err != nil {
		return nil, fmt.Errorf("failed to construct union of all the configured authorizers: %w", err)
	}
	rewritingAuthorizer := rewrite.NewRewritingAuthorizer(
		authzUnion,
		attrsGenerator,
	)

	if pathAuthorizer != nil {
		return union.New(
			union.NamedAuthorizer{AuthorizerName: "path", Authorizer: pathAuthorizer},
			union.NamedAuthorizer{AuthorizerName: "rewriting", Authorizer: rewritingAuthorizer},
		)
	}

	return rewritingAuthorizer, nil
}

func setupProxyHandler(cfg *server.KubeRBACProxyInfo) http.Handler {
	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			target := cfg.UpstreamURL
			pr.SetURL(target)
			pr.Out.Host = target.Host
			copyHeaderIfSet(pr.In, pr.Out, "X-Forwarded-For")
			pr.SetXForwarded()
		},
	}
	proxy.Transport = cfg.UpstreamTransport

	if cfg.UpstreamForceH2C {
		// Force http/2 for connections to the upstream i.e. do not start with HTTP1.1 UPGRADE req to
		// initialize http/2 session.
		var protocols http.Protocols
		protocols.SetUnencryptedHTTP2(true)
		proxy.Transport = &http.Transport{
			Protocols: &protocols,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
		}
	}

	return proxy
}

func copyHeaderIfSet(inReq *http.Request, outReq *http.Request, headerKey string) {
	src := inReq.Header.Values(headerKey)
	if src == nil {
		return
	}

	if outReq.Header == nil {
		outReq.Header = http.Header{}
	}

	for _, v := range src {
		outReq.Header.Add(headerKey, v)
	}
}
