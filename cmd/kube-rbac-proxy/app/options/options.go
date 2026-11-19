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

	"github.com/brancz/kube-rbac-proxy/pkg/authn"
	"github.com/brancz/kube-rbac-proxy/pkg/authn/identityheaders"
	genericoptions "k8s.io/apiserver/pkg/server/options"
	kubeflags "k8s.io/component-base/cli/flag"
)

// ProxyRunOptions bundles both generic server run options from upstream, the
// proxy-specific options and legacy options.
type ProxyRunOptions struct {
	SecureServing *genericoptions.SecureServingOptions
	// ProxySecureServing are options for the proxy endpoints, they will be copied
	// from the above with a changed port.
	ProxySecureServing *genericoptions.SecureServingOptions

	DelegatingAuthentication *genericoptions.DelegatingAuthenticationOptions
	DelegatingAuthorization  *genericoptions.DelegatingAuthorizationOptions

	ProxyOptions *ProxyOptions
	OIDCOptions  *OIDCOptions
}

func NewProxyRunOptions() *ProxyRunOptions {
	// unset the always allow paths, the proxy has its own authorizer for these
	delegatingAuthz := genericoptions.NewDelegatingAuthorizationOptions()
	delegatingAuthz.AlwaysAllowPaths = nil

	return &ProxyRunOptions{
		SecureServing:            genericoptions.NewSecureServingOptions(),
		DelegatingAuthentication: genericoptions.NewDelegatingAuthenticationOptions(),
		DelegatingAuthorization:  delegatingAuthz,

		ProxyOptions: &ProxyOptions{
			UpstreamHeader: &identityheaders.AuthnHeaderConfig{},
		},
		OIDCOptions: &OIDCOptions{
			OIDCConfig: &authn.OIDCConfig{},
		},
	}
}

func (o *ProxyRunOptions) Flags() kubeflags.NamedFlagSets {
	namedFlagSets := kubeflags.NamedFlagSets{}

	o.SecureServing.AddFlags(namedFlagSets.FlagSet("secure serving"))
	o.DelegatingAuthentication.AddFlags(namedFlagSets.FlagSet("delegating authentication"))
	o.DelegatingAuthorization.AddFlags(namedFlagSets.FlagSet("delegating authorization"))
	o.ProxyOptions.AddFlags(namedFlagSets.FlagSet("proxy"))
	o.OIDCOptions.AddFlags(namedFlagSets.FlagSet("OIDC"))

	// we have our own handling of always allow paths
	_ = namedFlagSets.FlagSets["delegating authorization"].MarkHidden("authorization-always-allow-paths")

	return namedFlagSets
}

func (o *ProxyRunOptions) ExtraValidate() []error {
	var errs []error

	if len(o.DelegatingAuthorization.AlwaysAllowPaths) > 0 {
		errs = append(errs, fmt.Errorf("--authorization-always-allow-paths cannot be set, see --allow-paths instead"))
	}

	return errs
}
