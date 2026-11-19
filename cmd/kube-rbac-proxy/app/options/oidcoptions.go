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
	"github.com/brancz/kube-rbac-proxy/pkg/server"
	"github.com/spf13/pflag"
)

type OIDCOptions struct {
	*authn.OIDCConfig
}

func (o *OIDCOptions) AddFlags(flagset *pflag.FlagSet) {
	// Authn OIDC flags
	flagset.StringVar(&o.IssuerURL, "oidc-issuer", "", "The URL of the OpenID issuer, only HTTPS scheme will be accepted. If set, it will be used to verify the OIDC JSON Web Token (JWT).")
	flagset.StringVar(&o.RequiredAudience, "oidc-required-audience", "", "The audience that must appear in all incoming tokens' `aud` claim. Must be set if `oidc-issuer` is configured.")
	flagset.StringVar(&o.UsernameClaim, "oidc-username-claim", "email", "Identifier of the user in JWT claim, by default set to 'email'")
	flagset.StringVar(&o.GroupsClaim, "oidc-groups-claim", "groups", "Identifier of groups in JWT claim, by default set to 'groups'")
	flagset.StringVar(&o.UsernamePrefix, "oidc-username-prefix", "", "If provided, the username will be prefixed with this value to prevent conflicts with other authentication strategies.")
	flagset.StringVar(&o.GroupsPrefix, "oidc-groups-prefix", "", "If provided, all groups will be prefixed with this value to prevent conflicts with other authentication strategies.")
	flagset.StringArrayVar(&o.SupportedSigningAlgs, "oidc-sign-alg", []string{"RS256"}, "Supported signing algorithms, default RS256")
	flagset.StringVar(&o.CAFile, "oidc-ca-file", "", "If set, the OpenID server's certificate will be verified by one of the authorities in the oidc-ca-file, otherwise the host's root CA set will be used.")

}

func (o *OIDCOptions) Validate() []error {
	var errs []error
	if len(o.IssuerURL) == 0 {
		return errs
	}

	if len(o.RequiredAudience) == 0 {
		errs = append(errs, fmt.Errorf("oidc-required-audience must be set when `oidc-issuer` is configured"))
	}

	return errs
}

func (o *OIDCOptions) ApplyTo(c *server.KubeRBACProxyInfo) error {
	c.OIDC = o.OIDCConfig
	return nil
}
