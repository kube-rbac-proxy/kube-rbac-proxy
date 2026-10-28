/*
Copyright 2017 Frederic Branczyk All rights reserved.

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

package authn

import (
	"context"
	"net/http"

	"k8s.io/apiserver/pkg/apis/apiserver"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/request/bearertoken"
	"k8s.io/apiserver/pkg/server/dynamiccertificates"
	"k8s.io/apiserver/plugin/pkg/authenticator/token/oidc"
)

type OIDCAuthenticator struct {
	dynamicClientCA      *dynamiccertificates.DynamicFileCAContent
	requestAuthenticator authenticator.Request
}

var (
	_ (authenticator.Request) = (*OIDCAuthenticator)(nil)
)

// NewOIDCAuthenticator returns OIDC authenticator
func NewOIDCAuthenticator(ctx context.Context, config *OIDCConfig) (*OIDCAuthenticator, error) {
	var (
		// Assign the [dynamiccertificates.CAContentProvider] interface only if the underlying concrete type is not nil.
		// Otherwise, the interface will get a type associated with it and will fail a nil check later on.
		// See https://github.com/brancz/kube-rbac-proxy/pull/361 for more details.
		dynamicCA         *dynamiccertificates.DynamicFileCAContent
		caContentProvider dynamiccertificates.CAContentProvider
	)

	if len(config.CAFile) > 0 { // if unset, the OIDC authenticator defaults to host's trust store
		var err error
		dynamicCA, err = dynamiccertificates.NewDynamicCAContentFromFile("oidc-ca", config.CAFile)
		if err != nil {
			return nil, err
		}
		caContentProvider = dynamicCA
	}

	tokenAuthenticator, err := oidc.New(ctx, oidc.Options{
		JWTAuthenticator: apiserver.JWTAuthenticator{
			Issuer: apiserver.Issuer{
				URL:       config.IssuerURL,
				Audiences: []string{config.RequiredAudience},
			},
			ClaimMappings: apiserver.ClaimMappings{
				Username: apiserver.PrefixedClaimOrExpression{
					Prefix: &config.UsernamePrefix,
					Claim:  config.UsernameClaim,
				},
				Groups: apiserver.PrefixedClaimOrExpression{
					Prefix: &config.GroupsPrefix,
					Claim:  config.GroupsClaim,
				},
			},
		},
		CAContentProvider:    caContentProvider,
		SupportedSigningAlgs: config.SupportedSigningAlgs,
	})
	if err != nil {
		return nil, err
	}

	return &OIDCAuthenticator{
		dynamicClientCA:      dynamicCA,
		requestAuthenticator: bearertoken.New(tokenAuthenticator),
	}, nil
}

func (o *OIDCAuthenticator) AuthenticateRequest(req *http.Request) (*authenticator.Response, bool, error) {
	return o.requestAuthenticator.AuthenticateRequest(req)
}

func (o *OIDCAuthenticator) Run(ctx context.Context) {
	if o.dynamicClientCA != nil {
		o.dynamicClientCA.Run(ctx, 1)
	}
}
