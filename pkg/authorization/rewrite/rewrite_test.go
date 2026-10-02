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

package rewrite

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/google/go-cmp/cmp"

	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/authorization/authorizerfactory"
)

func TestGeneratingAuthorizerAttributes(t *testing.T) {
	cases := []struct {
		desc     string
		config   *RewriteAttributesConfig
		req      *http.Request
		expected []authorizer.Attributes
	}{
		{
			"without resource attributes and rewrites",
			&RewriteAttributesConfig{},
			createRequest(nil, nil),
			[]authorizer.Attributes{
				authorizer.AttributesRecord{
					User:            nil,
					Verb:            "get",
					Namespace:       "",
					APIGroup:        "",
					APIVersion:      "",
					Resource:        "",
					Subresource:     "",
					Name:            "",
					ResourceRequest: false,
					Path:            "/accounts",
				},
			},
		},
		{
			"without rewrites config",
			&RewriteAttributesConfig{ResourceAttributes: &ResourceAttributes{Namespace: "tenant1", APIVersion: "v1", Resource: "namespace", Subresource: "metrics"}},
			createRequest(nil, nil),
			[]authorizer.Attributes{
				authorizer.AttributesRecord{
					User:            nil,
					Verb:            "get",
					Namespace:       "tenant1",
					APIGroup:        "",
					APIVersion:      "v1",
					Resource:        "namespace",
					Subresource:     "metrics",
					Name:            "",
					ResourceRequest: true,
				},
			},
		},
		{
			"with query param rewrites config",
			&RewriteAttributesConfig{
				Rewrites:           &SubjectAccessReviewRewrites{ByQueryParameter: &QueryParameterRewriteConfig{Name: "namespace"}},
				ResourceAttributes: &ResourceAttributes{Namespace: "{{ .Value }}", APIVersion: "v1", Resource: "namespace", Subresource: "metrics"},
			},
			createRequest(map[string][]string{"namespace": {"tenant1"}}, nil),
			[]authorizer.Attributes{
				authorizer.AttributesRecord{
					User:            nil,
					Verb:            "get",
					Namespace:       "tenant1",
					APIGroup:        "",
					APIVersion:      "v1",
					Resource:        "namespace",
					Subresource:     "metrics",
					Name:            "",
					ResourceRequest: true,
				},
			},
		},
		{
			"with query param rewrites config but missing URL query",
			&RewriteAttributesConfig{
				Rewrites:           &SubjectAccessReviewRewrites{ByQueryParameter: &QueryParameterRewriteConfig{Name: "namespace"}},
				ResourceAttributes: &ResourceAttributes{Namespace: "{{ .Value }}", APIVersion: "v1", Resource: "namespace", Subresource: "metrics"},
			},
			createRequest(nil, nil),
			nil,
		},
		{
			"with http header rewrites config",
			&RewriteAttributesConfig{
				Rewrites:           &SubjectAccessReviewRewrites{ByHTTPHeader: &HTTPHeaderRewriteConfig{Name: "namespace"}},
				ResourceAttributes: &ResourceAttributes{Namespace: "{{ .Value }}", APIVersion: "v1", Resource: "namespace", Subresource: "metrics"},
			},
			createRequest(nil, map[string][]string{"namespace": {"tenant1"}}),
			[]authorizer.Attributes{
				authorizer.AttributesRecord{
					User:            nil,
					Verb:            "get",
					Namespace:       "tenant1",
					APIGroup:        "",
					APIVersion:      "v1",
					Resource:        "namespace",
					Subresource:     "metrics",
					Name:            "",
					ResourceRequest: true,
				},
			},
		},
		{
			"with http header rewrites config and additional header",
			&RewriteAttributesConfig{
				Rewrites:           &SubjectAccessReviewRewrites{ByHTTPHeader: &HTTPHeaderRewriteConfig{Name: "namespace"}},
				ResourceAttributes: &ResourceAttributes{Namespace: "{{ .Value }}", APIVersion: "v1", Resource: "namespace", Subresource: "metrics"},
			},
			createRequest(nil, map[string][]string{"namespace": {"tenant1", "tenant2"}}),
			[]authorizer.Attributes{
				authorizer.AttributesRecord{
					User:            nil,
					Verb:            "get",
					Namespace:       "tenant1",
					APIGroup:        "",
					APIVersion:      "v1",
					Resource:        "namespace",
					Subresource:     "metrics",
					Name:            "",
					ResourceRequest: true,
				},
				authorizer.AttributesRecord{
					User:            nil,
					Verb:            "get",
					Namespace:       "tenant2",
					APIGroup:        "",
					APIVersion:      "v1",
					Resource:        "namespace",
					Subresource:     "metrics",
					Name:            "",
					ResourceRequest: true,
				},
			},
		},
		{
			"with http header rewrites config but missing header",
			&RewriteAttributesConfig{
				Rewrites:           &SubjectAccessReviewRewrites{ByQueryParameter: &QueryParameterRewriteConfig{Name: "namespace"}},
				ResourceAttributes: &ResourceAttributes{Namespace: "{{ .Value }}", APIVersion: "v1", Resource: "namespace", Subresource: "metrics"},
			},
			createRequest(nil, nil),
			nil,
		},
		{
			"with http header and query param rewrites config",
			&RewriteAttributesConfig{
				Rewrites: &SubjectAccessReviewRewrites{
					ByHTTPHeader:     &HTTPHeaderRewriteConfig{Name: "namespace"},
					ByQueryParameter: &QueryParameterRewriteConfig{Name: "namespace"},
				},
				ResourceAttributes: &ResourceAttributes{Namespace: "{{ .Value }}", APIVersion: "v1", Resource: "namespace", Subresource: "metrics"},
			},
			createRequest(
				map[string][]string{"namespace": {"tenant1"}},
				map[string][]string{"namespace": {"tenant2"}},
			),
			[]authorizer.Attributes{
				authorizer.AttributesRecord{
					User:            nil,
					Verb:            "get",
					Namespace:       "tenant1",
					APIGroup:        "",
					APIVersion:      "v1",
					Resource:        "namespace",
					Subresource:     "metrics",
					Name:            "",
					ResourceRequest: true,
				},
				authorizer.AttributesRecord{
					User:            nil,
					Verb:            "get",
					Namespace:       "tenant2",
					APIGroup:        "",
					APIVersion:      "v1",
					Resource:        "namespace",
					Subresource:     "metrics",
					Name:            "",
					ResourceRequest: true,
				},
			},
		},
	}

	for _, c := range cases {
		t.Run(c.desc, func(t *testing.T) {
			t.Log(c.req.URL.Query())
			n := rewritingAuthorizer{delegate: authorizerfactory.NewAlwaysAllowAuthorizer(), config: c.config}
			res := n.getKubeRBACProxyAuthzAttributes(
				WithKubeRBACProxyParams(context.Background(), requestToParams(c.config, c.req)),
				authorizer.AttributesRecord{
					Verb:            "get",
					Path:            "/accounts",
					ResourceRequest: false,
				})
			if !cmp.Equal(res, c.expected) {
				t.Errorf("Generated authorizer attributes are not correct. Expected %v, recieved %v", c.expected, res)
			}
		})
	}
}

func createRequest(queryParams, headers map[string][]string) *http.Request {
	r := httptest.NewRequest("GET", "/accounts", nil)
	if queryParams != nil {
		q := r.URL.Query()
		for key, values := range queryParams {
			for _, value := range values {
				q.Add(key, value)
			}
		}
		r.URL, _ = url.Parse(r.URL.String())
		r.URL.RawQuery = q.Encode()
	}
	for key, values := range headers {
		for _, value := range values {
			r.Header.Add(key, value)
		}
	}
	return r
}
