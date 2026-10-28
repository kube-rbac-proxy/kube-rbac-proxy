/*
Copyright 2023 the kube-rbac-proxy maintainers. All rights reserved.

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
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"
)

func TestRewriteParamsMiddleware(t *testing.T) {
	testCases := []struct {
		name     string
		rewrite  *SubjectAccessReviewRewrites
		request  *http.Request
		expected []string
	}{
		{
			name: "with query param rewrites config",
			rewrite: &SubjectAccessReviewRewrites{
				ByQueryParameter: &QueryParameterRewriteConfig{
					Name: "namespace",
				},
			},
			request: createRequest(withQueryParameters(map[string][]string{
				"namespace": {"default"},
			})),
			expected: []string{"default"},
		},
		{
			name: "with query param rewrites config but missing URL query",
			rewrite: &SubjectAccessReviewRewrites{
				ByQueryParameter: &QueryParameterRewriteConfig{
					Name: "namespace",
				},
			},
			request:  createRequest(),
			expected: nil,
		},
		{
			name: "with http header rewrites config",
			rewrite: &SubjectAccessReviewRewrites{
				ByHTTPHeader: &HTTPHeaderRewriteConfig{Name: "namespace"},
			},
			request: createRequest(withHeaderParameters(map[string][]string{
				"namespace": {"default"},
			})),
			expected: []string{"default"},
		},
		{
			name: "with http header rewrites config and additional header",
			rewrite: &SubjectAccessReviewRewrites{
				ByHTTPHeader: &HTTPHeaderRewriteConfig{Name: "namespace"},
			},
			request: createRequest(withHeaderParameters(map[string][]string{
				"namespace": {"default", "other"},
			})),
			expected: []string{"default", "other"},
		},
		{
			name: "with http header rewrites config but missing header",
			rewrite: &SubjectAccessReviewRewrites{
				ByQueryParameter: &QueryParameterRewriteConfig{Name: "namespace"},
			},
			request:  createRequest(),
			expected: nil,
		},
		{
			name: "with http header and query param rewrites config",
			rewrite: &SubjectAccessReviewRewrites{
				ByHTTPHeader:     &HTTPHeaderRewriteConfig{Name: "namespace"},
				ByQueryParameter: &QueryParameterRewriteConfig{Name: "namespace"},
			},
			request: createRequest(
				withHeaderParameters(map[string][]string{"namespace": {"default"}}),
				withQueryParameters(map[string][]string{"namespace": {"kube-system"}}),
			),
			expected: []string{"kube-system", "default"},
		},
		{
			name: "with query header rewrites config but header params",
			rewrite: &SubjectAccessReviewRewrites{
				ByQueryParameter: &QueryParameterRewriteConfig{Name: "namespace"},
			},
			request: createRequest(withHeaderParameters(map[string][]string{
				"namespace": {"default", "other"},
			})),
			expected: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			WithKubeRBACProxyParamsHandler(
				http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					values := getKubeRBACProxyParams(r.Context())
					if !reflect.DeepEqual(values, tc.expected) {
						t.Errorf("expected values to be %v, have %v", tc.expected, values)
					}
				}),
				&RewriteAttributesConfig{Rewrites: tc.rewrite},
			).ServeHTTP(nil, tc.request)
		})
	}
}

type requestOptions func(*http.Request)

func withQueryParameters(params map[string][]string) requestOptions {
	return func(r *http.Request) {
		q := r.URL.Query()
		for key, values := range params {
			for _, value := range values {
				q.Add(key, value)
			}
		}
		r.URL, _ = url.Parse(r.URL.String())
		r.URL.RawQuery = q.Encode()
	}
}

func withHeaderParameters(params map[string][]string) requestOptions {
	return func(r *http.Request) {
		for key, values := range params {
			for _, value := range values {
				r.Header.Add(key, value)
			}
		}
	}
}

func createRequest(opts ...requestOptions) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/accounts", nil)

	for _, opt := range opts {
		opt(r)
	}

	return r
}
