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
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/brancz/kube-rbac-proxy/pkg/authorization"
	"github.com/brancz/kube-rbac-proxy/pkg/authorization/rewrite"
	"github.com/brancz/kube-rbac-proxy/pkg/authorization/static"
	"github.com/brancz/kube-rbac-proxy/pkg/server"
	"github.com/google/go-cmp/cmp"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	serverconfig "k8s.io/apiserver/pkg/server"
)

func Test_copyHeaderIfSet(t *testing.T) {
	tests := []struct {
		name           string
		headerKey      string
		inHeader       http.Header
		outHeader      http.Header
		expectedValues []string
	}{
		{
			name:      "src exists, dist does not",
			headerKey: "NONCanon",
			inHeader: http.Header{
				"Noncanon": []string{"here"},
			},
			expectedValues: []string{"here"},
		},
		{
			name:      "src exists, dist does too",
			headerKey: "NONCanon",
			inHeader: http.Header{
				"Noncanon": []string{"here"},
			},
			outHeader: http.Header{
				"Noncanon": []string{"there"},
			},
			expectedValues: []string{"there", "here"},
		},
		{
			name:      "src does not exist, dist does",
			headerKey: "nonCanon",
			outHeader: http.Header{
				"Noncanon": []string{"there"},
			},
			expectedValues: []string{"there"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inReq := http.Request{
				Header: tt.inHeader,
			}
			outReq := http.Request{
				Header: tt.outHeader,
			}

			copyHeaderIfSet(&inReq, &outReq, tt.headerKey)
			if gotVals := outReq.Header.Values(tt.headerKey); !reflect.DeepEqual(tt.expectedValues, gotVals) {
				t.Errorf("expected values: %v, got: %v", tt.expectedValues, gotVals)
			}
		})
	}
}

func TestProxyHandler(t *testing.T) {
	reqChan := make(chan http.Header, 1)
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		reqChan <- req.Header
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(testServer.Close)

	testServerURL, err := url.Parse(testServer.URL)
	if err != nil {
		t.Fatalf("failed to parse testserver URL")
	}

	config := &server.KubeRBACProxyInfo{
		UpstreamURL: testServerURL,
	}
	testHandler := setupProxyHandler(config)

	// the Golang implementation of an HTTP server passes the remote address of an
	// incoming connection into the HTTP request, we'll emulate this in the tests
	const (
		testRemoteIP   = "10.0.0.1"
		testRemoteAddr = testRemoteIP + ":10354"
	)

	tests := []struct {
		name       string
		header     http.Header
		wantHeader http.Header
	}{
		{
			name:   "no extra headers",
			header: make(http.Header),
			wantHeader: http.Header{
				"X-Forwarded-For":   []string{testRemoteIP},
				"X-Forwarded-Host":  []string{testServerURL.Host},
				"X-Forwarded-Proto": []string{"http"},
			},
		},
		{
			name: "X-Forwarded-For is set",
			header: http.Header{
				"X-Forwarded-For": []string{"10.0.0.2"},
			},
			wantHeader: http.Header{
				"X-Forwarded-For":   []string{"10.0.0.2, " + testRemoteIP},
				"X-Forwarded-Host":  []string{testServerURL.Host},
				"X-Forwarded-Proto": []string{"http"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testWriter := httptest.NewRecorder()
			req, err := http.NewRequest(http.MethodGet, testServer.URL, nil)
			if err != nil {
				t.Fatalf("failed to create an http request: %v", err)
			}
			req.Header = tt.header
			req.RemoteAddr = testRemoteAddr
			testHandler.ServeHTTP(testWriter, req)

			var gotHeaders http.Header
			select {
			case gotHeaders = <-reqChan:
			case <-time.After(5 * time.Second):
				t.Fatal("timeout: did not receive any response")
			}

			gotHeaders.Del("Content-Length")
			gotHeaders.Del("Accept-Encoding")
			gotHeaders.Del("Date")

			if !reflect.DeepEqual(gotHeaders, tt.wantHeader) {
				t.Errorf("got different headers than expected: %s", cmp.Diff(tt.wantHeader, gotHeaders))
			}
		})
	}
}

func TestSetupAuthorizer_AllowPathsWithRewriteAndStaticAuth(t *testing.T) {
	defaultKubeRBACProxyInfo := func() *server.KubeRBACProxyInfo {
		return &server.KubeRBACProxyInfo{
			AllowPaths: []string{"/metrics"},
			Authorization: &authorization.AuthzConfig{
				RewriteAttributesConfig: &rewrite.RewriteAttributesConfig{
					Rewrites: &rewrite.SubjectAccessReviewRewrites{
						ByHTTPHeader: &rewrite.HTTPHeaderRewriteConfig{
							Name: "x-namespace",
						},
					},
					ResourceAttributes: &rewrite.ResourceAttributes{
						Resource:  "namespaces",
						Namespace: "{{ .Value }}",
					},
				},
				Static: []static.StaticAuthorizationConfig{
					{
						User: static.UserConfig{
							Name: "system:serviceaccount:default:client-with-static",
						},
						ResourceRequest: true,
						Resource:        "namespaces",
						Namespace:       "kube-system",
						Verb:            "get",
					},
				},
			},
		}
	}
	mockDelegated := newMockDelegatedAuthorizer()

	krbInfo := defaultKubeRBACProxyInfo()

	errStatic := defaultKubeRBACProxyInfo()
	errStatic.Authorization.Static[0].ResourceRequest = false

	errPath := defaultKubeRBACProxyInfo()
	errPath.AllowPaths = []string{"/foo/*/metrics"}
	errPath.Authorization.Static[0].ResourceRequest = true

	for _, tt := range []struct {
		name             string
		user             string
		verb             string
		path             string
		headerValue      string
		krbInfo          *server.KubeRBACProxyInfo
		expectDecision   authorizer.Decision
		expectAuthzError bool
		expectSetupError bool
	}{
		{
			name:           "non-allow-path should be denied",
			user:           "system:serviceaccount:default:client-with-static",
			verb:           "get",
			path:           "/forbidden",
			expectDecision: authorizer.DecisionDeny,
		},
		{
			name:           "allow-path with static auth match should be allowed",
			user:           "system:serviceaccount:default:client-with-static",
			verb:           "get",
			path:           "/metrics",
			headerValue:    "kube-system",
			expectDecision: authorizer.DecisionAllow,
		},
		{
			name:           "allow-path with no static match but delegated match should be allowed",
			user:           "system:serviceaccount:default:client-with-rbac",
			verb:           "get",
			path:           "/metrics",
			headerValue:    "default",
			expectDecision: authorizer.DecisionAllow,
		},
		{
			name:           "allow-path with no static match and delegated deny should be denied",
			user:           "system:serviceaccount:default:client-explicitly-denied",
			verb:           "get",
			path:           "/metrics",
			headerValue:    "default",
			expectDecision: authorizer.DecisionDeny,
		},
		{
			name:           "allow-path with no static match and no delegated match should be denied",
			user:           "other-user",
			verb:           "get",
			path:           "/metrics",
			headerValue:    "other-namespace",
			expectDecision: authorizer.DecisionDeny, // The krp logic is to deny on no-opinion
		},
		{
			name:             "everything looks fine, except that we receive an error from the delegated authz",
			user:             "system:serviceaccount:default:client-always-fails",
			verb:             "get",
			path:             "/metrics",
			headerValue:      "default",
			expectDecision:   authorizer.DecisionDeny,
			expectAuthzError: true,
		},
		{
			name:             "broken static authorization config",
			user:             "system:serviceaccount:default:client-with-rbac",
			verb:             "get",
			path:             "/metrics",
			headerValue:      "default",
			krbInfo:          errStatic,
			expectAuthzError: false,
			expectSetupError: true,
		},
		{
			name:             "broken allowed-path authorization config",
			user:             "system:serviceaccount:default:client-with-rbac",
			verb:             "get",
			path:             "/foo/bar/metrics",
			krbInfo:          errPath,
			expectAuthzError: false,
			expectSetupError: true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if tt.krbInfo == nil {
				tt.krbInfo = krbInfo
			}

			authz, err := setupAuthorizer(tt.krbInfo, &serverconfig.AuthorizationInfo{
				Authorizer: mockDelegated,
			})
			if err != nil && !tt.expectSetupError {
				t.Fatalf("setupAuthorizer failed: %v", err)
			}
			if err == nil && tt.expectSetupError {
				t.Fatalf("setupAuthorizer should have failed, but didn't")
			}
			if tt.expectSetupError {
				return
			}

			req, _ := http.NewRequest("GET", "http://example.com"+tt.path, nil)
			if tt.headerValue != "" {
				req.Header.Set("x-namespace", tt.headerValue)
			}

			params := []string{}
			if tt.headerValue != "" {
				params = append(params, tt.headerValue)
			}
			ctx := rewrite.WithKubeRBACProxyParams(context.Background(), params)

			attr := authorizer.AttributesRecord{
				User:            &user.DefaultInfo{Name: tt.user},
				Verb:            tt.verb,
				Path:            tt.path,
				ResourceRequest: false,
			}

			decision, reason, err := authz.Authorize(ctx, &attr)
			if err != nil && !tt.expectAuthzError {
				t.Fatalf("Authorization failed: %v", err)
			}
			if err == nil && tt.expectAuthzError {
				t.Fatalf("Authorization should have failed, but didn't")
			}
			if decision != tt.expectDecision {
				t.Errorf("Expected decision %v, got %v (reason: %s)", tt.expectDecision, decision, reason)
			}
		})
	}
}

func TestSetupAuthorizer_IgnorePathsWithResourceAttributes(t *testing.T) {
	defaultKubeRBACProxyInfo := func() *server.KubeRBACProxyInfo {
		return &server.KubeRBACProxyInfo{
			IgnorePaths: []string{"/healthz"},
			Authorization: &authorization.AuthzConfig{
				RewriteAttributesConfig: &rewrite.RewriteAttributesConfig{
					ResourceAttributes: &rewrite.ResourceAttributes{
						Resource:  "namespaces",
						Namespace: "kube-system",
					},
				},
				Static: []static.StaticAuthorizationConfig{
					{
						User: static.UserConfig{
							Name: "system:serviceaccount:default:client-with-static",
						},
						ResourceRequest: true,
						Resource:        "namespaces",
						Namespace:       "kube-system",
						Verb:            "get",
					},
				},
			},
		}
	}

	mockDelegated := newMockDelegatedAuthorizer()

	krbInfo := defaultKubeRBACProxyInfo()

	errPath := defaultKubeRBACProxyInfo()
	errPath.IgnorePaths = []string{"/foo/*/metrics"}
	errPath.AllowPaths = nil
	errPath.Authorization.Rewrites = &rewrite.SubjectAccessReviewRewrites{
		ByHTTPHeader: &rewrite.HTTPHeaderRewriteConfig{
			Name: "x-namespace",
		},
	}
	errPath.Authorization.ResourceAttributes.Namespace = "{{ .Value }}"
	errPath.Authorization.Static[0].ResourceRequest = false

	for _, tt := range []struct {
		name             string
		user             string
		verb             string
		path             string
		krbInfo          *server.KubeRBACProxyInfo
		expectDecision   authorizer.Decision
		expectAuthzError bool
		expectSetupError bool
	}{
		{
			name:           "ignore-path should be allowed",
			user:           "any-user",
			verb:           "get",
			path:           "/healthz",
			expectDecision: authorizer.DecisionAllow,
		},
		{
			name:           "non-ignore-path with static auth match should be allowed",
			user:           "system:serviceaccount:default:client-with-static",
			verb:           "get",
			path:           "/metrics",
			expectDecision: authorizer.DecisionAllow,
		},
		{
			name:           "non-ignore-path with no static match but delegated match should be allowed",
			user:           "system:serviceaccount:default:client-with-rbac",
			verb:           "get",
			path:           "/metrics",
			expectDecision: authorizer.DecisionAllow,
		},
		{
			name:           "non-ignore-path with no static match and delegated denies should be denied",
			user:           "system:serviceaccount:default:client-explicitly-denied",
			verb:           "get",
			path:           "/metrics",
			expectDecision: authorizer.DecisionDeny,
		},
		{
			name:           "non-ignore-path with no static and no delegated match should be denied",
			user:           "unknown-user",
			verb:           "get",
			path:           "/metrics",
			expectDecision: authorizer.DecisionDeny,
		},
		{
			name:             "everything looks fine, except that we receive an error from the delegated authz",
			user:             "system:serviceaccount:default:client-always-fails",
			verb:             "get",
			path:             "/metrics",
			expectDecision:   authorizer.DecisionDeny,
			expectAuthzError: true,
		},
		{
			name:             "broken ignore path config",
			user:             "system:serviceaccount:default:client-with-rbac",
			verb:             "get",
			path:             "/foo/bar/metrics",
			krbInfo:          errPath,
			expectAuthzError: false,
			expectSetupError: true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			if tt.krbInfo == nil {
				tt.krbInfo = krbInfo
			}
			authz, err := setupAuthorizer(tt.krbInfo, &serverconfig.AuthorizationInfo{
				Authorizer: mockDelegated,
			})
			if err != nil && !tt.expectSetupError {
				t.Fatalf("setupAuthorizer failed: %v", err)
			}
			if err == nil && tt.expectSetupError {
				t.Fatalf("setupAuthorizer should have failed, but didn't")
			}
			if tt.expectSetupError {
				return
			}

			attr := authorizer.AttributesRecord{
				User:            &user.DefaultInfo{Name: tt.user},
				Verb:            tt.verb,
				Path:            tt.path,
				ResourceRequest: false,
			}

			decision, reason, err := authz.Authorize(ctx, &attr)
			if err != nil && !tt.expectAuthzError {
				t.Fatalf("Authorization failed: %v", err)
			}
			if err == nil && tt.expectAuthzError {
				t.Fatalf("Authorization should have failed, but didn't")
			}
			if decision != tt.expectDecision {
				t.Errorf("Expected decision %v, got %v (reason: %s)", tt.expectDecision, decision, reason)
			}
		})
	}
}

func TestSetupAuthorizer_NonResourceAttributesGenerator(t *testing.T) {
	defaultKubeRBACProxyInfo := func() *server.KubeRBACProxyInfo {
		return &server.KubeRBACProxyInfo{
			Authorization: &authorization.AuthzConfig{
				RewriteAttributesConfig: &rewrite.RewriteAttributesConfig{},
			},
		}
	}

	staticUser := defaultKubeRBACProxyInfo()
	staticUser.Authorization.Static = []static.StaticAuthorizationConfig{
		{
			User: static.UserConfig{
				Name: "system:serviceaccount:default:static-user",
			},
			Verb: "get",
			Path: "/static-path",
		},
	}

	mockDelegated := newMockDelegatedAuthorizer()

	tests := []struct {
		name             string
		krbInfo          *server.KubeRBACProxyInfo
		user             user.Info
		verb             string
		path             string
		expectDecision   authorizer.Decision
		expectReason     string
		expectAuthzError bool
	}{
		{
			name:           "non-resource path with allowed user",
			krbInfo:        defaultKubeRBACProxyInfo(),
			user:           &user.DefaultInfo{Name: "system:serviceaccount:default:client-with-rbac"},
			verb:           "get",
			path:           "/metrics",
			expectDecision: authorizer.DecisionAllow,
			expectReason:   "delegated allow",
		},
		{
			name:             "non-resource path with denied user",
			krbInfo:          defaultKubeRBACProxyInfo(),
			user:             &user.DefaultInfo{Name: "system:serviceaccount:default:client-always-fails"},
			verb:             "get",
			path:             "/healthz",
			expectDecision:   authorizer.DecisionDeny,
			expectReason:     "delegated deny with error",
			expectAuthzError: true,
		},
		{
			name:           "non-resource path with no opinion user",
			krbInfo:        defaultKubeRBACProxyInfo(),
			user:           &user.DefaultInfo{Name: "system:serviceaccount:default:unknown-user"},
			verb:           "post",
			path:           "/api/v1/proxy",
			expectDecision: authorizer.DecisionDeny,
			expectReason:   "Forbidden (user=, verb=post, resource=, subresource=): someone else should decide",
		},
		{
			name: "non-resource with static authorization configured",
			krbInfo: &server.KubeRBACProxyInfo{
				Authorization: &authorization.AuthzConfig{
					RewriteAttributesConfig: &rewrite.RewriteAttributesConfig{
						// No ResourceAttributes or Rewrites - should use NonResourceAttributesGenerator
					},
					Static: []static.StaticAuthorizationConfig{
						{
							User: static.UserConfig{
								Name: "system:serviceaccount:default:static-user",
							},
							Verb: "get",
							Path: "/static-path",
						},
					},
				},
			},
			user:           &user.DefaultInfo{Name: "system:serviceaccount:default:static-user"},
			verb:           "get",
			path:           "/static-path",
			expectDecision: authorizer.DecisionAllow,
			expectReason:   "static authorizer decision",
		},
		{
			name:             "non-resource path with denied user",
			krbInfo:          defaultKubeRBACProxyInfo(),
			user:             &user.DefaultInfo{Name: "system:serviceaccount:default:client-explicitly-denied"},
			verb:             "get",
			path:             "/metrics",
			expectDecision:   authorizer.DecisionDeny,
			expectReason:     "delegated deny without error",
			expectAuthzError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			delegatedAuthz := &serverconfig.AuthorizationInfo{
				Authorizer: mockDelegated,
			}

			authz, err := setupAuthorizer(tt.krbInfo, delegatedAuthz)
			if err != nil {
				t.Fatalf("setupAuthorizer() error = %v", err)
			}

			// Create attributes for non-resource request
			attrs := authorizer.AttributesRecord{
				User:            tt.user,
				Verb:            tt.verb,
				Path:            tt.path,
				ResourceRequest: false,
			}

			decision, reason, err := authz.Authorize(ctx, attrs)

			if err != nil && !tt.expectAuthzError {
				t.Errorf("Authorization failed unexpectedly: %v", err)
			}
			if err == nil && tt.expectAuthzError {
				t.Fatalf("Authorization should have failed, but didn't")
			}
			if decision != tt.expectDecision {
				t.Errorf("Expected decision %v, got %v (reason: %s)", tt.expectDecision, decision, reason)
			}
		})
	}
}

func newMockDelegatedAuthorizer() authorizer.Authorizer {
	return authorizer.AuthorizerFunc(
		func(ctx context.Context, a authorizer.Attributes) (authorizer.Decision, string, error) {
			if a.GetUser().GetName() == "system:serviceaccount:default:client-with-rbac" {
				return authorizer.DecisionAllow, "delegated allow", nil
			}
			if a.GetUser().GetName() == "system:serviceaccount:default:client-always-fails" {
				return authorizer.DecisionDeny, "delegated deny with error", fmt.Errorf("delegated error")
			}
			if a.GetUser().GetName() == "system:serviceaccount:default:client-explicitly-denied" {
				return authorizer.DecisionDeny, "delegated deny without error", nil
			}

			return authorizer.DecisionNoOpinion, "someone else should decide", nil
		},
	)
}
