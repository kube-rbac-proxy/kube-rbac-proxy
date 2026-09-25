/*
Copyright 2022 the kube-rbac-proxy maintainers All rights reserved.

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
package filters_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path"
	"strings"
	"testing"

	"github.com/brancz/kube-rbac-proxy/pkg/authn"
	"github.com/brancz/kube-rbac-proxy/pkg/authz"
	"github.com/brancz/kube-rbac-proxy/pkg/filters"
	"github.com/brancz/kube-rbac-proxy/pkg/proxy"

	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/request/bearertoken"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/endpoints/request"
)

func TestWithAuthentication(t *testing.T) {
	audience := []string{"apiserver"}

	for _, tt := range []struct {
		name          string
		authenticator authenticator.Request
		audiences     []string
		status        int
	}{
		{
			name: "should return 200 ok on successful authn",
			authenticator: authenticatorFunc(func(req *http.Request) (*authenticator.Response, bool, error) {
				return &authenticator.Response{
					Audiences: []string{},
					User: &user.DefaultInfo{
						Name:   "Ben Utzer",
						UID:    "1337",
						Groups: []string{},
						Extra:  map[string][]string{},
					},
				}, true, nil
			}),
			status: http.StatusOK,
		},
		{
			name: "should put audiences into the ctx",
			authenticator: authenticatorFunc(func(req *http.Request) (*authenticator.Response, bool, error) {
				aud, ok := authenticator.AudiencesFrom(req.Context())
				if !ok {
					t.Errorf("want: %s\nhave: ok == false", audience)
				}
				if aud[0] != audience[0] {
					t.Errorf("want: %s\nhave: %s", audience, aud)
				}

				return nil, false, nil
			}),
			audiences: audience,
			status:    http.StatusUnauthorized,
		},
		{
			name: "should return unauthorized on err",
			authenticator: authenticatorFunc(func(req *http.Request) (*authenticator.Response, bool, error) {
				return nil, false, errors.New("this is an error")
			}),
			status: http.StatusUnauthorized,
		},
		{
			name: "should return unauthorized on authentication failure",
			authenticator: authenticatorFunc(func(req *http.Request) (*authenticator.Response, bool, error) {
				return nil, false, nil
			}),
			status: http.StatusUnauthorized,
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, "http://example.com", nil)
			if err != nil {
				t.Fatal(err)
			}
			rec := httptest.NewRecorder()
			filters.WithAuthentication(
				tt.authenticator,
				tt.audiences,
				func(w http.ResponseWriter, r *http.Request) {},
			).ServeHTTP(rec, req)

			res := rec.Result()
			if res.StatusCode != tt.status {
				t.Errorf("want: %d\nhave: %d\n", tt.status, res.StatusCode)
			}
		})
	}
}

type authenticatorFunc func(*http.Request) (*authenticator.Response, bool, error)

func (a authenticatorFunc) AuthenticateRequest(req *http.Request) (*authenticator.Response, bool, error) {
	return a(req)
}

func TestWithAuthorization(t *testing.T) {
	emptyRequest, err := http.NewRequest(http.MethodGet, "http://example.com", nil)
	if err != nil {
		t.Fatal(err)
	}

	userRequest := emptyRequest.WithContext(
		request.WithUser(emptyRequest.Context(), &user.DefaultInfo{}),
	)

	for _, tt := range []struct {
		name   string
		req    *http.Request
		authz  authorizer.Authorizer
		cfg    *authz.Config
		status int
	}{
		{
			name:   "should fail without user in context",
			req:    emptyRequest,
			authz:  nil,
			cfg:    &authz.Config{},
			status: http.StatusBadRequest,
		},
		{
			name:  "should fail without authorization attributes",
			req:   userRequest,
			authz: nil,
			cfg: &authz.Config{
				ResourceAttributes: &authz.ResourceAttributes{},
				Rewrites:           &authz.SubjectAccessReviewRewrites{},
			},
			status: http.StatusBadRequest,
		},
		{
			name: "should fail with error on authorization",
			req:  userRequest,
			authz: authorizer.AuthorizerFunc(func(ctx context.Context, attr authorizer.Attributes) (authorizer.Decision, string, error) {
				return authorizer.DecisionDeny, "there is an error", errors.New("this is an error")
			}),
			cfg:    &authz.Config{},
			status: http.StatusInternalServerError,
		},
		{
			name: "should fail with authorization failure",
			req:  userRequest,
			authz: authorizer.AuthorizerFunc(func(ctx context.Context, attr authorizer.Attributes) (authorizer.Decision, string, error) {
				return authorizer.DecisionDeny, "not authorized", nil
			}),
			cfg:    &authz.Config{},
			status: http.StatusForbidden,
		},
		{
			name: "should succeed with authorization",
			req:  userRequest,
			authz: authorizer.AuthorizerFunc(func(ctx context.Context, attr authorizer.Attributes) (authorizer.Decision, string, error) {
				return authorizer.DecisionAllow, "authorized!", nil
			}),
			cfg:    &authz.Config{},
			status: http.StatusOK,
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			filters.WithAuthorization(
				tt.authz,
				tt.cfg,
				func(w http.ResponseWriter, r *http.Request) {},
			).ServeHTTP(rec, tt.req)

			res := rec.Result()
			if tt.status != res.StatusCode {
				t.Errorf("want: %d\nhave: %d", tt.status, res.StatusCode)
			}
		})
	}
}

func TestWithAuthHeaders(t *testing.T) {
	okHandler := func(w http.ResponseWriter, r *http.Request) {}
	userKey := "User"
	userValue := "ben"
	groupKey := "Group"
	groupValue := "utzer"

	for _, tt := range []struct {
		name   string
		cfg    *authn.AuthnHeaderConfig
		ctx    context.Context
		header map[string][]string
	}{
		{
			name:   "should pass through",
			cfg:    &authn.AuthnHeaderConfig{Enabled: false},
			header: map[string][]string{},
		},
		{
			name: "should set username in header",
			cfg: &authn.AuthnHeaderConfig{
				Enabled:         true,
				UserFieldName:   userKey,
				GroupsFieldName: groupKey,
			},
			header: map[string][]string{
				userKey:  {userValue},
				groupKey: {groupValue},
			},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, "http://example.com", nil)
			if err != nil {
				t.Fatal(err)
			}
			req = req.WithContext(
				request.WithUser(
					req.Context(),
					&user.DefaultInfo{
						Name:   userValue,
						Groups: []string{groupValue},
					},
				),
			)

			rec := httptest.NewRecorder()
			filters.WithAuthHeaders(tt.cfg, okHandler).ServeHTTP(rec, req)

			if len(req.Header) != len(tt.header) {
				t.Errorf("want: %+v\nhave:%+v", tt.header, req.Header)
				return
			}

			if len(tt.header) > 0 {
				for k, v := range tt.header {
					if req.Header[k][0] != v[0] {
						t.Errorf("want: %s\nhave: %s", v[0], req.Header[k][0])
					}
				}
			}
		})
	}
}

func TestProxyWithOIDCSupport(t *testing.T) {
	cfg := proxy.Config{
		Authentication: &authn.AuthnConfig{
			OIDC: &authn.OIDCConfig{},
			Header: &authn.AuthnHeaderConfig{
				Enabled:         true,
				UserFieldName:   "user",
				GroupsFieldName: "groups",
			},
			Token: &authn.TokenConfig{},
		},
		Authorization: &authz.Config{},
	}

	fakeUser := user.DefaultInfo{Name: "Foo Bar", Groups: []string{"foo-bars"}}
	authenticator := fakeOIDCAuthenticator(t, &fakeUser)

	for _, v := range []testCase{
		{
			description: "Request with invalid Token should be authenticated and rejected with 401",
			given: given{
				req:        fakeJWTRequest("GET", "/accounts", "Bearer INVALID"),
				authorizer: fakeAuthorizer(authorizer.DecisionDeny),
			},
			expected: expected{
				status: http.StatusUnauthorized,
			},
		},
		{
			description: "Request with valid token should return 403 due to lack of permissions",
			given: given{
				req:        fakeJWTRequest("GET", "/accounts", "Bearer VALID"),
				authorizer: fakeAuthorizer(authorizer.DecisionDeny),
			},
			expected: expected{
				status: http.StatusForbidden,
			},
		},
		{
			description: "Request with valid token, should return 200 due to lack of permissions",
			given: given{
				req:        fakeJWTRequest("GET", "/accounts", "Bearer VALID"),
				authorizer: fakeAuthorizer(authorizer.DecisionAllow),
			},
			expected: expected{
				status:     http.StatusOK,
				verifyUser: true,
			},
		},
	} {

		t.Run(v.description, func(t *testing.T) {
			w := httptest.NewRecorder()

			handler := func(w http.ResponseWriter, r *http.Request) {}
			handler = filters.WithAuthHeaders(cfg.Authentication.Header, handler)
			handler = filters.WithAuthorization(v.authorizer, cfg.Authorization, handler)
			handler = filters.WithAuthentication(authenticator, cfg.Authentication.Token.Audiences, handler)

			handler(w, v.req)
			resp := w.Result()

			if resp.StatusCode != v.status {
				t.Errorf("Expected response: %d received : %d", v.status, resp.StatusCode)
			}

			if v.verifyUser {
				user := v.req.Header.Get(cfg.Authentication.Header.UserFieldName)
				groups := v.req.Header.Get(cfg.Authentication.Header.GroupsFieldName)
				if user != fakeUser.GetName() {
					t.Errorf("User in the response header does not match authenticated user. Expected : %s, received : %s ", fakeUser.GetName(), user)
				}
				if groups != strings.Join(fakeUser.GetGroups(), cfg.Authentication.Header.GroupSeparator) {
					t.Errorf("Groupsr in the response header does not match authenticated user groups. Expected : %s, received : %s ", fakeUser.GetName(), groups)
				}
			}
		})
	}
}

func fakeJWTRequest(method, path, token string) *http.Request {
	req := httptest.NewRequest(method, path, nil)
	req.Header.Add("Authorization", token)

	return req
}

func fakeOIDCAuthenticator(t *testing.T, fakeUser *user.DefaultInfo) authenticator.Request {

	auth := bearertoken.New(authenticator.TokenFunc(func(ctx context.Context, token string) (*authenticator.Response, bool, error) {
		if token != "VALID" {
			return nil, false, nil
		}
		return &authenticator.Response{User: fakeUser}, true, nil
	}))
	return auth
}

func fakeAuthorizer(decision authorizer.Decision) authorizer.Authorizer {
	return authorizer.AuthorizerFunc(func(ctx context.Context, attr authorizer.Attributes) (authorizer.Decision, string, error) {
		return decision, "", nil
	})
}

type given struct {
	req        *http.Request
	authorizer authorizer.Authorizer
}

type expected struct {
	status     int
	verifyUser bool
}

type testCase struct {
	given
	expected
	description string
}

func TestWithAuthHeadersStripsInboundWhenDisabled(t *testing.T) {
	cfg := &authn.AuthnHeaderConfig{
		Enabled:         false,
		UserFieldName:   "X-Remote-User",
		GroupsFieldName: "X-Remote-Groups",
	}

	var gotUser, gotGroups string
	inner := func(w http.ResponseWriter, r *http.Request) {
		gotUser = r.Header.Get("X-Remote-User")
		gotGroups = r.Header.Get("X-Remote-Groups")
	}

	req := httptest.NewRequest("GET", "/metrics", nil)
	req.Header.Set("X-Remote-User", "spoofed-admin")
	req.Header.Set("X-Remote-Groups", "system:masters")

	rec := httptest.NewRecorder()
	filters.WithAuthHeaders(cfg, inner).ServeHTTP(rec, req)

	if gotUser != "" {
		t.Errorf("inbound X-Remote-User not stripped when auth-headers disabled: got %q", gotUser)
	}
	if gotGroups != "" {
		t.Errorf("inbound X-Remote-Groups not stripped when auth-headers disabled: got %q", gotGroups)
	}
}

func TestWithAuthHeadersStripsExtraHeaders(t *testing.T) {
	cfg := &authn.AuthnHeaderConfig{
		Enabled:         true,
		UserFieldName:   "X-Remote-User",
		GroupsFieldName: "X-Remote-Groups",
	}

	var gotExtra string
	inner := func(w http.ResponseWriter, r *http.Request) {
		gotExtra = r.Header.Get("X-Remote-Extra-Scopes")
	}

	req := httptest.NewRequest("GET", "/metrics", nil)
	req.Header.Set("X-Remote-Extra-Scopes", "admin:full")

	rec := httptest.NewRecorder()
	filters.WithAuthHeaders(cfg, inner).ServeHTTP(rec, req)

	if gotExtra != "" {
		t.Errorf("inbound X-Remote-Extra-Scopes not stripped: got %q", gotExtra)
	}
}

func TestIgnorePathStripsAuthorizationHeader(t *testing.T) {
	var upstreamAuthHeader string
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamAuthHeader = r.Header.Get("Authorization")
	})

	handler := buildIgnorePathHandler([]string{"/healthz"}, &authn.AuthnHeaderConfig{
		UserFieldName:   "X-Remote-User",
		GroupsFieldName: "X-Remote-Groups",
	}, upstream)

	req := httptest.NewRequest("GET", "/healthz", nil)
	req.Header.Set("Authorization", "Bearer sa-token-prometheus-k8s")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if upstreamAuthHeader != "" {
		t.Errorf("Authorization header forwarded to upstream on ignore-path: got %q, want empty", upstreamAuthHeader)
	}
}

func TestIgnorePathStripsIdentityHeaders(t *testing.T) {
	var gotUser, gotGroups string
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUser = r.Header.Get("X-Remote-User")
		gotGroups = r.Header.Get("X-Remote-Groups")
	})

	handler := buildIgnorePathHandler([]string{"/healthz"}, &authn.AuthnHeaderConfig{
		UserFieldName:   "X-Remote-User",
		GroupsFieldName: "X-Remote-Groups",
	}, upstream)

	req := httptest.NewRequest("GET", "/healthz", nil)
	req.Header.Set("X-Remote-User", "system:admin")
	req.Header.Set("X-Remote-Groups", "system:masters")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if gotUser != "" {
		t.Errorf("X-Remote-User forwarded to upstream on ignore-path: got %q", gotUser)
	}
	if gotGroups != "" {
		t.Errorf("X-Remote-Groups forwarded to upstream on ignore-path: got %q", gotGroups)
	}
}

// buildIgnorePathHandler replicates the ignore-path handler logic from
// kube-rbac-proxy.go for isolated testing of header sanitization.
func buildIgnorePathHandler(ignorePaths []string, headerCfg *authn.AuthnHeaderConfig, upstream http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		cleaned := path.Clean(req.URL.Path)
		if cleaned != req.URL.Path {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		ignorePathFound := false
		for _, pathIgnored := range ignorePaths {
			found, err := path.Match(pathIgnored, cleaned)
			if err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			if found {
				ignorePathFound = true
				break
			}
		}

		if !ignorePathFound {
			http.NotFound(w, req)
			return
		}

		req.Header.Del("Authorization")
		req.Header.Del(headerCfg.UserFieldName)
		req.Header.Del(headerCfg.GroupsFieldName)
		for key := range req.Header {
			if strings.HasPrefix(strings.ToLower(key), "x-remote-extra-") {
				req.Header.Del(key)
			}
		}
		upstream.ServeHTTP(w, req)
	})
}
