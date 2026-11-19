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

package identityheaders_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"reflect"
	"testing"

	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/request/bearertoken"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	kubefilters "k8s.io/apiserver/pkg/endpoints/filters"
	"k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/client-go/kubernetes/scheme"

	"github.com/brancz/kube-rbac-proxy/pkg/authn/identityheaders"
	"github.com/brancz/kube-rbac-proxy/pkg/filters"
)

func TestWithAuthHeaders(t *testing.T) {
	okHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	userKey := "User"
	userValue := "ben"
	groupKey := "Group"
	groupValue := "utzer"

	defaultUserHeader := map[string][]string{
		userKey:  {userValue},
		groupKey: {groupValue},
	}

	for _, tt := range []struct {
		name   string
		cfg    *identityheaders.AuthnHeaderConfig
		req    *http.Request
		header map[string][]string
	}{
		{
			name:   "should pass through",
			cfg:    &identityheaders.AuthnHeaderConfig{},
			req:    testRequest(t, withHeader(defaultUserHeader)),
			header: defaultUserHeader,
		},
		{
			name: "should set username in header",
			cfg: &identityheaders.AuthnHeaderConfig{
				UserFieldName:   userKey,
				GroupsFieldName: groupKey,
			},
			header: defaultUserHeader,
			req:    testRequest(t, withUserContext(userValue, []string{groupValue})),
		},
		{
			name: "should not pass client header",
			cfg: &identityheaders.AuthnHeaderConfig{
				UserFieldName:   userKey,
				GroupsFieldName: groupKey,
			},
			req:    testRequest(t, withHeader(map[string][]string{userKey: {"admin"}, groupKey: {"system:admin"}})),
			header: map[string][]string{},
		},
		{
			name: "should include group containing comma",
			cfg: &identityheaders.AuthnHeaderConfig{
				UserFieldName:   userKey,
				GroupsFieldName: groupKey,
			},
			req: testRequest(t, withUserContext(userValue, []string{groupValue, "group,with,comma", "anothergroup"})),
			header: map[string][]string{
				userKey:  {userValue},
				groupKey: {groupValue, "group,with,comma", "anothergroup"},
			},
		},
		{
			name: "should drop group containing group separator",
			cfg: &identityheaders.AuthnHeaderConfig{
				UserFieldName:   userKey,
				GroupsFieldName: groupKey,
				GroupSeparator:  ";",
			},
			req: testRequest(t, withUserContext(userValue, []string{groupValue, "group;with;separator", "anothergroup"})),
			header: map[string][]string{
				userKey:  {userValue},
				groupKey: {groupValue + ";" + "anothergroup"},
			},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			identityheaders.WithAuthHeaders(okHandler, tt.cfg).ServeHTTP(rec, tt.req)

			if len(tt.req.Header) != len(tt.header) {
				t.Errorf("want: %+v\nhave:%+v", tt.header, tt.req.Header)
				return
			}

			if len(tt.header) > 0 {
				for k, v := range tt.header {
					if !reflect.DeepEqual(tt.req.Header.Values(k), v) {
						t.Errorf("want: %v,\nhave: %v", v, tt.req.Header.Values(k))
					}
				}
			}
		})
	}
}

func TestProxyWithOIDCSupport(t *testing.T) {
	cfg := &identityheaders.AuthnHeaderConfig{
		UserFieldName:   "user",
		GroupsFieldName: "groups",
	}

	fakeUser := user.DefaultInfo{Name: "Foo Bar", Groups: []string{"foo-bars", "admins"}}
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

			handler := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
			handler = identityheaders.WithAuthHeaders(handler, cfg)
			handler = kubefilters.WithAuthorization(handler, v.authorizer, scheme.Codecs)
			handler = kubefilters.WithAuthentication(handler, authenticator, http.HandlerFunc(filters.UnauthorizedHandler), []string{}, nil)
			handler = kubefilters.WithRequestInfo(handler, &request.RequestInfoFactory{})

			handler.ServeHTTP(w, v.req)
			resp := w.Result()

			if resp.StatusCode != v.status {
				respBytes, _ := httputil.DumpResponse(resp, true)
				t.Logf("received response:\n%s", respBytes)
				t.Errorf("Expected response: %d received : %d", v.status, resp.StatusCode)
			}

			if v.verifyUser {
				user := v.req.Header.Get(cfg.UserFieldName)
				groups := v.req.Header.Values(cfg.GroupsFieldName)
				if user != fakeUser.GetName() {
					t.Errorf("User in the response header does not match authenticated user. Expected : %s, received : %s ", fakeUser.GetName(), user)
				}
				if !reflect.DeepEqual(groups, fakeUser.GetGroups()) {
					t.Errorf("Groups in the response header do not match authenticated user groups. Expected : %v, received : %v ", fakeUser.GetGroups(), groups)
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

func testRequest(t *testing.T, withOpts ...func(*http.Request) (*http.Request, error)) *http.Request {
	req, err := http.NewRequest(http.MethodGet, "http://example.com", nil)
	if err != nil {
		t.Fatal(err)
	}

	for _, opt := range withOpts {
		req, err = opt(req)
		if err != nil {
			t.Fatal(err)
		}
	}

	return req
}

func withHeader(header map[string][]string) func(*http.Request) (*http.Request, error) {
	return func(req *http.Request) (*http.Request, error) {
		for key, values := range header {
			for _, value := range values {
				req.Header.Add(key, value)
			}
		}

		return req, nil
	}
}

func withUserContext(userValue string, groupValues []string) func(*http.Request) (*http.Request, error) {
	return func(req *http.Request) (*http.Request, error) {
		return req.WithContext(
			request.WithUser(
				req.Context(),
				&user.DefaultInfo{
					Name:   userValue,
					Groups: groupValues,
				},
			),
		), nil
	}
}
