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

package static

import (
	"context"
	"errors"
	"testing"

	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
)

func TestStaticAuthorizer(t *testing.T) {
	tests := []struct {
		name   string
		config []StaticAuthorizationConfig

		shouldFail      bool
		shouldPass      []authorizer.Attributes
		shouldNoOpinion []authorizer.Attributes
	}{
		{
			name: "pathOnly",
			config: []StaticAuthorizationConfig{
				{Path: "/metrics", ResourceRequest: false},
			},
			shouldPass: []authorizer.Attributes{
				authorizer.AttributesRecord{User: &user.DefaultInfo{Name: "system:foo"}, Verb: "get", Path: "/metrics"},
				authorizer.AttributesRecord{User: &user.DefaultInfo{Name: "system:foo"}, Verb: "update", Path: "/metrics"},
			},
			shouldNoOpinion: []authorizer.Attributes{
				// wrong path
				authorizer.AttributesRecord{User: &user.DefaultInfo{Name: "system:foo"}, Verb: "get", Path: "/api"},
			},
		},
		{
			name: "pathAndVerb",
			config: []StaticAuthorizationConfig{
				{Path: "/metrics", Verb: "get"},
			},
			shouldPass: []authorizer.Attributes{
				authorizer.AttributesRecord{User: &user.DefaultInfo{Name: "system:foo"}, Verb: "get", Path: "/metrics"},
			},
			shouldNoOpinion: []authorizer.Attributes{
				// wrong path
				authorizer.AttributesRecord{User: &user.DefaultInfo{Name: "system:foo"}, Verb: "get", Path: "/api"},
				// wrong path
				authorizer.AttributesRecord{User: &user.DefaultInfo{Name: "system:foo"}, Verb: "update", Path: "/metrics"},
			},
		},
		{
			name: "nonResourceRequestSpecifiedTrue",
			config: []StaticAuthorizationConfig{
				{Path: "/metrics", Verb: "get", ResourceRequest: true},
			},
			shouldFail: true,
		},
		{
			name: "resourceRequestSpecifiedFalse",
			config: []StaticAuthorizationConfig{
				{Resource: "namespaces", Verb: "get", ResourceRequest: false},
			},
			shouldFail: true,
		},
		{
			name: "resourceRequestSpecifiedFalse",
			config: []StaticAuthorizationConfig{
				{Path: "/metrics", Verb: "get", ResourceRequest: false},
			},
			shouldPass: []authorizer.Attributes{
				authorizer.AttributesRecord{User: &user.DefaultInfo{Name: "system:foo"}, Verb: "get", Path: "/metrics", ResourceRequest: false},
			},
			shouldNoOpinion: []authorizer.Attributes{
				// wrong resourceRequest
				authorizer.AttributesRecord{User: &user.DefaultInfo{Name: "system:foo"}, Verb: "get", Path: "/metrics", ResourceRequest: true},
			},
		},
		{
			name: "resourceRequestUnspecified",
			config: []StaticAuthorizationConfig{
				{Path: "/metrics", Verb: "get"},
			},
			shouldPass: []authorizer.Attributes{
				authorizer.AttributesRecord{User: &user.DefaultInfo{Name: "system:foo"}, Verb: "get", Path: "/metrics", ResourceRequest: false},
			},
			shouldNoOpinion: []authorizer.Attributes{
				// Verb: get and ResourceRequest: true should be
				// mutually exclusive
				authorizer.AttributesRecord{User: &user.DefaultInfo{Name: "system:foo"}, Verb: "get", Path: "/metrics", ResourceRequest: true},
				// wrong path
				authorizer.AttributesRecord{User: &user.DefaultInfo{Name: "system:foo"}, Verb: "get", Path: "/api", ResourceRequest: true},
				// wrong path
				authorizer.AttributesRecord{User: &user.DefaultInfo{Name: "system:foo"}, Verb: "update", Path: "/metrics", ResourceRequest: false},
			},
		},
		{
			name: "resourceRequest",
			config: []StaticAuthorizationConfig{
				{Resource: "namespaces", Verb: "get", ResourceRequest: true},
			},
			shouldPass: []authorizer.Attributes{
				authorizer.AttributesRecord{User: &user.DefaultInfo{Name: "system:foo"}, Verb: "get", Resource: "namespaces", ResourceRequest: true},
				authorizer.AttributesRecord{Verb: "get", Resource: "namespaces", ResourceRequest: true},
			},
			shouldNoOpinion: []authorizer.Attributes{
				authorizer.AttributesRecord{Verb: "get", Resource: "services", ResourceRequest: true},
			},
		},
		{
			name: "resourceRequestSpecificUser",
			config: []StaticAuthorizationConfig{
				{User: UserConfig{Name: "system:foo"}, Resource: "namespaces", Verb: "get", ResourceRequest: true},
			},
			shouldPass: []authorizer.Attributes{
				authorizer.AttributesRecord{User: &user.DefaultInfo{Name: "system:foo"}, Verb: "get", Resource: "namespaces", ResourceRequest: true},
			},
			shouldNoOpinion: []authorizer.Attributes{
				authorizer.AttributesRecord{User: &user.DefaultInfo{Name: "system:bar"}, Verb: "get", Resource: "namespaces", ResourceRequest: true},
				authorizer.AttributesRecord{Verb: "get", Resource: "namespaces", ResourceRequest: true},
				authorizer.AttributesRecord{Verb: "get", Resource: "services", ResourceRequest: true},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth, err := NewStaticAuthorizer(tt.config)
			if failed := err != nil; tt.shouldFail != failed {
				t.Errorf("static authorizer creation expected to fail: %v, got %v, err: %v", tt.shouldFail, failed, err)
				return
			}

			for _, attr := range tt.shouldPass {
				if decision, _, _ := auth.Authorize(context.Background(), attr); decision != authorizer.DecisionAllow {
					t.Errorf("incorrectly restricted %v", attr)
				}
				if decision := auth.ConditionsAwareAuthorize(context.Background(), attr); !decision.IsAllow() {
					t.Errorf("incorrectly restricted by ConditionsAwareAuthorize %v", attr)
				}
			}

			for _, attr := range tt.shouldNoOpinion {
				if decision, _, _ := auth.Authorize(context.Background(), attr); decision != authorizer.DecisionNoOpinion {
					t.Errorf("incorrectly opinionated %v", attr)
				}
				if decision := auth.ConditionsAwareAuthorize(context.Background(), attr); !decision.IsNoOpinion() {
					t.Errorf("incorrectly opinionated by ConditionsAwareAuthorize %v", attr)
				}
			}
		})
	}
}

func TestStaticAuthorizerEvaluateConditions(t *testing.T) {
	auth, err := NewStaticAuthorizer(nil)
	if err != nil {
		t.Fatal(err)
	}

	decision, _, err := auth.EvaluateConditions(context.Background(), authorizer.ConditionsAwareDecision{}, nil)
	if decision != authorizer.DecisionDeny || !errors.Is(err, authorizer.ErrorConditionEvaluationNotSupported) {
		t.Errorf("want: %v, %v\nhave: %v, %v", authorizer.DecisionDeny, authorizer.ErrorConditionEvaluationNotSupported, decision, err)
	}
}
