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
package path_test

import (
	"context"
	"testing"

	"github.com/brancz/kube-rbac-proxy/pkg/authorization/path"
	"k8s.io/apiserver/pkg/authorization/authorizer"
)

func TestIgnorePath(t *testing.T) {
	requestPath := "/allowed/path/with/suffix"

	for _, tt := range []struct {
		name        string
		paths       []string
		decision    authorizer.Decision
		expectError bool
	}{
		{
			name:     "should authorize attributes, if path is identical",
			paths:    []string{requestPath},
			decision: authorizer.DecisionAllow,
		},
		{
			name:     "should authorize attributes, if path matches with postfix wildcard",
			paths:    []string{"/allowed/*"},
			decision: authorizer.DecisionAllow,
		},
		{
			name:     "should authorize attributes, if path matches with generous postfix wildcard",
			paths:    []string{"/a*"},
			decision: authorizer.DecisionAllow,
		},
		{
			name:     "shouldn't authorize attributes, if path matches without trailing slash",
			paths:    []string{"/allowed/path/with/suffix/*"},
			decision: authorizer.DecisionNoOpinion,
		},
		{
			name:        "should fail on initialization with infix wildcard",
			paths:       []string{"/allowed/*/withsuffix"},
			expectError: true,
		},
		{
			name:     "should not authorize attributes, if path doesn't match",
			paths:    []string{"/denied"},
			decision: authorizer.DecisionNoOpinion,
		},
		{
			name:     "should not authorize attributes, if no path specified",
			paths:    []string{},
			decision: authorizer.DecisionNoOpinion,
		},
		{
			name:     "should not authorize attributes, if no path specified",
			paths:    []string{"/all?wed/path/with/suffix"},
			decision: authorizer.DecisionNoOpinion,
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			authz, err := path.NewPassthroughAuthorizer(tt.paths)
			if err != nil && !tt.expectError {
				t.Fatalf("unexpected error: %v", err)
			}
			if err == nil && tt.expectError {
				t.Fatalf("expected error, got none")
			}
			if tt.expectError {
				return
			}

			decision, _, _ := authz.Authorize(context.Background(), authorizer.AttributesRecord{
				Path: requestPath,
			})

			if decision != tt.decision {
				t.Fatalf("expected decision %v, got %v", tt.decision, decision)
			}
		})
	}
}

func TestAllowPath(t *testing.T) {
	requestPath := "/allowed/path/with/suffix"

	for _, tt := range []struct {
		name        string
		paths       []string
		decision    authorizer.Decision
		expectError bool
	}{
		{
			name:     "should let attributes through to next authorizer, if path allowed",
			paths:    []string{requestPath},
			decision: authorizer.DecisionNoOpinion,
		},
		{
			name:     "should let attributes through to next authorizer with postfix wildcard",
			paths:    []string{"/allowed/path/*"},
			decision: authorizer.DecisionNoOpinion,
		},
		{
			name:        "should not let attributes through to next authorizer with infix wildcard",
			paths:       []string{"/allowed/*/with/suffix"},
			expectError: true,
		},
		{
			name:     "should not let attributes through to next authorizer, if path not allowed",
			paths:    []string{"/denied"},
			decision: authorizer.DecisionDeny,
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			authz, err := path.NewAllowedPathsAuthorizer(tt.paths)
			if err != nil && !tt.expectError {
				t.Fatalf("unexpected error: %v", err)
			}
			if err == nil && tt.expectError {
				t.Fatalf("expected error, got none")
			}
			if tt.expectError {
				return
			}

			decision, _, _ := authz.Authorize(context.Background(), authorizer.AttributesRecord{
				Path: requestPath,
			})

			if decision != tt.decision {
				t.Errorf("want: %d\nhave: %d\n", tt.decision, decision)
			}
		})
	}
}
