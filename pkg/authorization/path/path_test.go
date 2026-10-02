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

func TestAllowPath(t *testing.T) {
	validPath := "/allowed/path/withsuffix"

	for _, tt := range []struct {
		name        string
		paths       []string
		decision    authorizer.Decision
		expectError bool
	}{
		{
			name:     "should let request through if path allowed",
			paths:    []string{validPath},
			decision: authorizer.DecisionNoOpinion,
		},
		{
			name:     "should let request through if path allowed by wildcard",
			paths:    []string{"/allowed/*/withsuffix"},
			decision: authorizer.DecisionNoOpinion,
		},
		{
			name:     "should not let request through if path not allowed",
			paths:    []string{"/denied"},
			decision: authorizer.DecisionDeny,
		},
		{
			name:     "should let request through if no path specified",
			paths:    []string{},
			decision: authorizer.DecisionNoOpinion,
		},
		{
			name:        "should not let request through if path is non-sense",
			paths:       []string{"[]a]/*"},
			decision:    authorizer.DecisionNoOpinion,
			expectError: true,
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			authz := path.NewAllowPathAuthorizer(tt.paths)
			decision, _, err := authz.Authorize(context.Background(), authorizer.AttributesRecord{
				Path: validPath,
			})

			if (err != nil) != tt.expectError {
				t.Fatalf("expected error: %v; got: %v", tt.expectError, err)
			}

			if decision != tt.decision {
				t.Errorf("want: %d\nhave: %d\n", tt.decision, decision)
			}
		})
	}
}
