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
package rewrite_test

import (
	"context"
	"errors"
	"testing"

	"github.com/brancz/kube-rbac-proxy/pkg/authorization/rewrite"
	"k8s.io/apiserver/pkg/authorization/authorizer"
)

func TestRewritingAuthorizer(t *testing.T) {
	simpleAttributesGenerator := &fakeAttributesGenerator{
		generate: func(context.Context, authorizer.Attributes) []authorizer.Attributes {
			return []authorizer.Attributes{
				authorizer.AttributesRecord{
					Namespace:  "kube-system",
					APIGroup:   "core",
					APIVersion: "v1",
					Resource:   "pods",
					Name:       "kube-apiserver",
				},
			}
		},
	}

	rewriteAttributesGenerator := &fakeAttributesGenerator{
		generate: func(context.Context, authorizer.Attributes) []authorizer.Attributes {
			return []authorizer.Attributes{
				authorizer.AttributesRecord{
					Namespace:  "kube-system",
					APIGroup:   "core",
					APIVersion: "v1",
					Resource:   "pods",
					Name:       "kube-apiserver",
				},
				authorizer.AttributesRecord{
					Namespace:  "default",
					APIGroup:   "core",
					APIVersion: "v1",
					Resource:   "pods",
					Name:       "kube-apiserver",
				},
			}
		},
	}

	alternatingFunc := func() func(context.Context, authorizer.Attributes) (authorizer.Decision, string, error) {
		count := 0

		return func(context.Context, authorizer.Attributes) (authorizer.Decision, string, error) {
			count = count + 1
			if count%2 != 0 {
				return authorizer.DecisionAllow, "", nil
			}

			return authorizer.DecisionDeny, "", nil
		}
	}

	testCases := []struct {
		name     string
		delegate authorizer.Authorizer
		attrGen  rewrite.AttributesGenerator
		expected authorizer.Decision
	}{
		{
			name:     "nil attributes",
			delegate: nil,
			attrGen: &fakeAttributesGenerator{
				generate: func(context.Context, authorizer.Attributes) []authorizer.Attributes {
					return nil
				},
			},
			expected: authorizer.DecisionDeny,
		},
		{
			name:     "empty attributes",
			delegate: nil,
			attrGen: &fakeAttributesGenerator{
				generate: func(context.Context, authorizer.Attributes) []authorizer.Attributes {
					return []authorizer.Attributes{}
				},
			},
			expected: authorizer.DecisionDeny,
		},
		{
			name: "simple allow",
			delegate: fakeAuthorizer(func(context.Context, authorizer.Attributes) (authorizer.Decision, string, error) {
				return authorizer.DecisionAllow, "", nil
			}),
			attrGen:  simpleAttributesGenerator,
			expected: authorizer.DecisionAllow,
		},
		{
			name: "simple deny",
			delegate: fakeAuthorizer(func(context.Context, authorizer.Attributes) (authorizer.Decision, string, error) {
				return authorizer.DecisionDeny, "", nil
			}),
			attrGen:  simpleAttributesGenerator,
			expected: authorizer.DecisionDeny,
		},
		{
			name: "simple don't care",
			delegate: fakeAuthorizer(func(context.Context, authorizer.Attributes) (authorizer.Decision, string, error) {
				return authorizer.DecisionNoOpinion, "", nil
			}),
			attrGen:  simpleAttributesGenerator,
			expected: authorizer.DecisionDeny,
		},
		{
			name: "simple error",
			delegate: fakeAuthorizer(func(context.Context, authorizer.Attributes) (authorizer.Decision, string, error) {
				reason := "some error"

				// shouldn't happen, but just in case
				return authorizer.DecisionAllow, reason, errors.New(reason)
			}),
			attrGen:  simpleAttributesGenerator,
			expected: authorizer.DecisionDeny,
		},
		{
			name: "rewrite AND all authorizers allow",
			delegate: fakeAuthorizer(func(context.Context, authorizer.Attributes) (authorizer.Decision, string, error) {
				return authorizer.DecisionAllow, "", nil
			}),
			attrGen:  rewriteAttributesGenerator,
			expected: authorizer.DecisionAllow,
		},
		{
			name:     "rewrite AND and authorizers alternate allow/deny",
			delegate: fakeAuthorizer(alternatingFunc()),
			attrGen:  rewriteAttributesGenerator,
			expected: authorizer.DecisionDeny,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			authorizer := rewrite.NewRewritingAuthorizer(tc.delegate, tc.attrGen)
			decision, _, _ := authorizer.Authorize(context.Background(), nil)
			if tc.expected != decision {
				t.Errorf("expected decision %v, got %v", tc.expected, decision)
			}
		})
	}
}

type fakeAttributesGenerator struct {
	generate func(context.Context, authorizer.Attributes) []authorizer.Attributes
}

func (f *fakeAttributesGenerator) Generate(ctx context.Context, attrs authorizer.Attributes) []authorizer.Attributes {
	return f.generate(ctx, attrs)
}

func fakeAuthorizer(authorize func(context.Context, authorizer.Attributes) (authorizer.Decision, string, error)) authorizer.Authorizer {
	return authorizer.AuthorizerFunc(func(ctx context.Context, attr authorizer.Attributes) (authorizer.Decision, string, error) {
		return authorize(ctx, attr)
	})
}
