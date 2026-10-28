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
	"reflect"
	"testing"

	"github.com/brancz/kube-rbac-proxy/pkg/authorization/rewrite"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
)

func TestDefaultAttributesGenerator(t *testing.T) {
	generator := &rewrite.NonResourceAttributesGenerator{}
	testCases := []struct {
		name       string
		attributes authorizer.AttributesRecord
		expected   authorizer.AttributesRecord
	}{
		{
			name: "basic HTTP attributes",
			attributes: authorizer.AttributesRecord{
				User:            &user.DefaultInfo{Name: "test user 0"},
				Verb:            "post",
				Namespace:       "",
				APIGroup:        "",
				APIVersion:      "",
				Resource:        "",
				Subresource:     "",
				Name:            "",
				ResourceRequest: false,
				Path:            "/api/v1/users",
			},
			expected: authorizer.AttributesRecord{
				User:            &user.DefaultInfo{Name: "test user 0"},
				Verb:            "post",
				Namespace:       "",
				APIGroup:        "",
				APIVersion:      "",
				Resource:        "",
				Subresource:     "",
				Name:            "",
				ResourceRequest: false,
				Path:            "/api/v1/users",
			},
		},
		{
			name: "basic attributes",
			attributes: authorizer.AttributesRecord{
				User:            &user.DefaultInfo{Name: "test user 1"},
				Verb:            "get",
				Namespace:       "default",
				APIGroup:        "",
				APIVersion:      "",
				Resource:        "pods",
				Subresource:     "",
				Name:            "",
				ResourceRequest: false,
				Path:            "/api/v1/namespaces/default/pods",
			},
			expected: authorizer.AttributesRecord{
				User:            &user.DefaultInfo{Name: "test user 1"},
				Verb:            "get",
				Namespace:       "",
				APIGroup:        "",
				APIVersion:      "",
				Resource:        "",
				Subresource:     "",
				Name:            "",
				ResourceRequest: false,
				Path:            "/api/v1/namespaces/default/pods",
			},
		},
		{
			name: "attributes with subresource",
			attributes: authorizer.AttributesRecord{
				User:            &user.DefaultInfo{Name: "test user 2"},
				Verb:            "update",
				Namespace:       "default",
				APIGroup:        "",
				APIVersion:      "",
				Resource:        "pods",
				Subresource:     "status",
				Name:            "pod1",
				ResourceRequest: false,
				Path:            "/api/v1/namespaces/default/pods/pod1/status",
			},
			expected: authorizer.AttributesRecord{
				User:            &user.DefaultInfo{Name: "test user 2"},
				Verb:            "update",
				Namespace:       "",
				APIGroup:        "",
				APIVersion:      "",
				Resource:        "",
				Subresource:     "",
				Name:            "",
				ResourceRequest: false,
				Path:            "/api/v1/namespaces/default/pods/pod1/status",
			},
		},
		{
			name: "resource request attributes",
			attributes: authorizer.AttributesRecord{
				User:            &user.DefaultInfo{Name: "test user 3"},
				Verb:            "get",
				Namespace:       "default",
				APIGroup:        "",
				APIVersion:      "",
				Resource:        "pods",
				Subresource:     "",
				Name:            "",
				ResourceRequest: true,
				Path:            "/api/v1/namespaces/default/pods",
			},
			expected: authorizer.AttributesRecord{
				User:            &user.DefaultInfo{Name: "test user 3"},
				Verb:            "get",
				Namespace:       "",
				APIGroup:        "",
				APIVersion:      "",
				Resource:        "",
				Subresource:     "",
				Name:            "",
				ResourceRequest: false,
				Path:            "/api/v1/namespaces/default/pods",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			generatedAttributes := generator.Generate(context.Background(), tc.attributes)

			if len(generatedAttributes) != 1 {
				t.Errorf("Expected 1 generated attribute, but got %d", len(generatedAttributes))
			}

			generatedRecord := generatedAttributes[0]
			if !reflect.DeepEqual(generatedRecord, tc.expected) {
				t.Errorf(
					"Generated attribute does not match expected attribute.\nHave: %+v,\nWant: %+v",
					generatedRecord, tc.expected,
				)
			}
		})
	}
}

func TestBoundAttributesGenerator(t *testing.T) {
	boundResource := &rewrite.ResourceAttributes{
		Namespace:  "kube-system",
		APIGroup:   "core",
		APIVersion: "v1",
		Resource:   "pods",
		Name:       "kube-apiserver",
	}

	defaultUser := &user.DefaultInfo{Name: "bound test user"}
	expectedAttributes := func(verb string) authorizer.Attributes {
		return authorizer.AttributesRecord{
			User:            defaultUser,
			Verb:            verb,
			Namespace:       boundResource.Namespace,
			APIGroup:        boundResource.APIGroup,
			APIVersion:      boundResource.APIVersion,
			Resource:        boundResource.Resource,
			Subresource:     boundResource.Subresource,
			Name:            boundResource.Name,
			ResourceRequest: true,
		}
	}

	testCases := []struct {
		name     string
		input    authorizer.Attributes
		expected authorizer.Attributes
	}{
		{
			name: "simple HTTP attributes",
			input: authorizer.AttributesRecord{
				User:            defaultUser,
				Verb:            "get",
				Namespace:       "default",
				APIGroup:        "",
				APIVersion:      "",
				Resource:        "pods",
				Subresource:     "",
				Name:            "",
				ResourceRequest: false,
				Path:            "/api/v1/namespaces/default/pods",
			},
			expected: expectedAttributes("get"),
		},
		{
			name: "normal k8s attributes",
			input: authorizer.AttributesRecord{
				User:            defaultUser,
				Verb:            "get",
				Namespace:       "default",
				APIGroup:        "core",
				APIVersion:      "v1",
				Resource:        "pods",
				Subresource:     "",
				Name:            "",
				ResourceRequest: true,
				Path:            "/api/v1/namespaces/default/pods",
			},
			expected: expectedAttributes("get"),
		},
		{
			name: "subresource attributes",
			input: authorizer.AttributesRecord{
				User:            defaultUser,
				Verb:            "update",
				Namespace:       "default",
				APIGroup:        "",
				APIVersion:      "",
				Resource:        "pods",
				Subresource:     "status",
				Name:            "pod1",
				ResourceRequest: false,
				Path:            "/api/v1/namespaces/default/pods/pod1/status",
			},
			expected: expectedAttributes("update"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			attrGen := rewrite.NewResourceAttributesGenerator(boundResource)
			results := attrGen.Generate(context.Background(), tc.input)
			if len(results) != 1 {
				t.Errorf("Expected 1 generated attribute, but got %d", len(results))
			}
			result := results[0]

			if !reflect.DeepEqual(result, tc.expected) {
				t.Errorf("Unexpected result. \nHave: %q, \nWant: %q", result, tc.expected)
			}
		})
	}
}

func TestRewritingAttributesGenerator(t *testing.T) {
	templateResource := &rewrite.ResourceAttributes{
		Namespace:  "{{ .Value }}",
		APIGroup:   "core",
		APIVersion: "v1",
		Resource:   "namespace",
	}

	defaultUser := &user.DefaultInfo{Name: "bound test user"}
	expectedAttributes := func(verb string, namespaces []string) []authorizer.Attributes {
		var attrs []authorizer.Attributes
		for _, namespace := range namespaces {
			attrs = append(attrs, authorizer.AttributesRecord{
				User:            defaultUser,
				Verb:            verb,
				Namespace:       namespace,
				APIGroup:        templateResource.APIGroup,
				APIVersion:      templateResource.APIVersion,
				Resource:        templateResource.Resource,
				Subresource:     templateResource.Subresource,
				Name:            templateResource.Name,
				ResourceRequest: true,
			})
		}

		return attrs
	}

	testCase := []struct {
		name   string
		params []string
		input  authorizer.Attributes
		output []authorizer.Attributes
	}{
		{
			name:   "with one param (hacked)",
			params: []string{"kube-system"},
			input: authorizer.AttributesRecord{
				User:            defaultUser,
				Verb:            "post",
				Namespace:       "admin",
				APIGroup:        "core",
				APIVersion:      "v1",
				Resource:        "pods",
				Subresource:     "trojan",
				Name:            "hack-pod",
				ResourceRequest: true,
				Path:            "/api/v1/namespaces/admin/pods/hack-pod",
			},
			output: expectedAttributes("post", []string{"kube-system"}),
		},
		{
			name:   "with no param",
			params: []string{},
			input: authorizer.AttributesRecord{
				User:            defaultUser,
				Verb:            "post",
				Namespace:       "admin",
				APIGroup:        "core",
				APIVersion:      "v1",
				Resource:        "pods",
				Subresource:     "trojan",
				Name:            "hack-pod",
				ResourceRequest: true,
				Path:            "/api/v1/namespaces/admin/pods",
			},
			output: nil,
		},
		{
			name:   "with multiple params",
			params: []string{"kube-system", "default"},
			input: authorizer.AttributesRecord{
				User:            defaultUser,
				Verb:            "get",
				Namespace:       "",
				APIGroup:        "",
				APIVersion:      "",
				Resource:        "",
				Subresource:     "",
				Name:            "",
				ResourceRequest: false,
				Path:            "/api/v1/namespaces/templated/pods/some-pod/metrics",
			},
			output: expectedAttributes("get", []string{"kube-system", "default"}),
		},
	}

	for _, tc := range testCase {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			ctx = rewrite.WithKubeRBACProxyParams(ctx, tc.params)
			attrGen := rewrite.NewTemplatedResourceAttributesGenerator(templateResource)
			results := attrGen.Generate(ctx, tc.input)
			if len(results) != len(tc.params) {
				t.Errorf(
					"Expected %d generated attributes, but have %d",
					len(tc.params), len(results),
				)
			}
		})
	}
}
