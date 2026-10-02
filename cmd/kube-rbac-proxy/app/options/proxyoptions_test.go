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

package options

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/brancz/kube-rbac-proxy/pkg/authz"
	"github.com/google/go-cmp/cmp"
)

func TestParseAuthorizationConfigFile(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "configfile.yaml")

	tests := []struct {
		name        string
		fileContent string
		want        *authz.Config
		wantErr     bool
	}{
		{
			name: "resources",
			fileContent: `authorization:
  rewrites:
    byQueryParameter:
      name: "namespace"
  resourceAttributes:
    resource: namespaces
    subresource: metrics
    namespace: "{{ .Value }}"
  static:
    - user:
        name: system:serviceaccount:default:default
      resourceRequest: true
      resource: namespaces
      subresource: metrics
      namespace: default
      verb: get`,
			want: &authz.Config{
				Rewrites: &authz.SubjectAccessReviewRewrites{
					ByQueryParameter: &authz.QueryParameterRewriteConfig{Name: "namespace"},
				},
				ResourceAttributes: &authz.ResourceAttributes{
					Resource:    "namespaces",
					Subresource: "metrics",
					Namespace:   "{{ .Value }}",
				},
				Static: []authz.StaticAuthorizationConfig{{
					User:            authz.UserConfig{Name: "system:serviceaccount:default:default"},
					ResourceRequest: true,
					Resource:        "namespaces",
					Subresource:     "metrics",
					Namespace:       "default",
					Verb:            "get",
				}},
			},
		},
		{
			name: "non-resources",
			fileContent: `authorization:
  static:
    - user:
        name: system:serviceaccount:default:default
      resourceRequest: false
      verb: get
      path: /metrics`,
			want: &authz.Config{
				Static: []authz.StaticAuthorizationConfig{{
					User:            authz.UserConfig{Name: "system:serviceaccount:default:default"},
					ResourceRequest: false,
					Verb:            "get",
					Path:            "/metrics",
				}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := os.WriteFile(filePath, []byte(tt.fileContent), 0o666); err != nil {
				t.Fatalf("failed to write file: %v", err)
			}

			got, err := parseAuthorizationConfigFile(filePath)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseAuthorizationConfigFile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseAuthorizationConfigFile(): %s", cmp.Diff(got, tt.want))
			}
		})
	}
}
