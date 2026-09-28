/*
Copyright 2026 The kube-rbac-proxy maintainers. All rights reserved.

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

package e2e

import (
	"fmt"
	"testing"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/brancz/kube-rbac-proxy/test/kubetest"
)

func testAllowPathHeaderRewriteStaticRBAC(client kubernetes.Interface) kubetest.TestSuite {
	return func(t *testing.T) {
		catchAllUpstream := &corev1.Container{
			Name:    "upstream",
			Image:   "nginx:alpine",
			Command: []string{"/bin/sh", "-c"},
			Args:    []string{`printf 'server { listen 8081; location / { return 200 "OK\\n"; } }' > /etc/nginx/conf.d/default.conf && nginx -g "daemon off;"`},
		}

		headerRewriteAuthzConfig := `
authorization:
  rewrites:
    byHttpHeader:
      name: X-Namespace
  resourceAttributes:
    namespace: "{{ .Value }}"
    resource: configmaps
    name: foobar
  static:
    - user:
        name: system:serviceaccount:default:default
      resourceRequest: true
      verb: get
      namespace: kube-system
      resource: configmaps
      name: foobar
`

		configmapGetterRole := &rbacv1.Role{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "configmap-foobar-getter",
				Namespace: "kube-node-lease",
			},
			Rules: []rbacv1.PolicyRule{{
				APIGroups:     []string{""},
				Resources:     []string{"configmaps"},
				Verbs:         []string{"get"},
				ResourceNames: []string{"foobar"},
			}},
		}

		statusCodeCmd := `STATUS_CODE=$(curl --connect-timeout 5 -o /dev/null -v -s -k --write-out "%%{http_code}" -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" %s https://kube-rbac-proxy.default.svc.cluster.local:8443%s); if [[ "$STATUS_CODE" != %d ]]; then echo "expecting %d status code, got $STATUS_CODE instead" > /proc/self/fd/2; exit 1; fi`

		krpConfig := func() *kubetest.KRPTestConfig {
			return kubetest.NewBasicKubeRBACProxyTestConfig().
				WithAuthorizationConfigYAML(headerRewriteAuthzConfig).
				WithoutMetricsEndpointAllowClusterRole().
				UpdateFlags(map[string]string{"allow-paths": "/api/v1/namespaces/default/configmaps/foobar"}).
				AddSARoleBinding("default", configmapGetterRole).
				ReplaceUpstream(catchAllUpstream)
		}

		for _, tc := range []struct {
			name        string
			extraHeader string
			path        string
			statusCode  int
		}{
			{
				name:        "FailsAllowPath",
				extraHeader: "",
				path:        "/not/an/allowed/path",
				statusCode:  404,
			},
			{
				name:        "PassesAllowPathFailsRewriteNoHeader",
				extraHeader: "",
				path:        "/api/v1/namespaces/default/configmaps/foobar",
				statusCode:  400,
			},
			{
				name:        "PassesAllowPathFailsAuthz",
				extraHeader: `-H "X-Namespace: default"`,
				path:        "/api/v1/namespaces/default/configmaps/foobar",
				statusCode:  403,
			},
			{
				name:        "PassesAllowPathMatchesStaticAuthorizer",
				extraHeader: `-H "X-Namespace: kube-system"`,
				path:        "/api/v1/namespaces/default/configmaps/foobar",
				statusCode:  200,
			},
			{
				name:        "PassesAllowPathMatchesRBAC",
				extraHeader: `-H "X-Namespace: kube-node-lease"`,
				path:        "/api/v1/namespaces/default/configmaps/foobar",
				statusCode:  200,
			},
		} {
			kubetest.Scenario{
				Name: tc.name,
				Given: kubetest.Actions(
					krpConfig().Launch(client),
				),
				When: kubetest.Actions(
					kubetest.PodsAreReady(client, 1, "app=kube-rbac-proxy"),
					kubetest.ServiceIsReady(client, "kube-rbac-proxy"),
				),
				Then: kubetest.Actions(
					kubetest.ClientSucceeds(
						client,
						fmt.Sprintf(statusCodeCmd, tc.extraHeader, tc.path, tc.statusCode, tc.statusCode),
						nil,
					),
				),
			}.Run(t)
		}
	}
}

func testIgnorePathQueryRewriteStaticRBAC(client kubernetes.Interface) kubetest.TestSuite {
	return func(t *testing.T) {
		catchAllUpstream := &corev1.Container{
			Name:    "upstream",
			Image:   "nginx:alpine",
			Command: []string{"/bin/sh", "-c"},
			Args:    []string{`printf 'server { listen 8081; location / { return 200 "OK\\n"; } }' > /etc/nginx/conf.d/default.conf && nginx -g "daemon off;"`},
		}

		queryRewriteAuthzConfig := `
authorization:
  rewrites:
    byQueryParameter:
      name: namespace
  resourceAttributes:
    namespace: "{{ .Value }}"
    resource: configmaps
    name: foobar
  static:
    - user:
        name: system:serviceaccount:default:default
      resourceRequest: true
      verb: get
      namespace: kube-system
      resource: configmaps
      name: foobar
`

		configmapGetterRole := &rbacv1.Role{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "configmap-foobar-getter",
				Namespace: "kube-node-lease",
			},
			Rules: []rbacv1.PolicyRule{{
				APIGroups:     []string{""},
				Resources:     []string{"configmaps"},
				Verbs:         []string{"get"},
				ResourceNames: []string{"foobar"},
			}},
		}

		statusCodeCmdNoAuth := `STATUS_CODE=$(curl --connect-timeout 5 -o /dev/null -v -s -k --write-out "%%{http_code}" https://kube-rbac-proxy.default.svc.cluster.local:8443%s); if [[ "$STATUS_CODE" != %d ]]; then echo "expecting %d status code, got $STATUS_CODE instead" > /proc/self/fd/2; exit 1; fi`
		statusCodeCmdWithAuth := `STATUS_CODE=$(curl --connect-timeout 5 -o /dev/null -v -s -k --write-out "%%{http_code}" -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" "https://kube-rbac-proxy.default.svc.cluster.local:8443%s"); if [[ "$STATUS_CODE" != %d ]]; then echo "expecting %d status code, got $STATUS_CODE instead" > /proc/self/fd/2; exit 1; fi`

		krpConfig := func() *kubetest.KRPTestConfig {
			return kubetest.NewBasicKubeRBACProxyTestConfig().
				WithAuthorizationConfigYAML(queryRewriteAuthzConfig).
				WithoutMetricsEndpointAllowClusterRole().
				UpdateFlags(map[string]string{"ignore-paths": "/healthz"}).
				AddSARoleBinding("default", configmapGetterRole).
				ReplaceUpstream(catchAllUpstream)
		}

		for _, tc := range []struct {
			name    string
			command string
		}{
			{
				name:    "MatchesIgnorePath",
				command: fmt.Sprintf(statusCodeCmdNoAuth, "/healthz", 200, 200),
			},
			{
				name:    "DoesNotMatchIgnorePathFailsAuthz",
				command: fmt.Sprintf(statusCodeCmdWithAuth, "/api/v1/namespaces/default/configmaps/foobar?namespace=default", 403, 403),
			},
			{
				name:    "DoesNotMatchIgnorePathMatchesStaticAuthorizer",
				command: fmt.Sprintf(statusCodeCmdWithAuth, "/api/v1/namespaces/kube-system/configmaps/foobar?namespace=kube-system", 200, 200),
			},
			{
				name:    "DoesNotMatchIgnorePathOrStaticAuthorizerMatchesSARRBAC",
				command: fmt.Sprintf(statusCodeCmdWithAuth, "/api/v1/namespaces/kube-node-lease/configmaps/foobar?namespace=kube-node-lease", 200, 200),
			},
		} {
			kubetest.Scenario{
				Name: tc.name,
				Given: kubetest.Actions(
					krpConfig().Launch(client),
				),
				When: kubetest.Actions(
					kubetest.PodsAreReady(client, 1, "app=kube-rbac-proxy"),
					kubetest.ServiceIsReady(client, "kube-rbac-proxy"),
				),
				Then: kubetest.Actions(
					kubetest.ClientSucceeds(
						client,
						tc.command,
						nil,
					),
				),
			}.Run(t)
		}
	}
}
