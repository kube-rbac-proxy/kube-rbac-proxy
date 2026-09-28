/*
Copyright the kube-rbac-proxy maintainers. All rights reserved.

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
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/brancz/kube-rbac-proxy/test/kubetest"
)

func testResourceBoundAuthorization(client kubernetes.Interface) kubetest.TestSuite {
	return func(t *testing.T) {
		command := `curl --connect-timeout 5 -v -s -k --fail -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" https://kube-rbac-proxy.default.svc.cluster.local:8443/metrics`
		serviceAccountName := "resource-metrics-allowed"
		resourceAttributesConfig := `
authorization:
  resourceAttributes:
    resource: pods
    apiGroup: ""
    namespace: "kube-system"
`

		podsRole := &rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{Name: "resource-attributes-pods"},
			Rules: []rbacv1.PolicyRule{{
				APIGroups: []string{""},
				Resources: []string{"pods"},
				Verbs:     []string{"get"},
			}},
		}

		for _, tc := range []struct {
			name  string
			given kubetest.Action
			check kubetest.Action
		}{
			{
				name: "WithoutResourceRBAC",
				given: kubetest.Actions(
					kubetest.NewBasicKubeRBACProxyTestConfig().
						WithAuthorizationConfigYAML(resourceAttributesConfig).
						WithoutMetricsEndpointAllowClusterRole().
						Launch(client),
				),
				check: kubetest.Actions(
					kubetest.ClientFails(
						client,
						command,
						nil,
					),
				),
			},
			{
				name: "WithResourceRBAC",
				given: kubetest.Actions(
					kubetest.CreateServiceAccount(client, serviceAccountName),
					kubetest.NewBasicKubeRBACProxyTestConfig().
						WithAuthorizationConfigYAML(resourceAttributesConfig).
						WithoutMetricsEndpointAllowClusterRole().
						AddSAClusterRoleBinding(serviceAccountName, podsRole).
						Launch(client),
				),
				check: kubetest.Actions(
					kubetest.ClientSucceeds(
						client,
						command,
						&kubetest.RunOptions{ServiceAccount: "resource-metrics-allowed"},
					),
				),
			},
		} {
			kubetest.Scenario{
				Name:  tc.name,
				Given: kubetest.Actions(tc.given),
				When: kubetest.Actions(
					kubetest.PodsAreReady(
						client,
						1,
						"app=kube-rbac-proxy",
					),
					kubetest.ServiceIsReady(
						client,
						"kube-rbac-proxy",
					),
				),
				Then: kubetest.Actions(tc.check),
			}.Run(t)
		}
	}
}
