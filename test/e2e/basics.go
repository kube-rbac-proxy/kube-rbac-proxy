/*
Copyright 2017 Frederic Branczyk All rights reserved.

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

	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/brancz/kube-rbac-proxy/test/kubetest"
	"github.com/brancz/kube-rbac-proxy/test/kubetest/testtemplates"
)

func testBasics(client kubernetes.Interface) kubetest.TestSuite {
	return func(t *testing.T) {
		command := `curl --connect-timeout 5 -v -s -k --fail -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" https://kube-rbac-proxy.default.svc.cluster.local:8443/metrics`

		kubetest.Scenario{
			Name: "NoRBAC",
			Description: `
				As a client without any RBAC rule access,
				I fail with my request
			`,

			Given: kubetest.Actions(
				kubetest.NewBasicKubeRBACProxyTestConfig().
					WithoutMetricsEndpointAllowClusterRole().
					Launch(client),
			),
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
			Then: kubetest.Actions(
				kubetest.ClientFails(
					client,
					command,
					nil,
				),
			),
		}.Run(t)

		kubetest.Scenario{
			Name: "WithRBAC",
			Description: `
				As a client with the correct RBAC rules,
				I succeed with my request
			`,

			Given: kubetest.Actions(
				kubetest.NewBasicKubeRBACProxyTestConfig().
					Launch(client),
			),
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
			Then: kubetest.Actions(
				kubetest.ClientSucceeds(
					client,
					command,
					nil,
				),
			),
		}.Run(t)
	}
}

func testTokenAudience(client kubernetes.Interface) kubetest.TestSuite {
	return func(t *testing.T) {
		command := `curl --connect-timeout 5 -v -s -k --fail -H "Authorization: Bearer $(cat /var/run/secrets/tokens/requestedtoken)" https://kube-rbac-proxy.default.svc.cluster.local:8443/metrics`

		krpWithAudiencesConfig := kubetest.NewBasicKubeRBACProxyTestConfig().
			UpdateFlags(map[string]string{"auth-token-audiences": "kube-rbac-proxy"})

		kubetest.Scenario{
			Name: "IncorrectAudience",
			Description: `
				As a client with the wrong token audience,
				I fail with my request
			`,

			Given: kubetest.Actions(krpWithAudiencesConfig.Launch(client)),
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
			Then: kubetest.Actions(
				kubetest.ClientFails(
					client,
					command,
					&kubetest.RunOptions{TokenAudience: "wrong-audience"},
				),
			),
		}.Run(t)

		kubetest.Scenario{
			Name: "CorrectAudience",
			Description: `
				As a client with the correct token audience,
				I succeed with my request
			`,

			Given: kubetest.Actions(krpWithAudiencesConfig.Launch(client)),
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
			Then: kubetest.Actions(
				kubetest.ClientSucceeds(
					client,
					command,
					&kubetest.RunOptions{TokenAudience: "kube-rbac-proxy"},
				),
			),
		}.Run(t)
	}
}

func testClientCertificates(client kubernetes.Interface) kubetest.TestSuite {
	return func(t *testing.T) {
		command := `curl --connect-timeout 5 -v -s -k --fail --cert /certs/tls.crt --key /certs/tls.key https://kube-rbac-proxy.default.svc.cluster.local:8443/metrics`

		clientCertSetup := func() *kubetest.KRPTestConfig {
			return kubetest.NewBasicKubeRBACProxyTestConfig().
				AddUserClusterRoleBinding("test-client", testtemplates.GetMetricsRoleForClient()).
				WithClientCerts("test-client").
				UpdateFlags(map[string]string{"client-ca-file": "/var/run/configMaps/test-client-trust/ca.crt"})
		}

		kubetest.Scenario{
			Name: "NoRBAC",
			Description: `
				As a client with client certificates authorization without RBAC,
				I fail with my request
			`,

			Given: kubetest.Actions(
				clientCertSetup().
					UpdateUserClusterRoleBindings(map[string]*rbacv1.ClusterRole{"test-client": nil}).
					Launch(client),
			),
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
			Then: kubetest.Actions(
				kubetest.ClientFails(
					client,
					command,
					&kubetest.RunOptions{ClientCertificatesSecretName: "test-client-certs"},
				),
			),
		}.Run(t)

		kubetest.Scenario{
			Name: "WithRBAC",
			Description: `
				As a client with client certificates authorization with RBAC,
				I succeed with my request
			`,

			Given: kubetest.Actions(
				clientCertSetup().
					Launch(client),
			),
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
			Then: kubetest.Actions(
				kubetest.ClientSucceeds(
					client,
					command,
					&kubetest.RunOptions{ClientCertificatesSecretName: "test-client-certs"},
				),
			),
		}.Run(t)

		kubetest.Scenario{
			Name: "WrongCA",
			Description: `
				As a client with client certificates authorization with RBAC and with unmatched CA,
				I fail with my request
			`,

			Given: kubetest.Actions(
				clientCertSetup().
					UpdateFlags(map[string]string{"client-ca-file": "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"}).
					Launch(client),
			),
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
			Then: kubetest.Actions(
				kubetest.ClientFails(
					client,
					command,
					&kubetest.RunOptions{ClientCertificatesSecretName: "test-client-certs"},
				),
			),
		}.Run(t)
	}
}

func testAllowPathsRegexp(client kubernetes.Interface) kubetest.TestSuite {
	return func(t *testing.T) {
		command := `STATUS_CODE=$(curl --connect-timeout 5 -o /dev/null -v -s -k --write-out "%%{http_code}" -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" https://kube-rbac-proxy.default.svc.cluster.local:8443%s); if [[ "$STATUS_CODE" != %d ]]; then echo "expecting %d status code, got $STATUS_CODE instead" > /proc/self/fd/2; exit 1; fi`

		allowPathsSetup := kubetest.NewBasicKubeRBACProxyTestConfig().
			UpdateFlags(map[string]string{"allow-paths": "/metrics,/api/v1/label/*"})

		kubetest.Scenario{
			Name: "WithPathNotAllowed",
			Description: `
				As a client with the correct RBAC rules,
				I get a 403 response when requesting a path which isn't allowed by kube-rbac-proxy
			`,

			Given: kubetest.Actions(allowPathsSetup.Launch(client)),
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
			Then: kubetest.Actions(
				kubetest.ClientSucceeds(
					client,
					fmt.Sprintf(command, "/", 403, 403),
					nil,
				),
				kubetest.ClientSucceeds(
					client,
					fmt.Sprintf(command, "/api/v1", 403, 403),
					nil,
				),
			),
		}.Run(t)

		kubetest.Scenario{
			Name: "WithPathAllowed",
			Description: `
				As a client with the correct RBAC rules,
				I succeed with my request for a path that is allowed
			`,

			Given: kubetest.Actions(allowPathsSetup.Launch(client)),
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
			Then: kubetest.Actions(
				kubetest.ClientSucceeds(
					client,
					fmt.Sprintf(command, "/metrics", 200, 200),
					nil,
				),
				kubetest.ClientSucceeds(
					client,
					fmt.Sprintf(command, "/api/v1/label/job/values", 200, 200),
					nil,
				),
			),
		}.Run(t)
	}
}

func testIgnorePaths(client kubernetes.Interface) kubetest.TestSuite {
	return func(t *testing.T) {
		commandWithoutAuth := `STATUS_CODE=$(curl --connect-timeout 5 -o /dev/null -v -s -k --write-out "%%{http_code}" https://kube-rbac-proxy.default.svc.cluster.local:8443%s); if [[ "$STATUS_CODE" != %d ]]; then echo "expecting %d status code, got $STATUS_CODE instead" > /proc/self/fd/2; exit 1; fi`

		ignorePathsSetup := kubetest.NewBasicKubeRBACProxyTestConfig().
			UpdateFlags(map[string]string{"ignore-paths": "/metrics,/api/v1/*"})

		kubetest.Scenario{
			Name: "WithIgnorePathMatch",
			Description: `
				As a client without an auth token,
				I get a 200 response when requesting a path included in ignorePaths
			`,

			Given: kubetest.Actions(ignorePathsSetup.Launch(client)),
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
			Then: kubetest.Actions(
				kubetest.ClientSucceeds(
					client,
					fmt.Sprintf(commandWithoutAuth, "/metrics", 200, 200),
					nil,
				),
				kubetest.ClientSucceeds(
					client,
					fmt.Sprintf(commandWithoutAuth, "/api/v1/", 200, 200),
					nil,
				),
				kubetest.ClientSucceeds(
					client,
					fmt.Sprintf(commandWithoutAuth, "/api/v1/labels", 200, 200),
					nil,
				),
				kubetest.ClientSucceeds(
					client,
					fmt.Sprintf(commandWithoutAuth, "/api/v1/label/values", 200, 200),
					nil,
				),
			),
		}.Run(t)

		kubetest.Scenario{
			Name: "WithIgnorePathNoMatch",
			Description: `
				As a client without an auth token,
				I get a 403 response when requesting a path not included in ignorePaths
				because I end up being system:anonymous to the proxy
			`,

			Given: kubetest.Actions(ignorePathsSetup.Launch(client)),
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
			Then: kubetest.Actions(
				kubetest.ClientSucceeds(
					client,
					fmt.Sprintf(commandWithoutAuth, "/", 403, 403),
					nil,
				),
				kubetest.ClientSucceeds(
					client,
					fmt.Sprintf(commandWithoutAuth, "/api/v1", 403, 403),
					nil,
				),
				kubetest.ClientSucceeds(
					client,
					fmt.Sprintf(commandWithoutAuth, "/api/v12", 403, 403),
					nil,
				),
			),
		}.Run(t)
	}
}
