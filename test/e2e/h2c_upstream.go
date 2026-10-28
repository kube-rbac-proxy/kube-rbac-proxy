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
	"testing"

	"k8s.io/client-go/kubernetes"

	"github.com/brancz/kube-rbac-proxy/test/kubetest"
)

func testH2CUpstream(client kubernetes.Interface) kubetest.TestSuite {
	return func(t *testing.T) {
		command := `curl --connect-timeout 5 -v -s -k --fail -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" https://kube-rbac-proxy.default.svc.cluster.local:8443/metrics`

		kubetest.Scenario{
			Name: "With H2C non-local upstream",

			Given: kubetest.Actions(
				kubetest.CreatedManifests(
					client,
					"h2c-upstream/deployment-upstream-non-loopback.yaml",
					"h2c-upstream/upstream-svc.yaml",
				),
				kubetest.NewBasicKubeRBACProxyTestConfig().
					UpdateFlags(map[string]string{
						"upstream-force-h2c": "true",
						"upstream":           "http://http-echo-service.default.svc.cluster.local:80/",
					}).
					UpdateUpstreamFlags(map[string]string{"h2c": "true"}).
					Launch(client),
			),
			When: kubetest.Actions(
				kubetest.PodsAreReady(
					client,
					1,
					"app=http-echo",
				),
				kubetest.ServiceIsReady(
					client,
					"http-echo-service",
				),
			),
			Then: kubetest.Actions(
				kubetest.PodIsCrashLoopBackOff(
					client,
					"kube-rbac-proxy",
				),
			),
		}.Run(t)

		kubetest.Scenario{
			Name: "With H2C local upstream",

			Given: kubetest.Actions(
				kubetest.NewBasicKubeRBACProxyTestConfig().
					UpdateFlags(map[string]string{"upstream-force-h2c": "true"}).
					UpdateUpstreamFlags(map[string]string{"h2c": "true"}).
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
