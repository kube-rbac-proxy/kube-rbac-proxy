/*
Copyright 2024 the kube-rbac-proxy maintainers. All rights reserved.

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

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/brancz/kube-rbac-proxy/test/kubetest"
)

const (
	nginxNoTLSEchoHeaderConfig = `
server {
    listen 8081;
    server_name upstream_nginx;

    location /metrics {
        add_header Content-Type text/plain;
        add_header x-remote-user $http_x_remote_user;
        return 200 'metrics endpoint reached\n';
    }
}
`
)

func testIdentityHeaders(client kubernetes.Interface) kubetest.TestSuite {
	return func(t *testing.T) {
		command := `curl --connect-timeout 5 -v -s -k --fail -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" https://kube-rbac-proxy.default.svc.cluster.local:8443/metrics`

		kubetest.Scenario{
			Name: "With x-remote-user",
			Description: `
				Verifies that remote user is set to the service account, when
				upstreama is listening on loopback through a HTTP connection.
			`,

			Given: kubetest.Actions(
				kubetest.NewBasicKubeRBACProxyTestConfig().
					UpdateFlags(map[string]string{
						"auth-header-user-field-name":        "x-remote-user",
						"auth-header-groups-field-name":      "x-remote-groups",
						"auth-header-groups-field-separator": "|",
					}).
					WithConfigMap("nginx-config", &corev1.ConfigMap{
						ObjectMeta: metav1.ObjectMeta{Name: "nginx-config"},
						Data: map[string]string{
							"server.conf": nginxNoTLSEchoHeaderConfig,
						},
					}).
					ReplaceUpstream(&corev1.Container{
						Name:  "nginx",
						Image: "nginx:latest",
						Ports: []corev1.ContainerPort{{
							ContainerPort: 8081, // the proxy flag expects this port
						}},
						VolumeMounts: []corev1.VolumeMount{{
							Name:      "nginx-config",
							MountPath: "/etc/nginx/conf.d/server.conf",
							SubPath:   "server.conf",
						}},
					}).
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
				kubetest.ClientLogsContain(
					client,
					command,
					[]string{`< x-remote-user: system:serviceaccount:default:default`},
					nil,
				),
			),
		}.Run(t)

		kubetest.Scenario{
			Name: "With http on no loopback",
			Description: `
					Verifies that the proxy is not able to connect to the remote upstream service,
					if upstream isn't offering TLS, when identity headers are being used.
				`,

			Given: kubetest.Actions(
				kubetest.CreatedManifests(
					client,
					"identityheaders/insecure/deployment-upstream.yaml",
					"identityheaders/insecure/service-upstream.yaml",
				),
				kubetest.NewBasicKubeRBACProxyTestConfig().
					UpdateFlags(map[string]string{
						"upstream":                           "http://nginx.default.svc.cluster.local:80/",
						"auth-header-user-field-name":        "x-remote-user",
						"auth-header-groups-field-name":      "x-remote-groups",
						"auth-header-groups-field-separator": "|",
					}).Launch(client),
			),
			When: kubetest.Actions(
				kubetest.PodsAreReady(
					client,
					1,
					"app=nginx",
				),
				kubetest.ServiceIsReady(
					client,
					"nginx",
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
			Name: "With https on no loopback",
			Description: `
					Verifies that the proxy is able to connect to the remote upstream service,
					through a mTLS connection, when providing identity headers.
				`,
			Given: kubetest.Actions(
				kubetest.NewBasicKubeRBACProxyTestConfig().
					UpdateFlags(map[string]string{
						"upstream":                           "https://nginx.default.svc.cluster.local:8443/",
						"auth-header-user-field-name":        "x-remote-user",
						"auth-header-groups-field-name":      "x-remote-groups",
						"auth-header-groups-field-separator": "|",
						"tls-cert-file":                      "/var/run/secrets/kube-rbac-proxy/tls.crt",
						"tls-private-key-file":               "/var/run/secrets/kube-rbac-proxy/tls.key",
						"upstream-ca-file":                   "/var/run/configMaps/nginx-trust/ca.crt",
						"upstream-client-cert-file":          "/var/run/secrets/kube-rbac-proxy-client/tls.crt",
						"upstream-client-key-file":           "/var/run/secrets/kube-rbac-proxy-client/tls.key",
					}).
					WithServerCerts("nginx").
					WithServerCerts("kube-rbac-proxy").
					WithClientCerts("kube-rbac-proxy-client").
					Launch(client),
				kubetest.CreatedManifests(
					client,
					"identityheaders/secure/configmap-nginx.yaml",
					"identityheaders/secure/deployment-upstream.yaml",
					"identityheaders/secure/service-upstream.yaml",
				),
			),
			When: kubetest.Actions(
				kubetest.PodsAreReady(
					client,
					1,
					"app=nginx",
				),
				kubetest.ServiceIsReady(
					client,
					"nginx",
				),
				kubetest.PodsAreReady(
					client,
					1,
					"app=kube-rbac-proxy",
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
