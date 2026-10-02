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
	"bufio"
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/brancz/kube-rbac-proxy/test/kubetest"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

func testTokenMasking(client kubernetes.Interface) kubetest.TestSuite {
	return func(t *testing.T) {
		command := `curl --connect-timeout 5 -v -s -k --fail -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" https://kube-rbac-proxy.default.svc.cluster.local:8443/metrics`

		kubetest.Scenario{
			Name: "TokenMasking",
			Description: `
                As a client making a request through kube-rbac-proxy,
                I expect the logs to have tokens masked.
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
				checkLogsForMaskedToken(client),
			),
		}.Run(t)
	}
}

func checkLogsForMaskedToken(client kubernetes.Interface) kubetest.Action {
	return func(ctx *kubetest.ScenarioContext) error {
		pods, err := client.CoreV1().Pods(ctx.Namespace).List(context.TODO(), v1.ListOptions{
			LabelSelector: "app=kube-rbac-proxy",
		})
		if err != nil {
			return fmt.Errorf("failed to list pods: %v", err)
		}

		if len(pods.Items) == 0 {
			return fmt.Errorf("no pods found with label app=kube-rbac-proxy")
		}

		podName := pods.Items[0].Name

		logsReq := client.CoreV1().Pods(ctx.Namespace).GetLogs(podName, &corev1.PodLogOptions{
			Container: "kube-rbac-proxy",
		})
		logsStream, err := logsReq.Stream(context.TODO())
		if err != nil {
			return fmt.Errorf("failed to get logs: %v", err)
		}
		defer func() {
			closeErr := logsStream.Close()
			if closeErr != nil && err == nil {
				err = fmt.Errorf("failed to close logs stream: %v", closeErr)
			}
		}()

		scanner := bufio.NewScanner(logsStream)
		foundMaskedToken := false
		for scanner.Scan() {
			line := scanner.Text()
			if strings.Contains(line, `"kind":"TokenReview"`) {
				if strings.Contains(line, `"token":"<masked>"`) {
					foundMaskedToken = true
					break
				} else {
					return fmt.Errorf("found TokenReview in logs but token is not masked")
				}
			}
		}
		if err := scanner.Err(); err != nil {
			return fmt.Errorf("error reading logs: %v", err)
		}

		if !foundMaskedToken {
			return fmt.Errorf("no TokenReview log found with masked token")
		}

		return nil
	}
}
