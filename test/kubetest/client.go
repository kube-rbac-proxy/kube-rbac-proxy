/*
Copyright 2022 kube-rbac-proxy authors. All rights reserved.

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

package kubetest

import (
	"k8s.io/client-go/kubernetes"
)

// ClientLogsContain returns an action that checks if the client logs contain
// all of the given log entries.
func ClientLogsContain(client kubernetes.Interface, command string, logEntries []string, opts *RunOptions) Action {
	return func(ctx *ScenarioContext) error {
		return RunHasLogEntry(
			client,
			"quay.io/brancz/krp-curl:v0.0.2",
			"kube-rbac-proxy-client",
			[]string{"/bin/sh", "-c", command},
			logEntries,
			opts,
		)(ctx)
	}
}

// ClientSucceeds returns an action that checks that the client has succeeded.
func ClientSucceeds(client kubernetes.Interface, command string, opts *RunOptions) Action {
	return func(ctx *ScenarioContext) error {
		return RunSucceeds(
			client,
			"quay.io/brancz/krp-curl:v0.0.2",
			"kube-rbac-proxy-client",
			[]string{"/bin/sh", "-c", command},
			opts,
		)(ctx)
	}
}

// ClientSucceeds returns an action that checks that the client has failed.
func ClientFails(client kubernetes.Interface, command string, opts *RunOptions) Action {
	return func(ctx *ScenarioContext) error {
		return RunFails(
			client,
			"quay.io/brancz/krp-curl:v0.0.2",
			"kube-rbac-proxy-client",
			[]string{"/bin/sh", "-c", command},
			opts,
		)(ctx)
	}
}
