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

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/brancz/kube-rbac-proxy/test/kubetest"
)

func Test(t *testing.T) {
	clientConfig, err := newClientConfigForTest()
	if err != nil {
		t.Fatalf("failed retrieving kubernetes client config: %v", err)
	}
	client, err := kubernetes.NewForConfig(clientConfig)
	if err != nil {
		t.Fatalf("failed to setup a client for the tests: %v", err)
	}

	tests := map[string]kubetest.TestSuite{
		"Basics":                     testBasics(client),
		"H2CUpstream":                testH2CUpstream(client),
		"ClientCertificates":         testClientCertificates(client),
		"TokenAudience":              testTokenAudience(client),
		"AllowPath":                  testAllowPathsRegexp(client),
		"IgnorePath":                 testIgnorePaths(client),
		"TLS":                        testTLS(client),
		"StaticAuthorizer":           testStaticAuthorizer(client),
		"HTTP2":                      testHTTP2(client),
		"Flags":                      testFlags(client),
		"TokenMasking":               testTokenMasking(client),
		"ResourceBoundAuthorization": testResourceBoundAuthorization(client),
	}

	for name, tc := range tests {
		t.Run(name, tc)
	}
}

// NewClientConfigForTest returns a config configured to connect to the api server
func newClientConfigForTest() (*rest.Config, error) {
	loader := clientcmd.NewDefaultClientConfigLoadingRules()
	clientConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loader, &clientcmd.ConfigOverrides{})
	config, err := clientConfig.ClientConfig()
	if err == nil {
		fmt.Printf("Found configuration for host %v.\n", config.Host)
	}

	return config, err
}
