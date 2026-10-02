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
	"fmt"
	"net"
	"strconv"

	"github.com/brancz/kube-rbac-proxy/pkg/authn"
	"github.com/brancz/kube-rbac-proxy/pkg/server"
	"github.com/spf13/pflag"

	genericoptions "k8s.io/apiserver/pkg/server/options"
	netutils "k8s.io/utils/net"
)

// LegacyOptions are options that existed in the original KRP.
type LegacyOptions struct {
	SecureListenAddress string

	x509Auth *authn.X509Config

	KubeconfigLocation string
}

func (o *LegacyOptions) AddFlags(flagset *pflag.FlagSet) {
	// kube-rbac-proxy flags
	flagset.StringVar(&o.SecureListenAddress, "secure-listen-address", "", "The address the kube-rbac-proxy HTTPs server should listen on.")

	//Kubeconfig flag
	flagset.StringVar(&o.KubeconfigLocation, "kubeconfig", "", "Path to a kubeconfig file, specifying how to connect to the API server. If unset, in-cluster configuration will be used")
}

func (o *LegacyOptions) Validate() []error {
	var errs []error
	return errs
}

func (o *LegacyOptions) ConvertToNewOptions(
	so *genericoptions.SecureServingOptions,
	authn *genericoptions.DelegatingAuthenticationOptions,
	authz *genericoptions.DelegatingAuthorizationOptions,
) error {
	if so.BindAddress.Equal(netutils.ParseIPSloppy("0.0.0.0")) && len(o.SecureListenAddress) > 0 {
		secureHost, securePort, err := net.SplitHostPort(o.SecureListenAddress)
		if err != nil {
			return fmt.Errorf("error separating secure listen address host and port: %w", err)
		}

		so.BindAddress = net.ParseIP(secureHost)
		so.BindPort, err = strconv.Atoi(securePort)
		if err != nil {
			return fmt.Errorf("failed to convert port to an integer: %w", err)
		}
	}

	if len(authn.RemoteKubeConfigFile) == 0 && len(o.KubeconfigLocation) > 0 {
		authn.RemoteKubeConfigFile = o.KubeconfigLocation
	}

	if len(authz.RemoteKubeConfigFile) == 0 && len(o.KubeconfigLocation) > 0 {
		authz.RemoteKubeConfigFile = o.KubeconfigLocation
	}

	return nil
}

func (o *LegacyOptions) ApplyTo(c *server.KubeRBACProxyInfo) error {
	return nil
}
