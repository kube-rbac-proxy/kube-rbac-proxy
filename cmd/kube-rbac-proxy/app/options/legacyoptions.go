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

	"github.com/brancz/kube-rbac-proxy/pkg/server"
	"github.com/spf13/pflag"

	genericoptions "k8s.io/apiserver/pkg/server/options"
	"k8s.io/klog/v2"
	netutils "k8s.io/utils/net"
)

// LegacyOptions are options that existed in the original KRP.
type LegacyOptions struct {
	InsecureListenAddress string
	SecureListenAddress   string
}

func (o *LegacyOptions) AddFlags(flagset *pflag.FlagSet) {
	flagset.StringVar(&o.InsecureListenAddress, "insecure-listen-address", "", "The address the kube-rbac-proxy HTTP server should listen on.")
	flagset.StringVar(&o.SecureListenAddress, "secure-listen-address", "", "The address the kube-rbac-proxy HTTPs server should listen on.")
}

func (o *LegacyOptions) Validate(certFile, keyFile string) []error {
	var errs []error

	hasCerts := certFile != "" && keyFile != ""
	hasInsecureListenAddress := o.InsecureListenAddress != ""
	if !hasCerts || hasInsecureListenAddress {
		klog.Warning(`
==== Deprecation Warning ======================

Insecure listen address will be removed.
Using --insecure-listen-address won't be possible!

The ability to run kube-rbac-proxy without TLS certificates will be removed.
Not using --tls-cert-file and --tls-private-key-file won't be possible!

For more information, please go to https://github.com/brancz/kube-rbac-proxy/issues/187

===============================================

		`)
	}

	return errs
}

func (o *LegacyOptions) ConvertIntoSecureServingOptions(so *genericoptions.SecureServingOptions) error {
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

	return nil
}

func (o *LegacyOptions) ApplyTo(c *server.KubeRBACProxyInfo) error {
	c.InsecureListenAddress = o.InsecureListenAddress
	return nil
}
