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

package app

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"time"
)

func initTransport(upstreamCAPool *x509.CertPool, upstreamClientCertPath, upstreamClientKeyPath string) (http.RoundTripper, error) {
	if upstreamCAPool == nil {
		return http.DefaultTransport, nil
	}

	var certKeyPair tls.Certificate
	if len(upstreamClientCertPath) > 0 {
		var err error
		certKeyPair, err = tls.LoadX509KeyPair(upstreamClientCertPath, upstreamClientKeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read upstream client cert/key: %w", err)
		}
	}

	// http.Transport sourced from go 1.10.7
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig: &tls.Config{
			RootCAs: upstreamCAPool,
		},
	}

	if certKeyPair.Certificate != nil {
		transport.TLSClientConfig.Certificates = []tls.Certificate{certKeyPair}
	}

	return transport, nil
}
