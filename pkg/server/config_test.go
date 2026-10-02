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
package server

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"path/filepath"
	"testing"
	"time"

	certutil "k8s.io/client-go/util/cert"
	"k8s.io/client-go/util/keyutil"
)

func TestInitTransportWithClientCertAuth(t *testing.T) {
	serverCertPath, serverKeyPath, clientCAPath, clientCertPath, clientKeyPath, err := setupCerts(t)
	if err != nil {
		t.Fatalf("failed to generate client cert: %v", err)
	}

	tlsCert, err := tls.LoadX509KeyPair(serverCertPath, serverKeyPath)
	if err != nil {
		t.Fatalf("failed to load a new serving cert: %v", err)
	}

	clientCAPEM, err := os.ReadFile(clientCAPath)
	if err != nil {
		t.Fatalf("failed to read the client CA PEM: %v", err)
	}

	clientCAPool := x509.NewCertPool()
	if ok := clientCAPool.AppendCertsFromPEM([]byte(clientCAPEM)); !ok {
		t.Fatal("error parsing upstream CA certificate")
	}

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on secure address: %v", err)
	}
	defer l.Close()
	tlsListener := tls.NewListener(l, &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		ClientCAs:    clientCAPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	})
	defer tlsListener.Close()

	tlsServer := http.Server{
		Handler: http.HandlerFunc(testHTTPHandler),
	}
	go func() {
		if err := tlsServer.Serve(tlsListener); err != nil {
			t.Logf("failed to run the test server: %v", err)
		}
	}()
	defer tlsServer.Close()

	i := KubeRBACProxyInfo{}
	if err := i.SetUpstreamTransport(serverCertPath, clientCertPath, clientKeyPath); err != nil {
		t.Errorf("want err to be nil, but got %v", err)
		return
	}
	roundTripper := i.UpstreamTransport

	httpReq, err := http.NewRequest(http.MethodPost, fmt.Sprintf("https://127.0.0.1:%d", l.Addr().(*net.TCPAddr).Port), nil)
	if err != nil {
		t.Fatalf("failed to create an HTTP request: %v", err)
	}

	resp, err := roundTripper.RoundTrip(httpReq)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Logf("failed to read response body: %v", err)
		}
		t.Logf("response with failure logs:\n%s", respBody)
		t.Errorf("expected the response code to be '%d', but it is '%d'", http.StatusOK, resp.StatusCode)
	}
}

func TestKubeRBACProxyInfo_SetUpstreamTransport(t *testing.T) {
	_, _, clientCAPath, clientCertPath, clientKeyPath, err := setupCerts(t)
	if err != nil {
		t.Fatalf("failed to generate client cert: %v", err)
	}

	tests := []struct {
		name                   string
		upstreamCAPath         string
		upstreamClientCertPath string
		upstreamClientKeyPath  string
		expectedCerts          bool
		expectedRootCA         bool
		wantErr                bool
	}{
		{
			name:           "default transport",
			expectedCerts:  false,
			expectedRootCA: false,
			wantErr:        false,
		},
		{
			name:           "CA set",
			upstreamCAPath: clientCAPath,
			expectedCerts:  false,
			expectedRootCA: true,
			wantErr:        false,
		},
		{
			name:                   "upstream client certs set",
			upstreamClientCertPath: clientCertPath,
			upstreamClientKeyPath:  clientKeyPath,
			expectedCerts:          true,
			expectedRootCA:         false,
			wantErr:                false,
		},
		{
			name:                   "both set",
			upstreamCAPath:         clientCAPath,
			upstreamClientCertPath: clientCertPath,
			upstreamClientKeyPath:  clientKeyPath,
			expectedCerts:          true,
			expectedRootCA:         true,
			wantErr:                false,
		},
		{
			name:                   "cert set/key unset",
			upstreamClientCertPath: clientCertPath,
			expectedCerts:          false,
			expectedRootCA:         false,
			wantErr:                true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i := &KubeRBACProxyInfo{}
			err := i.SetUpstreamTransport(tt.upstreamCAPath, tt.upstreamClientCertPath, tt.upstreamClientKeyPath)

			if (err != nil) != tt.wantErr {
				t.Errorf("KubeRBACProxyInfo.SetUpstreamTransport() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil {
				return
			}

			transport := i.UpstreamTransport.(*http.Transport)
			if (transport.TLSClientConfig.RootCAs != nil) != (tt.expectedRootCA) {
				t.Errorf("expected root CA to be set %v, but it is in fact %v", tt.expectedRootCA, transport.TLSClientConfig.RootCAs)
			}

			if (len(transport.TLSClientConfig.Certificates) > 0) != (tt.expectedCerts) {
				t.Errorf("expected certificates to be set %v, but they are in fact %v", tt.expectedCerts, transport.TLSClientConfig.Certificates)
			}
		})
	}
}

func setupCerts(t *testing.T) (serverCertPath, serverKeyPath, clientCAPath, clientCertPath, clientKeyPath string, err error) {
	t.Helper()

	serverCert, serverKey, err := certutil.GenerateSelfSignedCertKey("127.0.0.1", nil, nil)
	if err != nil {
		err = fmt.Errorf("failed to create a new serving cert: %w", err)
		return
	}

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		err = fmt.Errorf("failed to generate private key: %v", err)
		return
	}
	ca, err := certutil.NewSelfSignedCACert(certutil.Config{CommonName: "testing-ca"}, privKey)
	if err != nil {
		err = fmt.Errorf("failed to generate CA cert: %v", err)
		return
	}

	privKeyClient, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		err = fmt.Errorf("failed to generate private key: %v", err)
		return
	}

	certDER, err := x509.CreateCertificate(rand.Reader,
		&x509.Certificate{
			Subject:      pkix.Name{CommonName: "testing-client"},
			SerialNumber: big.NewInt(15233),
			NotBefore:    time.Now().Add(-5 * time.Second),
			NotAfter:     time.Now().Add(1 * time.Minute),
			KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		},
		ca, privKeyClient.Public(), privKey,
	)
	if err != nil {
		err = fmt.Errorf("failed to create a client cert: %v", err)
		return
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	caPool := x509.NewCertPool()
	caPool.AddCert(ca)

	privKeyPEM, err := keyutil.MarshalPrivateKeyToPEM(privKeyClient)
	if err != nil {
		err = fmt.Errorf("failed to encode private key to pem: %v", err)
		return
	}

	tmpDir := t.TempDir()

	clientCAPath = filepath.Join(tmpDir, "ca.crt")
	serverCertPath = filepath.Join(tmpDir, "server.crt")
	serverKeyPath = filepath.Join(tmpDir, "server.key")
	clientCertPath = filepath.Join(tmpDir, "client.crt")
	clientKeyPath = filepath.Join(tmpDir, "client.key")

	if err := certutil.WriteCert(serverCertPath, serverCert); err != nil {
		t.Fatalf("failed to write server cert: %v", err)
	}
	if err := keyutil.WriteKey(serverKeyPath, serverKey); err != nil {
		t.Fatalf("failed to write server key: %v", err)
	}

	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})
	if err := certutil.WriteCert(clientCAPath, caPEM); err != nil {
		t.Fatalf("failed to write CA cert: %v", err)
	}
	if err := certutil.WriteCert(clientCertPath, certPEM); err != nil {
		t.Fatalf("failed to write client cert: %v", err)
	}
	if err := keyutil.WriteKey(clientKeyPath, privKeyPEM); err != nil {
		t.Fatalf("failed to write client key: %v", err)
	}

	return
}

func testHTTPHandler(w http.ResponseWriter, req *http.Request) {
	if len(req.TLS.PeerCertificates) > 0 {
		_, _ = w.Write([]byte("ok"))
		return
	} else {
		reqDump, _ := httputil.DumpRequest(req, false)
		resp := fmt.Sprintf("got request without client certificates:\n%s\n", reqDump)
		resp += fmt.Sprintf("TLS config: %#v\n", req.TLS)
		http.Error(w, resp, http.StatusBadRequest)
	}
}
