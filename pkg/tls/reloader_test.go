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

package tls

import (
	"context"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog/v2"

	certutil "k8s.io/client-go/util/cert"
)

func TestReloader(t *testing.T) {
	cases := []struct {
		name  string
		given stepFunc
		check checkFunc
	}{
		{
			name: "match cn",
			given: steps(
				newSelfSignedCert("foo"),
				newCertReloader,
			),
			check: commonNameIs("foo"),
		},
		{
			name: "change",
			given: steps(
				newSelfSignedCert("foo"),
				newCertReloader,
				startWatching,
				newSelfSignedCert("baz"),
				swapCert,
			),
			check: commonNameIs("baz"),
		},
		{
			name: "double symlink",
			given: steps(
				newSelfSignedCert("foo"),
				doubleSymlinkCert,
				newCertReloader,
				startWatching,
				newSelfSignedCert("bar"),
				swapSymlink,
			),
			check: commonNameIs("bar"),
		},
		{
			name: "swap double symlink twice",
			given: steps(
				newSelfSignedCert("foo"),
				doubleSymlinkCert,
				newCertReloader,
				startWatching,
				newSelfSignedCert("bar"),
				swapSymlink,
				newSelfSignedCert("baz"),
				swapSymlink,
			),
			check: commonNameIs("baz"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &scenario{tmpDir: t.TempDir()}

			tc.given(t, s)

			if err := tc.check(s); err != nil {
				t.Error(err)
			}

			for _, cleanup := range s.cleanups {
				cleanup()
			}
		})
	}
}

func TestMain(m *testing.M) {
	// add klog flags
	klog.InitFlags(flag.CommandLine)

	var err error
	err = flag.Set("alsologtostderr", "true")
	if err != nil {
		log.Fatal(err)
	}

	err = flag.Set("v", "5")
	if err != nil {
		log.Fatal(err)
	}

	flag.Parse()
	os.Exit(m.Run())
}

type scenario struct {
	certPath, keyPath string
	reloader          *CertReloader
	cleanups          []func()
	tmpDir            string
}

type stepFunc func(*testing.T, *scenario)

type checkFunc func(*scenario) error

func commonNameIs(want string) checkFunc {
	return func(g *scenario) error {
		return poll(10*time.Millisecond, 100*time.Millisecond, func() (err error) {
			cert, err := g.reloader.GetCertificate(nil)
			if err != nil {
				return fmt.Errorf("error getting certificate: %v", err)
			}

			first, err := x509.ParseCertificate(cert.Certificate[0])
			if err != nil {
				return fmt.Errorf("error parsing certificate: %v", err)
			}

			if !strings.HasPrefix(first.Subject.CommonName, want) {
				return fmt.Errorf("want subject common name to start with %q, got %q", want, first.Subject.CommonName)
			}

			return nil
		})
	}
}

func newCertReloader(t *testing.T, s *scenario) {
	r, err := NewCertReloader(s.certPath, s.keyPath, 10*time.Millisecond)
	if err != nil {
		t.Fatalf("error creating cert reloader: %v", err)
	}
	s.reloader = r
}

func startWatching(t *testing.T, s *scenario) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error)

	go func() {
		done <- s.reloader.Watch(ctx)
	}()

	cleanup := func() {
		cancel()

		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}

	s.cleanups = append([]func(){cleanup}, s.cleanups...)
}

func newSelfSignedCert(hostname string) stepFunc {
	return func(t *testing.T, s *scenario) {
		var err error
		certBytes, keyBytes, err := certutil.GenerateSelfSignedCertKey(hostname, nil, nil)
		if err != nil {
			t.Fatalf("generation of self signed cert and key failed: %v", err)
		}

		certPath, err := writeTempFile("cert", certBytes)
		if err != nil {
			t.Fatalf("error writing cert data: %v", err)
		}
		keyPath, err := writeTempFile("key", keyBytes)
		if err != nil {
			t.Fatalf("error writing key data: %v", err)
		}

		s.certPath = certPath
		s.keyPath = keyPath

		s.cleanups = append(s.cleanups, func() {
			_ = os.Remove(certPath)
			_ = os.Remove(keyPath)
		})
	}
}

func doubleSymlinkCert(t *testing.T, s *scenario) {
	name, err := os.MkdirTemp("", "keys")
	if err != nil {
		t.Fatal(err)
	}

	keyPath := path.Join(name, "key")
	if err := os.Rename(s.keyPath, keyPath); err != nil {
		t.Fatal(err)
	}

	certPath := path.Join(name, "cert")
	if err := os.Rename(s.certPath, certPath); err != nil {
		t.Fatal(err)
	}

	keysdir := path.Join(s.tmpDir, "keys")
	if err := os.Symlink(name, keysdir); err != nil {
		t.Fatal(err)
	}

	keyLink := path.Join(s.tmpDir, "key")
	_ = os.Symlink(path.Join(keysdir, "key"), keyLink)

	certLink := path.Join(s.tmpDir, "cert")
	_ = os.Symlink(path.Join(keysdir, "cert"), certLink)

	s.keyPath = keyLink
	s.certPath = certLink

	s.cleanups = append(s.cleanups, func() {
		_ = os.Remove(keyPath)
		_ = os.Remove(certPath)
		_ = os.Remove(keyLink)
		_ = os.Remove(certLink)
		_ = os.Remove(keysdir)
		_ = os.RemoveAll(name)
	})
}

func swapCert(t *testing.T, s *scenario) {
	t.Log("renaming", s.keyPath, "to", s.reloader.keyPath)
	if err := os.Rename(s.certPath, s.reloader.certPath); err != nil {
		t.Fatal(err)
	}

	if err := os.Rename(s.keyPath, s.reloader.keyPath); err != nil {
		t.Fatal(err)
	}

	s.certPath = s.reloader.certPath
	s.keyPath = s.reloader.keyPath
}

func swapSymlink(t *testing.T, s *scenario) {
	name, err := os.MkdirTemp("", "keys")
	if err != nil {
		t.Fatal(err)
	}

	keyPath := path.Join(name, "key")
	if err := os.Rename(s.keyPath, keyPath); err != nil {
		t.Fatal(err)
	}

	certPath := path.Join(name, "cert")
	if err := os.Rename(s.certPath, certPath); err != nil {
		t.Fatal(err)
	}

	tmp := path.Join(s.tmpDir, "keys.tmp")
	if err := os.Symlink(name, tmp); err != nil {
		t.Fatal(err)
	}

	keysdir := path.Join(s.tmpDir, "keys")
	if err := os.Rename(tmp, keysdir); err != nil {
		t.Fatal(err)
	}

	s.keyPath = path.Join(s.tmpDir, "key")
	s.certPath = path.Join(s.tmpDir, "cert")

	s.cleanups = append(s.cleanups, func() {
		_ = os.Remove(keyPath)
		_ = os.Remove(certPath)
		_ = os.Remove(keysdir)
		_ = os.RemoveAll(name)
	})
}

func steps(gs ...stepFunc) stepFunc {
	return func(t *testing.T, g *scenario) {
		for _, gf := range gs {
			gf(t, g)
		}
	}
}

func writeTempFile(pattern string, data []byte) (string, error) {
	f, err := os.CreateTemp("", pattern)
	if err != nil {
		return "", fmt.Errorf("error creating temp file: %v", err)
	}
	defer f.Close()

	n, err := f.Write(data)
	if err == nil && n < len(data) {
		err = io.ErrShortWrite
	}

	if err != nil {
		return "", fmt.Errorf("error writing temporary file: %v", err)
	}

	return f.Name(), nil
}

// poll calls the scenario function f every scenario interval
// until it returns no error or the scenario timeout occurs.
// If a timeout occurs, the last observed error is returned
// or wait.ErrWaitTimeout if no error occurred.
func poll(interval, timeout time.Duration, f func() error) error {
	var lastErr error

	ctx := context.Background()
	err := wait.PollUntilContextTimeout(ctx, interval, timeout, true, func(_ context.Context) (bool, error) {
		lastErr = f()

		if lastErr != nil {
			klog.V(4).Infof("error loading certificate: %v, retrying ...", lastErr)
			return false, nil
		}

		return true, nil
	})

	if err != nil && wait.Interrupted(err) && lastErr != nil {
		err = fmt.Errorf("%v: %v", err, lastErr)
	}

	return err
}
