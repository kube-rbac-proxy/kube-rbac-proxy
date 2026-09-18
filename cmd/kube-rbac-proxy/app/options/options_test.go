/*
Copyright 2026 the kube-rbac-proxy maintainers. All rights reserved.

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
	"crypto/tls"
	"reflect"
	"testing"
)

func TestTLSCurvePreferencesFlag(t *testing.T) {
	o := NewProxyRunOptions()
	flagSets := o.Flags()

	if err := flagSets.FlagSet("kube-rbac-proxy").Parse([]string{"--tls-curve-preferences=23,29"}); err != nil {
		t.Fatalf("parse flags: %v", err)
	}

	want := []int32{int32(tls.CurveP256), int32(tls.X25519)}
	if !reflect.DeepEqual(o.TLS.CurvePreferences, want) {
		t.Errorf("CurvePreferences = %v, want %v", o.TLS.CurvePreferences, want)
	}
}
