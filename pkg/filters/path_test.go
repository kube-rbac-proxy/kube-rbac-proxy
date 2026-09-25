/*
Copyright 2022 the kube-rbac-proxy maintainers All rights reserved.

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
package filters_test

import (
	"net/http"
	"net/http/httptest"
	"path"
	"testing"

	"github.com/brancz/kube-rbac-proxy/pkg/filters"
)

func emptyHandler(w http.ResponseWriter, r *http.Request) {}

func TestAllowPath(t *testing.T) {
	validPath := "/allowed"

	for _, tt := range []struct {
		name   string
		paths  []string
		status int
	}{
		{
			name:   "should let request through if path allowed",
			paths:  []string{validPath},
			status: http.StatusOK,
		},
		{
			name:   "should not let request through if path not allowed",
			paths:  []string{"/denied"},
			status: http.StatusNotFound,
		},
		{
			name:   "should let request through if no path specified",
			paths:  []string{},
			status: http.StatusOK,
		},
		{
			name:   "should not let request through if path is non-sense",
			paths:  []string{"[]a]"},
			status: http.StatusInternalServerError,
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req, err := http.NewRequest(http.MethodGet, validPath, nil)
			if err != nil {
				t.Fatal(err)
			}

			filters.WithAllowPaths(tt.paths, emptyHandler).ServeHTTP(rec, req)
			res := rec.Result()

			if res.StatusCode != tt.status {
				t.Errorf("want: %d\nhave: %d\n", tt.status, res.StatusCode)
			}
		})
	}
}

func TestAllowPathRejectsNonCanonicalPath(t *testing.T) {
	handler := filters.WithAllowPaths([]string{"/public/*"}, emptyHandler)

	req := httptest.NewRequest("GET", "/public/..", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code == http.StatusOK {
		t.Errorf("non-canonical path /public/.. was not rejected: got status %d, want 400", rec.Code)
	}
}

func TestIgnorePathRejectsNonCanonicalPath(t *testing.T) {
	var upstreamCalled bool
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalled = true
	})

	ignorePaths := []string{"/public/*"}
	handler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		cleaned := path.Clean(req.URL.Path)
		if cleaned != req.URL.Path {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		for _, pathIgnored := range ignorePaths {
			found, err := path.Match(pathIgnored, cleaned)
			if err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			if found {
				upstream.ServeHTTP(w, req)
				return
			}
		}
		http.NotFound(w, req)
	})

	req := httptest.NewRequest("GET", "/public/..", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if upstreamCalled {
		t.Error("non-canonical path /public/.. reached upstream via ignore-paths")
	}
	if rec.Code == http.StatusOK {
		t.Errorf("non-canonical path /public/.. was not rejected: got status %d, want 400", rec.Code)
	}
}
