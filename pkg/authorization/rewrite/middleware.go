/*
Copyright 2023 the kube-rbac-proxy maintainers. All rights reserved.

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
package rewrite

import (
	"context"
	"net/http"
	"net/textproto"

	"k8s.io/apiserver/pkg/endpoints/request"
)

// WithKubeRBACProxyParamsHandler returns a handler that adds the params from
// the request to the context from pre-defined locations.
// They can origin from the query parameters or from the HTTP headers.
func WithKubeRBACProxyParamsHandler(handler http.Handler, config *RewriteAttributesConfig) http.Handler {
	if config == nil || config.Rewrites == nil {
		return handler
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// If config.Rewrites is defined, the client input is used to rewrite the
		// attributes, according to the templates defined in configuration.
		r = r.WithContext(WithKubeRBACProxyParams(
			r.Context(),
			requestToParams(config, r),
		))

		handler.ServeHTTP(w, r)
	})
}

// requestToParams returns the params from the request that should be used to
// rewrite the attributes.
func requestToParams(config *RewriteAttributesConfig, req *http.Request) []string {
	params := []string{}

	// FIXME / TODO: We should add a flag (--insecure-pass-through) that is required in order
	//               to not remove the query / header attributes after consumption.
	if config.Rewrites.ByQueryParameter != nil && config.Rewrites.ByQueryParameter.Name != "" {
		if ps, ok := req.URL.Query()[config.Rewrites.ByQueryParameter.Name]; ok {
			params = append(params, ps...)
		}
	}
	if config.Rewrites.ByHTTPHeader != nil && config.Rewrites.ByHTTPHeader.Name != "" {
		mimeHeader := textproto.MIMEHeader(req.Header)
		mimeKey := textproto.CanonicalMIMEHeaderKey(config.Rewrites.ByHTTPHeader.Name)
		if ps, ok := mimeHeader[mimeKey]; ok {
			params = append(params, ps...)
		}
	}
	return params
}

// WithKubeRBACProxyParams adds the values from the pre-defined location to the
// context.
func WithKubeRBACProxyParams(ctx context.Context, params []string) context.Context {
	if len(params) == 0 {
		return ctx
	}

	return request.WithValue(ctx, rewriterParams, params)
}

// getKubeRBACProxyParams returns the values from the context that should be
// used to rewrite the attributes.
func getKubeRBACProxyParams(ctx context.Context) []string {
	params, _ := ctx.Value(rewriterParams).([]string)

	return params
}
