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
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/textproto"
	"text/template"

	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/endpoints/request"
)

var _ authorizer.Authorizer = &rewritingAuthorizer{}

const rewriterParams = iota

type RewriteAttributesConfig struct {
	Rewrites               *SubjectAccessReviewRewrites `json:"rewrites,omitempty"`
	ResourceAttributes     *ResourceAttributes          `json:"resourceAttributes,omitempty"`
	ResourceAttributesFile string                       `json:"-"`
}

// SubjectAccessReviewRewrites describes how SubjectAccessReview may be
// rewritten on a given request.
type SubjectAccessReviewRewrites struct {
	ByQueryParameter *QueryParameterRewriteConfig `json:"byQueryParameter,omitempty"`
	ByHTTPHeader     *HTTPHeaderRewriteConfig     `json:"byHttpHeader,omitempty"`
}

// QueryParameterRewriteConfig describes which HTTP URL query parameter is to
// be used to rewrite a SubjectAccessReview on a given request.
type QueryParameterRewriteConfig struct {
	Name string `json:"name,omitempty"`
}

// HTTPHeaderRewriteConfig describes which HTTP header is to
// be used to rewrite a SubjectAccessReview on a given request.
type HTTPHeaderRewriteConfig struct {
	Name string `json:"name,omitempty"`
}

// ResourceAttributes describes attributes available for resource request authorization
type ResourceAttributes struct {
	Namespace   string `json:"namespace,omitempty"`
	APIGroup    string `json:"apiGroup,omitempty"`
	APIVersion  string `json:"apiVersion,omitempty"`
	Resource    string `json:"resource,omitempty"`
	Subresource string `json:"subresource,omitempty"`
	Name        string `json:"name,omitempty"`
}

func NewRewritingAuthorizer(delegate authorizer.Authorizer, config *RewriteAttributesConfig) *rewritingAuthorizer {
	rewriteConfig := config
	if rewriteConfig == nil {
		rewriteConfig = &RewriteAttributesConfig{}
	}

	return &rewritingAuthorizer{
		config:   rewriteConfig,
		delegate: delegate,
	}
}

type rewritingAuthorizer struct {
	config   *RewriteAttributesConfig
	delegate authorizer.Authorizer
}

// GetRequestAttributes populates authorizer attributes for the requests to kube-rbac-proxy.
func (n *rewritingAuthorizer) Authorize(ctx context.Context, attrs authorizer.Attributes) (authorizer.Decision, string, error) {
	proxyAttrs := n.getKubeRBACProxyAuthzAttributes(ctx, attrs)

	if len(proxyAttrs) == 0 {
		return authorizer.DecisionDeny,
			"The request or configuration is malformed.",
			fmt.Errorf("bad request. The request or configuration is malformed")
	}

	var (
		authorized authorizer.Decision
		reason     string
		err        error
	)
	for _, at := range proxyAttrs {
		authorized, reason, err = n.delegate.Authorize(ctx, at)
		if err != nil {
			return authorizer.DecisionDeny,
				"AuthorizationError",
				fmt.Errorf("authorization error (user=%s, verb=%s, resource=%s, subresource=%s): %w", at.GetName(), at.GetVerb(), at.GetResource(), at.GetSubresource(), err)
		}
		if authorized != authorizer.DecisionAllow {
			return authorizer.DecisionDeny,
				fmt.Sprintf("Forbidden (user=%s, verb=%s, resource=%s, subresource=%s): %s", at.GetName(), at.GetVerb(), at.GetResource(), at.GetSubresource(), reason),
				nil
		}
	}

	if authorized == authorizer.DecisionAllow {
		return authorized, "", nil
	}

	return authorizer.DecisionDeny,
		"No attribute combination matched",
		nil
}

// ConditionsAwareAuthorize is not conditions-aware, converts the Authorize decision.
func (n *rewritingAuthorizer) ConditionsAwareAuthorize(ctx context.Context, a authorizer.Attributes) authorizer.ConditionsAwareDecision {
	return authorizer.ConditionsAwareDecisionFromParts(n.Authorize(ctx, a))
}

// EvaluateConditions is not supported by this authorizer.
func (n *rewritingAuthorizer) EvaluateConditions(_ context.Context, _ authorizer.ConditionsAwareDecision, _ authorizer.ConditionsData) (authorizer.Decision, string, error) {
	return authorizer.DecisionDeny, "", authorizer.ErrorConditionEvaluationNotSupported
}

func (n *rewritingAuthorizer) getKubeRBACProxyAuthzAttributes(ctx context.Context, origAttrs authorizer.Attributes) []authorizer.Attributes {
	u := origAttrs.GetUser()
	apiVerb := origAttrs.GetVerb()
	path := origAttrs.GetPath()

	attrs := []authorizer.Attributes{}
	if n.config.ResourceAttributes == nil {
		// Default attributes mirror the API attributes that would allow this access to kube-rbac-proxy
		return append(attrs,
			authorizer.AttributesRecord{
				User:            u,
				Verb:            apiVerb,
				ResourceRequest: false,
				Path:            path,
			})
	}

	if n.config.Rewrites == nil {
		return append(attrs,
			authorizer.AttributesRecord{
				User:            u,
				Verb:            apiVerb,
				Namespace:       n.config.ResourceAttributes.Namespace,
				APIGroup:        n.config.ResourceAttributes.APIGroup,
				APIVersion:      n.config.ResourceAttributes.APIVersion,
				Resource:        n.config.ResourceAttributes.Resource,
				Subresource:     n.config.ResourceAttributes.Subresource,
				Name:            n.config.ResourceAttributes.Name,
				ResourceRequest: true,
			})

	}

	params := GetKubeRBACProxyParams(ctx)
	if len(params) == 0 {
		return nil
	}

	for _, param := range params {
		attrs = append(attrs,
			authorizer.AttributesRecord{
				User:            u,
				Verb:            apiVerb,
				Namespace:       templateWithValue(n.config.ResourceAttributes.Namespace, param),
				APIGroup:        templateWithValue(n.config.ResourceAttributes.APIGroup, param),
				APIVersion:      templateWithValue(n.config.ResourceAttributes.APIVersion, param),
				Resource:        templateWithValue(n.config.ResourceAttributes.Resource, param),
				Subresource:     templateWithValue(n.config.ResourceAttributes.Subresource, param),
				Name:            templateWithValue(n.config.ResourceAttributes.Name, param),
				ResourceRequest: true,
			})
	}

	return attrs
}

func templateWithValue(templateString, value string) string {
	tmpl, _ := template.New("valueTemplate").Parse(templateString)
	out := bytes.NewBuffer(nil)
	err := tmpl.Execute(out, struct{ Value string }{Value: value})
	if err != nil {
		return ""
	}
	return out.String()
}

func WithKubeRBACProxyParamsHandler(handler http.Handler, config *RewriteAttributesConfig) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = r.WithContext(WithKubeRBACProxyParams(r.Context(), requestToParams(config, r)))
		handler.ServeHTTP(w, r)
	})
}

func requestToParams(config *RewriteAttributesConfig, req *http.Request) []string {
	params := []string{}
	if config == nil || config.Rewrites == nil {
		return nil
	}

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

func WithKubeRBACProxyParams(ctx context.Context, params []string) context.Context {
	return request.WithValue(ctx, rewriterParams, params)
}

func GetKubeRBACProxyParams(ctx context.Context) []string {
	params, ok := ctx.Value(rewriterParams).([]string)
	if !ok {
		return nil
	}
	return params
}
