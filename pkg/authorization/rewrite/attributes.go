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
	"sync"
	"text/template"

	"k8s.io/apiserver/pkg/authorization/authorizer"
)

// AttributesGenerator is a an interface for generating a list of attributes.
// Attributes must be adjusted dependant on the configuration and context.
type AttributesGenerator interface {
	Generate(context.Context, authorizer.Attributes) []authorizer.Attributes
}

// NonResourceAttributesGenerator reduces a given attribute to user and http based
// attributes.
type NonResourceAttributesGenerator struct{}

var _ AttributesGenerator = &NonResourceAttributesGenerator{}

// Generate reduces the original attributes to user and http based attributes.
func (d *NonResourceAttributesGenerator) Generate(ctx context.Context, attr authorizer.Attributes) []authorizer.Attributes {
	return []authorizer.Attributes{
		authorizer.AttributesRecord{
			User:            attr.GetUser(),
			Verb:            attr.GetVerb(),
			ResourceRequest: false,
			Path:            attr.GetPath(),
		},
	}
}

// ResourceAttributesGenerator uses the given attributes' user, http verb and
// verifies its authorization against a static kubernetes resource. The
// authorization is bound to that given kubernetes resource.
type ResourceAttributesGenerator struct {
	attributes *ResourceAttributes
}

var _ AttributesGenerator = &ResourceAttributesGenerator{}

// NewResourceAttributesGenerator creates a BoundAttributesGenerator.
func NewResourceAttributesGenerator(attributes *ResourceAttributes) *ResourceAttributesGenerator {
	return &ResourceAttributesGenerator{
		attributes: attributes,
	}
}

// Generate maps the given attributes user and verb to a static kubernetes
// resource.
func (b *ResourceAttributesGenerator) Generate(ctx context.Context, attr authorizer.Attributes) []authorizer.Attributes {
	return []authorizer.Attributes{
		authorizer.AttributesRecord{
			User:            attr.GetUser(),
			Verb:            attr.GetVerb(),
			Namespace:       b.attributes.Namespace,
			APIGroup:        b.attributes.APIGroup,
			APIVersion:      b.attributes.APIVersion,
			Resource:        b.attributes.Resource,
			Subresource:     b.attributes.Subresource,
			Name:            b.attributes.Name,
			ResourceRequest: true,
		},
	}
}

// TemplatedResourceAttributesGenerator uses the given attributes' user and http verb
// and verifies its authorization against a predefined kubernetes resource
// template. The template is rewritting using client input data, which is VERY
// DANGEROUS. It should only be used in a narrow use-case, where the upstream
// is interpreting the input data as well.
type TemplatedResourceAttributesGenerator struct {
	attributes *ResourceAttributes

	namespace   *template.Template
	apiGroup    *template.Template
	apiVersion  *template.Template
	resource    *template.Template
	subresource *template.Template
	name        *template.Template

	bufPool *sync.Pool
}

var _ AttributesGenerator = &TemplatedResourceAttributesGenerator{}

// NewTemplatedResourceAttributesGenerator returns a RewritingAttributesGenerator.
func NewTemplatedResourceAttributesGenerator(attributes *ResourceAttributes) *TemplatedResourceAttributesGenerator {
	return &TemplatedResourceAttributesGenerator{
		attributes: attributes,

		namespace:   template.Must(template.New("namespace").Parse(attributes.Namespace)),
		apiGroup:    template.Must(template.New("apiGroup").Parse(attributes.APIGroup)),
		apiVersion:  template.Must(template.New("apiVersion").Parse(attributes.APIVersion)),
		resource:    template.Must(template.New("resource").Parse(attributes.Resource)),
		subresource: template.Must(template.New("subresource").Parse(attributes.Subresource)),
		name:        template.Must(template.New("name").Parse(attributes.Name)),

		bufPool: &sync.Pool{
			New: func() interface{} {
				return &bytes.Buffer{}
			},
		},
	}
}

// Generate maps the given attributes and context against a pre-defined kubernetes
// resource template. The template is rewritting using client input data, which
// is VERY DANGEROUS. It should only be used in a narrow use-case, where the
// upstream is interpreting the input data as well.
func (r *TemplatedResourceAttributesGenerator) Generate(ctx context.Context, attr authorizer.Attributes) []authorizer.Attributes {
	params := getKubeRBACProxyParams(ctx)
	if len(params) == 0 {
		return nil
	}

	attrs := []authorizer.Attributes{}
	for _, param := range params {
		attrs = append(attrs,
			authorizer.AttributesRecord{
				User:            attr.GetUser(),
				Verb:            attr.GetVerb(),
				Namespace:       r.templateWithValue(r.namespace, param),
				APIGroup:        r.templateWithValue(r.apiGroup, param),
				APIVersion:      r.templateWithValue(r.apiVersion, param),
				Resource:        r.templateWithValue(r.resource, param),
				Subresource:     r.templateWithValue(r.subresource, param),
				Name:            r.templateWithValue(r.name, param),
				ResourceRequest: true,
			})
	}

	if len(attrs) == 0 {
		// If there are no params, we want to minimize the probability to run insecurely.
		return nil
	}

	return attrs
}

func (r *TemplatedResourceAttributesGenerator) templateWithValue(tmpl *template.Template, value string) string {
	buf := r.bufPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer r.bufPool.Put(buf)

	err := tmpl.Execute(buf, struct{ Value string }{Value: value})
	if err != nil {
		return ""
	}
	return buf.String()
}
