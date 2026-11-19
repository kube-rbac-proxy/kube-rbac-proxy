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
	"fmt"

	"k8s.io/apiserver/pkg/authorization/authorizer"
)

func NewRewritingAuthorizer(delegate authorizer.Authorizer, attrsGenerator AttributesGenerator) authorizer.Authorizer {
	return &rewritingAuthorizer{
		delegate:            delegate,
		attributesGenerator: attrsGenerator,
	}
}

type rewritingAuthorizer struct {
	delegate            authorizer.Authorizer
	attributesGenerator AttributesGenerator
}

var _ authorizer.Authorizer = &rewritingAuthorizer{}

// Authorize generates a list of attributes based on the given attributes generator
// and context. All attributes must be authorized to allow the request.
// If no attributes are generated, the request is denied.
func (n *rewritingAuthorizer) Authorize(ctx context.Context, attrs authorizer.Attributes) (authorizer.Decision, string, error) {
	proxyAttrs := n.attributesGenerator.Generate(ctx, attrs)

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

	// AND logic on all SubjectAccessReview requests.
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
		return authorizer.DecisionAllow, "", nil
	}

	// Most probably never happens.
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
