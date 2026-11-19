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

package path

import (
	"context"
	"fmt"

	"k8s.io/apiserver/pkg/authorization/authorizer"
	pathauthorizer "k8s.io/apiserver/pkg/authorization/path"
)

// NewAllowedPathsAuthorizer returns an authorizer that allows requests to
// `allowPaths` through with `NoOpinion` and denies all others. This ensures that
// subsequent authorizers in a union are still called on the requests that pass through
// this authorizer.
// The provided paths can include simple glob patterns.
func NewAllowedPathsAuthorizer(allowPaths []string) (authorizer.Authorizer, error) {
	delegatedPathAuthorizer, err := pathauthorizer.NewAuthorizer(allowPaths)
	if err != nil {
		return nil, fmt.Errorf("error creating path authorizer: %v", err)
	}

	return authorizer.AuthorizerFunc(func(ctx context.Context, attr authorizer.Attributes) (authorizer.Decision, string, error) {
		decision, reason, err := delegatedPathAuthorizer.Authorize(ctx, attr)

		// There is a match on the path, so we have no opinion and let subsequent
		// authorizers in a union decide.
		if err == nil && decision == authorizer.DecisionAllow {
			return authorizer.DecisionNoOpinion, reason, nil
		}

		return authorizer.DecisionDeny, fmt.Sprintf("NOT(%s)", reason), err
	}), nil
}

// NewPassthroughAuthorizer returns an authorizer that allows on matches for
// the given paths and has no opinion on all others. This allows skipping
// subsequent authorizers in a union, effectively passing through the given
// paths.
// The given paths can include simple glob patterns.
func NewPassthroughAuthorizer(ignorePaths []string) (authorizer.Authorizer, error) {
	return pathauthorizer.NewAuthorizer(ignorePaths)
}
