/*
Copyright 2025 kube-rbac-proxy authors. All rights reserved.

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

package kubetest

import (
	"context"
	"fmt"
	"maps"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilerrs "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"

	"github.com/brancz/kube-rbac-proxy/test/kubetest/testtemplates"
)

type KRPTestConfig struct {
	Flags               map[string]string
	UpstreamFlags       map[string]string
	UpstreamReplacement *corev1.Container

	MountedSecrets          map[string]*corev1.Secret      // mounts to /var/run/secrets/<key>
	MountedConfigMaps       map[string]*corev1.ConfigMap   // mounts to /var/run/configMaps/<key>
	SAClusterRoleBindings   map[string]*rbacv1.ClusterRole // maps local SA name to ClusterRole
	UserClusterRoleBindings map[string]*rbacv1.ClusterRole // maps user name to ClusterRole
	SARoleBindings          map[string]*rbacv1.Role        // maps local SA name to Role

	setupErrors []error
}

func NewBasicKubeRBACProxyTestConfig() *KRPTestConfig {
	return &KRPTestConfig{
		Flags: map[string]string{
			"secure-listen-address": "0.0.0.0:8443",
			"upstream":              "http://127.0.0.1:8081/",
			"v":                     "10",
		},
		UpstreamFlags: map[string]string{},
		SAClusterRoleBindings: map[string]*rbacv1.ClusterRole{
			"kube-rbac-proxy": testtemplates.GetKRPAuthDelegatorRole(),
			"default":         testtemplates.GetMetricsRoleForClient(),
		},
		UserClusterRoleBindings: make(map[string]*rbacv1.ClusterRole),
		SARoleBindings:          make(map[string]*rbacv1.Role),
		MountedSecrets:          make(map[string]*corev1.Secret),
		MountedConfigMaps:       make(map[string]*corev1.ConfigMap),
	}
}

func (c *KRPTestConfig) UpdateSAClusterRoleBindings(bindings map[string]*rbacv1.ClusterRole) *KRPTestConfig {
	maps.Copy(c.SAClusterRoleBindings, bindings)
	return c
}

func (c *KRPTestConfig) UpdateUserClusterRoleBindings(bindings map[string]*rbacv1.ClusterRole) *KRPTestConfig {
	maps.Copy(c.UserClusterRoleBindings, bindings)
	return c
}

func (c *KRPTestConfig) WithoutMetricsEndpointAllowClusterRole() *KRPTestConfig {
	delete(c.SAClusterRoleBindings, "default")
	return c
}

func (c *KRPTestConfig) WithConfigMap(mountDir string, cm *corev1.ConfigMap) *KRPTestConfig {
	c.MountedConfigMaps[mountDir] = cm
	return c
}

func (c *KRPTestConfig) UpdateFlags(flags map[string]string) *KRPTestConfig {
	maps.Copy(c.Flags, flags)
	return c
}

func (c *KRPTestConfig) UpdateUpstreamFlags(flags map[string]string) *KRPTestConfig {
	maps.Copy(c.UpstreamFlags, flags)
	return c
}

func (c *KRPTestConfig) WithAuthorizationConfigYAML(configYAML string) *KRPTestConfig {
	c.MountedConfigMaps["authorization-config"] = &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name: "authorization-config",
		},
		Data: map[string]string{
			"authorization.yaml": configYAML,
		},
	}
	c.Flags["config-file"] = "/var/run/configMaps/authorization-config/authorization.yaml"
	return c
}

func (c *KRPTestConfig) AddSAClusterRoleBinding(saName string, clusterRole *rbacv1.ClusterRole) *KRPTestConfig {
	if existing, ok := c.SAClusterRoleBindings[saName]; ok {
		c.setupErrors = append(c.setupErrors, fmt.Errorf(
			"SA %q already bound to cluster role %q, cannot also bind to %q",
			saName, existing.Name, clusterRole.Name,
		))
		return c
	}
	c.SAClusterRoleBindings[saName] = clusterRole
	return c
}

func (c *KRPTestConfig) AddUserClusterRoleBinding(userName string, clusterRole *rbacv1.ClusterRole) *KRPTestConfig {
	c.UserClusterRoleBindings[userName] = clusterRole
	return c
}

func (c *KRPTestConfig) AddSARoleBinding(saName string, role *rbacv1.Role) *KRPTestConfig {
	if existing, ok := c.SARoleBindings[saName]; ok {
		c.setupErrors = append(c.setupErrors, fmt.Errorf(
			"SA %q already bound to role %q, cannot also bind to %q",
			saName, existing.Name, role.Name,
		))
		return c
	}
	c.SARoleBindings[saName] = role
	return c
}

func (c *KRPTestConfig) WithClientCerts(commonNameBase string) *KRPTestConfig {
	trustCM, secret, err := createCerts(commonNameBase, createSignedClientCert)
	if err != nil {
		c.setupErrors = append(c.setupErrors, fmt.Errorf("failed to create client certs: %w", err))
		return c
	}
	c.MountedConfigMaps[commonNameBase+"-trust"] = trustCM
	c.MountedSecrets[commonNameBase] = secret
	return c
}

func (c *KRPTestConfig) WithServerCerts(hostBase string) *KRPTestConfig {
	trustCM, secret, err := createCerts(hostBase, createSignedServerCert)
	if err != nil {
		c.setupErrors = append(c.setupErrors, fmt.Errorf("failed to create server certs: %w", err))
		return c
	}
	c.MountedConfigMaps[hostBase+"-trust"] = trustCM
	c.MountedSecrets[hostBase] = secret
	return c
}

func (c *KRPTestConfig) ReplaceUpstream(upstream *corev1.Container) *KRPTestConfig {
	c.UpstreamReplacement = upstream
	return c
}

func (c *KRPTestConfig) Launch(client kubernetes.Interface) Action {
	if len(c.setupErrors) > 0 {
		return func(ctx *ScenarioContext) error {
			return utilerrs.NewAggregate(c.setupErrors)
		}
	}

	return func(ctx *ScenarioContext) error {
		finalDeployment := testtemplates.GetKRPDeploymentTemplate()

		for flag, value := range c.Flags {
			if len(value) == 0 {
				continue
			}
			finalDeployment.Spec.Template.Spec.Containers[0].Args = append(
				finalDeployment.Spec.Template.Spec.Containers[0].Args,
				fmt.Sprintf("--%s=%s", flag, value),
			)
		}

		if len(c.UpstreamFlags) > 0 && c.UpstreamReplacement != nil {
			return fmt.Errorf("cannot use both UpstreamFlags and UpstreamReplacement at the same time")
		}

		if c.UpstreamReplacement != nil {
			finalDeployment.Spec.Template.Spec.Containers[1] = *c.UpstreamReplacement
		}

		for flag, value := range c.UpstreamFlags {
			if len(value) == 0 {
				continue
			}
			finalDeployment.Spec.Template.Spec.Containers[1].Args = append(
				finalDeployment.Spec.Template.Spec.Containers[1].Args,
				fmt.Sprintf("--%s=%s", flag, value),
			)
		}

		for mountDir, secret := range c.MountedSecrets {
			if secret == nil {
				continue
			}
			secretCleanup, err := attachSecret(context.TODO(), client.CoreV1().Secrets(ctx.Namespace), secret, finalDeployment, mountDir)
			if err != nil {
				return err
			}
			ctx.CleanUp = append(ctx.CleanUp, secretCleanup)
		}

		for mountDir, configMap := range c.MountedConfigMaps {
			if configMap == nil {
				continue
			}
			cmCleanup, err := attachConfigMap(context.TODO(), client.CoreV1().ConfigMaps(ctx.Namespace), configMap, finalDeployment, mountDir)
			if err != nil {
				return err
			}
			ctx.CleanUp = append(ctx.CleanUp, cmCleanup)
		}

		// the service account name is currently hardcoded in the KRP deployment template
		const krpServiceAccountName = "kube-rbac-proxy"
		_, err := client.CoreV1().ServiceAccounts(ctx.Namespace).Create(context.TODO(),
			&corev1.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{Name: krpServiceAccountName},
			},
			metav1.CreateOptions{},
		)
		if err != nil {
			return err
		}
		ctx.AddCleanUp(func() error {
			return client.CoreV1().ServiceAccounts(ctx.Namespace).Delete(context.TODO(), krpServiceAccountName, metav1.DeleteOptions{})
		})

		for saName, clusterrole := range c.SAClusterRoleBindings {
			if clusterrole == nil {
				continue
			}
			cleanup, err := bindToClusterRole(context.TODO(), client, ctx.Namespace, saName, addSAToClusterRoleBinding, clusterrole)
			ctx.AddCleanUp(cleanup)
			if err != nil {
				return err
			}
		}

		for userName, clusterrole := range c.UserClusterRoleBindings {
			if clusterrole == nil {
				continue
			}
			cleanup, err := bindToClusterRole(context.TODO(), client, ctx.Namespace, userName, addUserToClusterRoleBinding, clusterrole)
			ctx.AddCleanUp(cleanup)
			if err != nil {
				return err
			}
		}

		for saName, role := range c.SARoleBindings {
			if role == nil {
				continue
			}
			cleanup, err := bindToRole(context.TODO(), client, ctx.Namespace, saName, role)
			ctx.AddCleanUp(cleanup)
			if err != nil {
				return err
			}
		}

		_, err = client.CoreV1().Services(ctx.Namespace).Create(context.TODO(), testtemplates.GetKRPService(), metav1.CreateOptions{})
		if err != nil {
			return err
		}
		ctx.AddCleanUp(func() error {
			return client.CoreV1().Services(ctx.Namespace).Delete(context.TODO(), testtemplates.GetKRPService().Name, metav1.DeleteOptions{})
		})

		_, err = client.AppsV1().Deployments(ctx.Namespace).Create(context.TODO(), finalDeployment, metav1.CreateOptions{})
		if err == nil {
			ctx.AddCleanUp(func() error {
				if err := client.AppsV1().Deployments(ctx.Namespace).Delete(context.TODO(), finalDeployment.Name, metav1.DeleteOptions{}); err != nil {
					return err
				}
				// TODO: wire proper context below
				return wait.PollUntilContextTimeout(context.TODO(), 1*time.Second, 15*time.Second, true, func(waitCtx context.Context) (bool, error) {
					podList, err := client.CoreV1().Pods(ctx.Namespace).List(waitCtx, metav1.ListOptions{
						LabelSelector: "app=kube-rbac-proxy",
					})
					if err == nil && len(podList.Items) == 0 {
						return true, nil
					}
					return false, err
				})
			})
		}

		return err
	}
}

func addSAToClusterRoleBinding(crb *rbacv1.ClusterRoleBinding, namespace, saName string) {
	crb.Subjects = append(crb.Subjects, rbacv1.Subject{
		Kind:      "ServiceAccount",
		Namespace: namespace,
		Name:      saName,
	})
}

func addUserToClusterRoleBinding(crb *rbacv1.ClusterRoleBinding, _, userName string) {
	crb.Subjects = append(crb.Subjects, rbacv1.Subject{
		Kind: "User",
		Name: userName,
	})
}

type addSubjectToCRBFunc func(crb *rbacv1.ClusterRoleBinding, namespace, subjectName string)

func bindToClusterRole(ctx context.Context, client kubernetes.Interface, namespace, subjectName string, addSubjectToCRB addSubjectToCRBFunc, clusterRole *rbacv1.ClusterRole) (func() error, error) {
	cleanups := []func() error{}
	cleanUp := func() error {
		errs := []error{}
		for _, cleanup := range cleanups {
			if err := cleanup(); err != nil {
				errs = append(errs, err)
			}
		}
		return utilerrs.NewAggregate(errs)
	}

	_, err := client.RbacV1().ClusterRoles().Create(ctx, clusterRole, metav1.CreateOptions{})
	if err != nil && !apierrors.IsAlreadyExists(err) {
		return cleanUp, err
	}
	cleanups = append(cleanups, func() error {
		return ignoreNotFound(client.RbacV1().ClusterRoles().Delete(ctx, clusterRole.Name, metav1.DeleteOptions{}))
	})

	crb := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: fmt.Sprintf("%s-%s", subjectName, clusterRole.Name),
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     clusterRole.Name,
		},
	}
	addSubjectToCRB(crb, namespace, subjectName)

	if _, err := client.RbacV1().ClusterRoleBindings().Create(ctx, crb, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return cleanUp, err
	}
	cleanups = append(cleanups, func() error {
		return ignoreNotFound(client.RbacV1().ClusterRoleBindings().Delete(ctx, crb.Name, metav1.DeleteOptions{}))
	})

	return cleanUp, nil
}

func bindToRole(ctx context.Context, client kubernetes.Interface, saNamespace, saName string, role *rbacv1.Role) (func() error, error) {
	cleanups := []func() error{}
	cleanUp := func() error {
		errs := []error{}
		for _, cleanup := range cleanups {
			if err := cleanup(); err != nil {
				errs = append(errs, err)
			}
		}
		return utilerrs.NewAggregate(errs)
	}

	_, err := client.RbacV1().Roles(role.Namespace).Create(ctx, role, metav1.CreateOptions{})
	if err != nil && !apierrors.IsAlreadyExists(err) {
		return cleanUp, err
	}
	cleanups = append(cleanups, func() error {
		return ignoreNotFound(client.RbacV1().Roles(role.Namespace).Delete(ctx, role.Name, metav1.DeleteOptions{}))
	})

	rb := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-%s", saName, role.Name),
			Namespace: role.Namespace,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     role.Name,
		},
		Subjects: []rbacv1.Subject{{
			Kind:      "ServiceAccount",
			Name:      saName,
			Namespace: saNamespace,
		}},
	}

	if _, err := client.RbacV1().RoleBindings(role.Namespace).Create(ctx, rb, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return cleanUp, err
	}
	cleanups = append(cleanups, func() error {
		return ignoreNotFound(client.RbacV1().RoleBindings(role.Namespace).Delete(ctx, rb.Name, metav1.DeleteOptions{}))
	})

	return cleanUp, nil
}

func attachSecret(ctx context.Context, client corev1client.SecretInterface, secret *corev1.Secret, deployment *appsv1.Deployment, mountDir string) (func() error, error) {
	if _, err := client.Create(ctx, secret, metav1.CreateOptions{}); err != nil {
		return nil, err
	}
	cleanup := func() error { return client.Delete(ctx, secret.Name, metav1.DeleteOptions{}) }
	podSpec := &deployment.Spec.Template.Spec
	podSpec.Containers[0].VolumeMounts = append(
		podSpec.Containers[0].VolumeMounts,
		corev1.VolumeMount{
			Name:      secret.Name,
			MountPath: fmt.Sprintf("/var/run/secrets/%s", mountDir),
			ReadOnly:  true,
		},
	)
	podSpec.Volumes = append(
		podSpec.Volumes,
		corev1.Volume{
			Name: secret.Name,
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: secret.Name,
				},
			},
		},
	)
	return cleanup, nil
}

func attachConfigMap(ctx context.Context, client corev1client.ConfigMapInterface, cm *corev1.ConfigMap, deployment *appsv1.Deployment, mountDir string) (func() error, error) {
	if _, err := client.Create(ctx, cm, metav1.CreateOptions{}); err != nil {
		return nil, err
	}
	cleanup := func() error { return client.Delete(ctx, cm.Name, metav1.DeleteOptions{}) }
	podSpec := &deployment.Spec.Template.Spec
	podSpec.Containers[0].VolumeMounts = append(
		podSpec.Containers[0].VolumeMounts,
		corev1.VolumeMount{
			Name:      cm.Name,
			MountPath: fmt.Sprintf("/var/run/configMaps/%s", mountDir),
			ReadOnly:  true,
		},
	)
	podSpec.Volumes = append(
		podSpec.Volumes,
		corev1.Volume{
			Name: cm.Name,
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: cm.Name,
					},
				},
			},
		},
	)
	return cleanup, nil
}

func ignoreNotFound(err error) error {
	if err == nil || apierrors.IsNotFound(err) {
		return nil
	}
	return err
}
