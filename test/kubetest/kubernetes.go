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

package kubetest

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v2"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	kubeyaml "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/kubernetes"
)

func CreateServerCerts(client kubernetes.Interface, hostBase string) Action {
	return createCertsAction(client, hostBase, createSignedServerCert)
}

func CreateClientCerts(client kubernetes.Interface, commonName string) Action {
	return createCertsAction(client, commonName, createSignedClientCert)
}

func createCertsAction(client kubernetes.Interface, commonName string, createSignedCert createCertsFunc) Action {
	return func(ctx *ScenarioContext) error {
		trustCM, certsSecret, err := createCerts(commonName, createSignedCert)
		if err != nil {
			return fmt.Errorf("failed to create certs: %v", err)
		}

		_, err = client.CoreV1().ConfigMaps(ctx.Namespace).Create(context.TODO(), trustCM, metav1.CreateOptions{})
		if err != nil {
			return err
		}
		ctx.AddCleanUp(func() error {
			return client.CoreV1().ConfigMaps(ctx.Namespace).Delete(context.TODO(), trustCM.Name, metav1.DeleteOptions{})
		})

		_, err = client.CoreV1().Secrets(ctx.Namespace).Create(context.TODO(), certsSecret, metav1.CreateOptions{})
		if err != nil {
			return err
		}
		ctx.AddCleanUp(func() error {
			return client.CoreV1().Secrets(ctx.Namespace).Delete(context.TODO(), certsSecret.Name, metav1.DeleteOptions{})
		})

		return nil
	}
}

// createCerts creates a self-signed CA and a cert/key pair where the cert is signed by the CA.
// It returns a CM with the CA and a secret with the cert/key pair.
//
// Naming convention:
// - ConfigMap: <certCommonName>-trust
// - Secret: <certCommonName>-certs
func createCerts(certCommonName string, createSignedCert createCertsFunc) (*corev1.ConfigMap, *corev1.Secret, error) {
	caCert, caKey, err := createSelfSignedCA(fmt.Sprintf("%s-ca", certCommonName))
	if err != nil {
		return nil, nil, err
	}
	cert, key, err := createSignedCert(caCert, caKey, certCommonName)
	if err != nil {
		return nil, nil, err
	}

	configMapName := fmt.Sprintf("%s-trust", certCommonName)
	trustCM := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name: configMapName,
		},
		Data: map[string]string{
			"ca.crt": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})),
		},
	}

	secretName := fmt.Sprintf("%s-certs", certCommonName)
	certsSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: secretName,
		},
		Data: map[string][]byte{
			"tls.crt": pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: cert.Raw,
			}),
			"tls.key": []byte(pem.EncodeToMemory(&pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: x509.MarshalPKCS1PrivateKey(key),
			})),
		},
	}

	return trustCM, certsSecret, nil
}

func CreateServiceAccount(client kubernetes.Interface, name string) Action {
	return func(ctx *ScenarioContext) error {
		_, err := client.CoreV1().ServiceAccounts(ctx.Namespace).Create(context.TODO(),
			&corev1.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{Name: name},
			},
			metav1.CreateOptions{},
		)
		if err != nil {
			return err
		}
		ctx.AddCleanUp(func() error {
			return client.CoreV1().ServiceAccounts(ctx.Namespace).Delete(context.TODO(), name, metav1.DeleteOptions{})
		})
		return nil
	}
}

func CreatedManifests(client kubernetes.Interface, paths ...string) Action {
	return func(ctx *ScenarioContext) error {
		for _, path := range paths {
			content, err := os.ReadFile(path)
			if err != nil {
				return err
			}

			if len(content) == 0 {
				return fmt.Errorf("manifest has no content: %s", path)
			}

			var meta metav1.TypeMeta
			if err = yaml.Unmarshal(content, &meta); err != nil {
				return err
			}

			// TODO: This needs to be more generic!

			kind := strings.ToLower(meta.Kind)
			switch kind {
			case "clusterrole":
				if err := createClusterRole(client, ctx, content); err != nil {
					return err
				}
			case "clusterrolebinding":
				if err := createClusterRoleBinding(client, ctx, content); err != nil {
					return err
				}
			case "deployment":
				if err := createDeployment(client, ctx, content); err != nil {
					return err
				}
			case "service":
				if err := createService(client, ctx, content); err != nil {
					return err
				}
			case "serviceaccount":
				if err := createServiceAccount(client, ctx, content); err != nil {
					return err
				}
			case "secret":
				if err := createSecret(client, ctx, content); err != nil {
					return err
				}
			case "configmap":
				if err := createConfigmap(client, ctx, content); err != nil {
					return err
				}
			default:
				return fmt.Errorf("unable to unmarshal manifest with unknown kind: %s", kind)
			}
		}
		return nil
	}
}

func createClusterRole(client kubernetes.Interface, ctx *ScenarioContext, content []byte) error {
	r := bytes.NewReader(content)

	var cr *rbacv1.ClusterRole
	if err := kubeyaml.NewYAMLOrJSONDecoder(r, r.Len()).Decode(&cr); err != nil {
		return err
	}

	_, err := client.RbacV1().ClusterRoles().Create(context.TODO(), cr, metav1.CreateOptions{})

	ctx.AddCleanUp(func() error {
		return client.RbacV1().ClusterRoles().Delete(context.TODO(), cr.Name, metav1.DeleteOptions{})
	})

	return err
}

func createClusterRoleBinding(client kubernetes.Interface, ctx *ScenarioContext, content []byte) error {
	r := bytes.NewReader(content)

	var crb *rbacv1.ClusterRoleBinding
	if err := kubeyaml.NewYAMLOrJSONDecoder(r, r.Len()).Decode(&crb); err != nil {
		return err
	}

	_, err := client.RbacV1().ClusterRoleBindings().Create(context.TODO(), crb, metav1.CreateOptions{})

	ctx.AddCleanUp(func() error {
		return client.RbacV1().ClusterRoleBindings().Delete(context.TODO(), crb.Name, metav1.DeleteOptions{})
	})

	return err
}

func createDeployment(client kubernetes.Interface, ctx *ScenarioContext, content []byte) error {
	r := bytes.NewReader(content)

	var d appsv1.Deployment
	if err := kubeyaml.NewYAMLOrJSONDecoder(r, r.Len()).Decode(&d); err != nil {
		return err
	}

	d.Namespace = ctx.Namespace

	_, err := client.AppsV1().Deployments(d.Namespace).Create(context.TODO(), &d, metav1.CreateOptions{})

	ctx.AddCleanUp(func() error {
		dep, err := client.AppsV1().Deployments(d.Namespace).Get(context.TODO(), d.Name, metav1.GetOptions{})
		if err != nil {
			return err
		}

		sel, err := metav1.LabelSelectorAsSelector(dep.Spec.Selector)
		if err != nil {
			return err
		}

		logsFprintf(client, ctx, metav1.ListOptions{LabelSelector: sel.String()}, os.Stdout)

		err = client.AppsV1().Deployments(dep.Namespace).Delete(context.TODO(), dep.Name, metav1.DeleteOptions{})
		if err != nil {
			return err
		}

		return PodsAreGone(client, sel.String())(ctx)
	})

	return err
}

func logsFprintf(client kubernetes.Interface, ctx *ScenarioContext, opts metav1.ListOptions, w io.Writer) {
	pods, err := client.CoreV1().Pods(ctx.Namespace).List(context.TODO(), opts)
	if err != nil {
		return
	}

	for _, p := range pods.Items {
		for _, c := range p.Spec.Containers {
			fmt.Fprintf(w, "\n=== LOGS %s %s %s", ctx.Namespace, p.Name, c.Name)

			req := client.CoreV1().Pods(ctx.Namespace).GetLogs(p.GetName(), &corev1.PodLogOptions{
				Container: c.Name,
				Follow:    false,
			})

			stream, err := req.Stream(context.TODO())
			if err != nil {
				return
			}

			_, _ = io.Copy(w, stream)
		}
	}
}

func createService(client kubernetes.Interface, ctx *ScenarioContext, content []byte) error {
	r := bytes.NewReader(content)

	var s *corev1.Service
	if err := kubeyaml.NewYAMLOrJSONDecoder(r, r.Len()).Decode(&s); err != nil {
		return err
	}

	s.Namespace = ctx.Namespace

	_, err := client.CoreV1().Services(s.Namespace).Create(context.TODO(), s, metav1.CreateOptions{})

	ctx.AddCleanUp(func() error {
		return client.CoreV1().Services(s.Namespace).Delete(context.TODO(), s.Name, metav1.DeleteOptions{})
	})

	return err
}

func createServiceAccount(client kubernetes.Interface, ctx *ScenarioContext, content []byte) error {
	r := bytes.NewReader(content)

	var sa *corev1.ServiceAccount
	if err := kubeyaml.NewYAMLOrJSONDecoder(r, r.Len()).Decode(&sa); err != nil {
		return err
	}

	sa.Namespace = ctx.Namespace

	_, err := client.CoreV1().ServiceAccounts(sa.Namespace).Create(context.TODO(), sa, metav1.CreateOptions{})

	ctx.AddCleanUp(func() error {
		return client.CoreV1().ServiceAccounts(sa.Namespace).Delete(context.TODO(), sa.Name, metav1.DeleteOptions{})
	})

	return err
}

func createSecret(client kubernetes.Interface, ctx *ScenarioContext, content []byte) error {
	r := bytes.NewReader(content)

	var secret *corev1.Secret
	if err := kubeyaml.NewYAMLOrJSONDecoder(r, r.Len()).Decode(&secret); err != nil {
		return err
	}

	secret.Namespace = ctx.Namespace

	_, err := client.CoreV1().Secrets(secret.Namespace).Create(context.TODO(), secret, metav1.CreateOptions{})

	ctx.AddCleanUp(func() error {
		return client.CoreV1().Secrets(secret.Namespace).Delete(context.TODO(), secret.Name, metav1.DeleteOptions{})
	})

	return err
}

func createConfigmap(client kubernetes.Interface, ctx *ScenarioContext, content []byte) error {
	r := bytes.NewReader(content)

	var configmap *corev1.ConfigMap
	if err := kubeyaml.NewYAMLOrJSONDecoder(r, r.Len()).Decode(&configmap); err != nil {
		return err
	}

	configmap.Namespace = ctx.Namespace

	_, err := client.CoreV1().ConfigMaps(configmap.Namespace).Create(context.TODO(), configmap, metav1.CreateOptions{})

	ctx.AddCleanUp(func() error {
		return client.CoreV1().ConfigMaps(configmap.Namespace).Delete(context.TODO(), configmap.Name, metav1.DeleteOptions{})
	})

	return err
}

// PodIsCrashLoopBackOff checks if there is any pod that is in the state of CrashLoopBackOff.
// This is required to verify negative test cases.
func PodIsCrashLoopBackOff(client kubernetes.Interface, labels string) func(*ScenarioContext) error {
	return func(ctx *ScenarioContext) error {
		return wait.Poll(time.Second, time.Minute, func() (bool, error) {
			list, err := client.CoreV1().Pods(ctx.Namespace).List(context.TODO(), metav1.ListOptions{})
			if err != nil {
				return false, fmt.Errorf("failed to list pods: %v", err)
			}

			for _, p := range list.Items {
				for _, c := range p.Status.ContainerStatuses {
					if c.State.Waiting != nil &&
						c.Name == labels &&
						c.State.Waiting.Reason == "CrashLoopBackOff" {

						return true, nil
					}
				}
			}

			return false, nil
		})
	}
}

// PodsAreReady waits for a number if replicas matching the given labels to be ready.
// Returns a func directly (not Setup or Conditions) as it can be used in Given and When steps
func PodsAreReady(client kubernetes.Interface, replicas int, labels string) func(*ScenarioContext) error {
	return func(ctx *ScenarioContext) error {
		return wait.Poll(time.Second, time.Minute, func() (bool, error) {
			list, err := client.CoreV1().Pods(ctx.Namespace).List(context.TODO(), metav1.ListOptions{
				LabelSelector: labels,
			})
			if err != nil {
				return false, fmt.Errorf("failed to list pods: %v", err)
			}

			runningAndReady := 0
			for _, p := range list.Items {
				isRunningAndReady, err := podRunningAndReady(p)
				if err != nil {
					return false, err
				}

				if isRunningAndReady {
					runningAndReady++
				}
			}

			if runningAndReady == replicas {
				return true, nil
			}
			return false, nil
		})
	}
}

// PodsAreGone waits for pods being gone for the given labels.
// Returns a func directly (not Setup or Conditions) as it can be used in Given and When steps
func PodsAreGone(client kubernetes.Interface, labels string) func(*ScenarioContext) error {
	return func(ctx *ScenarioContext) error {
		return wait.Poll(time.Second, time.Minute, func() (bool, error) {
			list, err := client.CoreV1().Pods(ctx.Namespace).List(context.TODO(), metav1.ListOptions{
				LabelSelector: labels,
			})

			if err != nil {
				return false, fmt.Errorf("failed to list pods: %v", err)
			}

			return len(list.Items) == 0, nil
		})
	}
}

// ServiceIsReady waits for given service to exist and have at least 1 endpoint.
// Returns a func directly (not Setup or Conditions) as it can be used in Given and When steps
func ServiceIsReady(client kubernetes.Interface, service string) func(*ScenarioContext) error {
	return func(ctx *ScenarioContext) error {
		return wait.Poll(time.Second, time.Minute, func() (bool, error) {
			_, err := client.CoreV1().Services(ctx.Namespace).Get(context.TODO(), service, metav1.GetOptions{})
			if err != nil {
				return false, fmt.Errorf("failed to get service: %v", err)
			}

			endpoints, err := client.CoreV1().Endpoints(ctx.Namespace).Get(context.TODO(), service, metav1.GetOptions{})
			if err != nil {
				return false, fmt.Errorf("failed to get endpoints: %v", err)
			}

			amount := 0
			for _, s := range endpoints.Subsets {
				amount = amount + len(s.Addresses)
			}
			if amount >= 1 {
				return true, nil
			}

			return false, nil
		})
	}
}

// podRunningAndReady returns whether a pod is running and each container has
// passed it's ready state.
func podRunningAndReady(pod corev1.Pod) (bool, error) {
	switch pod.Status.Phase {
	case corev1.PodFailed, corev1.PodSucceeded:
		return false, fmt.Errorf("pod completed")
	case corev1.PodRunning:
		for _, cond := range pod.Status.Conditions {
			if cond.Type != corev1.PodReady {
				continue
			}
			return cond.Status == corev1.ConditionTrue, nil
		}
		return false, fmt.Errorf("pod ready condition not found")
	}
	return false, nil
}

type RunOptions struct {
	ServiceAccount               string
	TokenAudience                string
	ClientCertificatesSecretName string    // the name of the secret containing client certificates
	OutputStream                 io.Writer // Functional Options would be better
}

func RunSucceeds(client kubernetes.Interface, image string, name string, command []string, opts *RunOptions) Action {
	return func(ctx *ScenarioContext) error {
		return run(client, ctx, image, name, command, opts)
	}
}

func RunFails(client kubernetes.Interface, image string, name string, command []string, opts *RunOptions) Action {
	return func(ctx *ScenarioContext) error {
		err := run(client, ctx, image, name, command, opts)
		if err == nil {
			return fmt.Errorf("expected run to fail")
		}
		if err != errRun {
			return err
		}
		return nil
	}
}

func RunHasLogEntry(client kubernetes.Interface, image string, name string, command, logEntries []string, opts *RunOptions) Action {
	return func(ctx *ScenarioContext) error {
		if opts == nil {
			opts = &RunOptions{}
		}

		builder := &strings.Builder{}
		opts.OutputStream = builder
		if err := run(client, ctx, image, name, command, opts); err != nil {
			return fmt.Errorf("failed to run for log entries: %v", err)
		}

		output := builder.String()
		for _, entry := range logEntries {
			if !strings.Contains(output, entry) {
				return fmt.Errorf("log entry not found: %s", entry)
			}
		}

		return nil
	}
}

var errRun = fmt.Errorf("failed to run")

// run the command and return the Check with the container's logs
func run(client kubernetes.Interface, ctx *ScenarioContext, image string, name string, command []string, opts *RunOptions) error {
	labels := map[string]string{
		"app": name,
	}
	pod := corev1.PodTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{
			Labels: labels,
		},
		Spec: corev1.PodSpec{
			ServiceAccountName: "default",
			Containers: []corev1.Container{{
				Name:    name,
				Image:   image,
				Command: command,
			}},
			RestartPolicy: corev1.RestartPolicyNever,
		},
	}

	if opts != nil && opts.ServiceAccount != "" {
		pod.Spec.ServiceAccountName = opts.ServiceAccount
	}
	if opts != nil && opts.TokenAudience != "" {
		pod.Spec.Volumes = append(pod.Spec.Volumes, corev1.Volume{
			Name: "requestedtoken",
			VolumeSource: corev1.VolumeSource{
				Projected: &corev1.ProjectedVolumeSource{
					Sources: []corev1.VolumeProjection{{
						ServiceAccountToken: &corev1.ServiceAccountTokenProjection{
							Audience: opts.TokenAudience,
							Path:     "requestedtoken",
						},
					}},
				},
			},
		})
		pod.Spec.Containers[0].VolumeMounts = append(pod.Spec.Containers[0].VolumeMounts,
			corev1.VolumeMount{
				Name:      "requestedtoken",
				MountPath: "/var/run/secrets/tokens",
			},
		)
	}

	if opts != nil && len(opts.ClientCertificatesSecretName) > 0 {
		pod.Spec.Volumes = append(pod.Spec.Volumes, corev1.Volume{
			Name: "clientcertificates",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: opts.ClientCertificatesSecretName,
				},
			},
		})

		pod.Spec.Containers[0].VolumeMounts = append(pod.Spec.Containers[0].VolumeMounts,
			corev1.VolumeMount{
				Name:      "clientcertificates",
				MountPath: "/certs",
			},
		)
	}

	parallelism := int32(1)
	completions := int32(1)
	activeDeadlineSeconds := int64(60)
	backoffLimit := int32(10)
	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "kube-rbac-proxy-client-",
			Namespace:    ctx.Namespace,
		},
		Spec: batchv1.JobSpec{
			Parallelism:           &parallelism,
			Completions:           &completions,
			ActiveDeadlineSeconds: &activeDeadlineSeconds,
			BackoffLimit:          &backoffLimit,
			Template:              pod,
		},
	}

	batch, err := client.BatchV1().Jobs(ctx.Namespace).Create(context.TODO(), job, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create job: %v", err)
	}

	ctx.AddCleanUp(func() error {
		err := client.BatchV1().Jobs(ctx.Namespace).Delete(context.TODO(), batch.Name, metav1.DeleteOptions{})
		if err != nil {
			return fmt.Errorf("failed to delete job: %v", err)
		}

		return nil
	})

	watch, err := client.BatchV1().Jobs(ctx.Namespace).Watch(context.TODO(), metav1.SingleObject(batch.ObjectMeta))
	if err != nil {
		return fmt.Errorf("failed to watch job: %v", err)
	}

	if opts == nil {
		opts = &RunOptions{}
	}
	if opts.OutputStream == nil {
		opts.OutputStream = os.Stdout
	}

	for event := range watch.ResultChan() {
		job := event.Object.(*batchv1.Job)
		conditions := job.Status.Conditions

		failed := false
		for _, c := range conditions {
			if c.Type == batchv1.JobFailed {
				failed = c.Status == corev1.ConditionTrue
			}
		}

		if failed {
			logsFprintf(client, ctx, metav1.ListOptions{LabelSelector: "job-name=" + batch.Name}, opts.OutputStream)
			return errRun
		}

		complete := false
		for _, c := range conditions {
			if c.Type == batchv1.JobComplete && c.Status == corev1.ConditionTrue {
				complete = true
			}
		}
		if complete && !failed {
			logsFprintf(client, ctx, metav1.ListOptions{LabelSelector: "job-name=" + batch.Name}, opts.OutputStream)
			return nil
		}
	}

	return nil
}
