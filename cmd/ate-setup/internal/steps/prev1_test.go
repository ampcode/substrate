// Copyright 2026 The Agent Substrate Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package steps

import (
	"context"
	"testing"
	"time"

	"go.ate.dev/substrate/cmd/ate-setup/internal/kube"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/utils/ptr"
)

func preV1CRD(name, plural string, versions ...string) *unstructured.Unstructured {
	vs := make([]any, 0, len(versions))
	for _, v := range versions {
		vs = append(vs, map[string]any{"name": v, "served": true, "storage": v == versions[0]})
	}
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "apiextensions.k8s.io/v1",
		"kind":       "CustomResourceDefinition",
		"metadata":   map[string]any{"name": name},
		"spec": map[string]any{
			"group":    "ate.dev",
			"names":    map[string]any{"plural": plural},
			"versions": vs,
		},
	}}
}

func preV1Object(kind, plural, namespace, name string, finalizers ...string) *unstructured.Unstructured {
	obj := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "ate.dev/v1alpha1",
		"kind":       kind,
		"metadata":   map[string]any{"name": name},
	}}
	if namespace != "" {
		obj.SetNamespace(namespace)
	}
	if len(finalizers) > 0 {
		obj.SetFinalizers(finalizers)
	}
	return obj
}

func scaledDeployment(namespace, name string) *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Spec:       appsv1.DeploymentSpec{Replicas: ptr.To[int32](2)},
	}
}

// The upgrade stops the provider, the worker pools (whose pods suspend their
// sandboxes before they exit), then the old control plane, and only then
// replaces the CRDs, with every finalizer that only the stopped controller
// would have cleared removed first.
func TestUpgradeFromV1alpha1(t *testing.T) {
	ctx := context.Background()
	pools := schema.GroupVersionResource{Group: "ate.dev", Version: "v1alpha1", Resource: "workerpools"}
	sandboxConfigs := schema.GroupVersionResource{Group: "ate.dev", Version: "v1alpha1", Resource: "sandboxconfigs"}
	workerPod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Namespace: "amp-orbs", Name: "amp-orbs-1a2b3c4d-x", Labels: map[string]string{workerPodLabel: "amp-orbs-1a2b3c4d"},
	}}
	cs := fake.NewClientset(
		scaledDeployment("amp-orbs", "amp-orb-provider"),
		scaledDeployment(NamespaceAteSystem, "ate-api-server"),
		scaledDeployment(NamespaceAteSystem, "ate-controller"),
		workerPod,
	)
	dc := dynamicfake.NewSimpleDynamicClient(clientgoscheme.Scheme,
		preV1CRD("workerpools.ate.dev", "workerpools", "v1alpha1"),
		preV1CRD("sandboxconfigs.ate.dev", "sandboxconfigs", "v1alpha1"),
		preV1Object("WorkerPool", "workerpools", "amp-orbs", "amp-orbs-1a2b3c4d"),
		preV1Object("SandboxConfig", "sandboxconfigs", "", "gvisor", "sandboxconfig.ate.dev/workerpool-protection"),
	)
	// The pool's Deployment and pods go with it on a real cluster through
	// garbage collection; here the pod disappears when the pool is deleted.
	var poolDeletedBefore struct{ provider bool }
	dc.PrependReactor("delete", "workerpools", func(action k8stesting.Action) (bool, runtime.Object, error) {
		dep, err := cs.AppsV1().Deployments("amp-orbs").Get(ctx, "amp-orb-provider", metav1.GetOptions{})
		if err != nil {
			return false, nil, err
		}
		poolDeletedBefore.provider = dep.Spec.Replicas != nil && *dep.Spec.Replicas == 0
		if err := cs.CoreV1().Pods("amp-orbs").Delete(ctx, workerPod.Name, metav1.DeleteOptions{}); err != nil {
			return false, nil, err
		}
		return false, nil, nil
	})
	// The control plane stops only after the workers are gone.
	var controlPlaneStoppedAfterPods bool
	cs.PrependReactor("patch", "deployments", func(action k8stesting.Action) (bool, runtime.Object, error) {
		if action.GetNamespace() == NamespaceAteSystem {
			_, err := dc.Resource(pools).Namespace("amp-orbs").Get(ctx, "amp-orbs-1a2b3c4d", metav1.GetOptions{})
			controlPlaneStoppedAfterPods = apierrors.IsNotFound(err)
		}
		return false, nil, nil
	})
	env := &Env{Kube: kube.NewFromClients(nil, cs, dc, cs.Discovery())}

	err := env.UpgradeFromV1alpha1(ctx, V1alpha1Upgrade{
		ScaleDown: []string{"amp-orbs/amp-orb-provider"},
		Timeout:   5 * time.Second,
	})
	if err != nil {
		t.Fatalf("UpgradeFromV1alpha1: %v", err)
	}

	if !poolDeletedBefore.provider {
		t.Error("the worker pools were deleted while the provider still ran")
	}
	if !controlPlaneStoppedAfterPods {
		t.Error("the control plane was scaled down before the worker pools were gone")
	}
	for _, name := range []string{"ate-api-server", "ate-controller"} {
		dep, err := cs.AppsV1().Deployments(NamespaceAteSystem).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if dep.Spec.Replicas == nil || *dep.Spec.Replicas != 0 {
			t.Errorf("%s has %v replicas, want 0", name, dep.Spec.Replicas)
		}
	}
	for _, crd := range []string{"workerpools.ate.dev", "sandboxconfigs.ate.dev"} {
		if _, err := dc.Resource(crdResource).Get(ctx, crd, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
			t.Errorf("CRD %s still exists (err %v)", crd, err)
		}
	}
	sc, err := dc.Resource(sandboxConfigs).Get(ctx, "gvisor", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(sc.GetFinalizers()) != 0 {
		t.Errorf("SandboxConfig still has finalizers %v", sc.GetFinalizers())
	}
}

// A cluster without the old CRDs, or one already on 1.0, is left alone.
func TestUpgradeFromV1alpha1NoOp(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name string
		crds []runtime.Object
	}{
		{name: "fresh cluster"},
		{name: "already 1.0", crds: []runtime.Object{preV1CRD("workerpools.ate.dev", "workerpools", "v1")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			provider := scaledDeployment("amp-orbs", "amp-orb-provider")
			cs := fake.NewClientset(provider)
			dc := dynamicfake.NewSimpleDynamicClient(clientgoscheme.Scheme, tc.crds...)
			env := &Env{Kube: kube.NewFromClients(nil, cs, dc, cs.Discovery())}
			if err := env.UpgradeFromV1alpha1(ctx, V1alpha1Upgrade{ScaleDown: []string{"amp-orbs/amp-orb-provider"}, Timeout: time.Second}); err != nil {
				t.Fatal(err)
			}
			dep, err := cs.AppsV1().Deployments("amp-orbs").Get(ctx, "amp-orb-provider", metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if *dep.Spec.Replicas != 2 {
				t.Errorf("provider was scaled to %d", *dep.Spec.Replicas)
			}
			for _, crd := range tc.crds {
				if _, err := dc.Resource(crdResource).Get(ctx, crd.(*unstructured.Unstructured).GetName(), metav1.GetOptions{}); err != nil {
					t.Errorf("CRD was touched: %v", err)
				}
			}
		})
	}
}

func TestUpgradeFromV1alpha1RejectsBadScaleDownTarget(t *testing.T) {
	cs := fake.NewClientset()
	dc := dynamicfake.NewSimpleDynamicClient(clientgoscheme.Scheme, preV1CRD("workerpools.ate.dev", "workerpools", "v1alpha1"))
	env := &Env{Kube: kube.NewFromClients(nil, cs, dc, cs.Discovery())}
	err := env.UpgradeFromV1alpha1(context.Background(), V1alpha1Upgrade{ScaleDown: []string{"amp-orb-provider"}, Timeout: time.Second})
	if err == nil {
		t.Fatal("expected an error for a target without a namespace")
	}
}
