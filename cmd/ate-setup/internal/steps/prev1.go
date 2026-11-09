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
	"fmt"
	"strings"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/util/retry"

	"go.ate.dev/substrate/cmd/ate-setup/internal/kube"
	"go.ate.dev/substrate/cmd/ate-setup/internal/log"
)

// Upgrade of a cluster installed from the Amp fork of Substrate before 1.0.
//
// That install served the ate.dev CRDs at v1alpha1 and stored Actors in a
// database encoding 1.0 cannot read (see cmd/ateapi/internal/store/atepg
// prev1.go). 1.0 serves the CRDs at v1 only, with no conversion from
// v1alpha1, so the CRDs have to be replaced, which deletes every WorkerPool
// and SandboxConfig; and the first 1.0 ate-api-server rewrites the database,
// keeping suspended Actors and nothing else. UpgradeFromV1alpha1 turns that
// into an orderly stop of the old install, run before the chart applies 1.0:
//
//  1. Scale the listed Deployments to zero: the orb provider, so it stops
//     creating actors and pools while the install is torn down.
//  2. Delete every v1alpha1 WorkerPool and wait for the worker pods to go.
//     The old control plane is still running, so each pod's shutdown hands
//     its running sandboxes to ateapi to suspend durably; every orb that was
//     running is paused the same way a pause from Amp would have paused it.
//  3. Scale ate-api-server and ate-controller to zero. The database is then
//     quiet for the rewrite, and the old API server does not overlap with the
//     new one during the rolling update.
//  4. Remove the finalizers from the remaining ate.dev objects (only the old
//     controller would have), delete the three CRDs, and wait until they are
//     gone. The caller then applies 1.0's CRDs.
//
// A cluster whose workerpools.ate.dev CRD does not serve v1alpha1, including
// a fresh install and an upgrade that already ran this, needs nothing and
// returns at once, so the step can run on every upgrade.

// V1alpha1Upgrade configures UpgradeFromV1alpha1.
type V1alpha1Upgrade struct {
	// ScaleDown names Deployments as namespace/name to scale to zero before
	// the worker pools are deleted.
	ScaleDown []string
	// Timeout bounds each wait: the scale-downs, the worker pods draining,
	// and the CRD deletion.
	Timeout time.Duration
}

var (
	crdResource          = schema.GroupVersionResource{Group: "apiextensions.k8s.io", Version: "v1", Resource: "customresourcedefinitions"}
	v1alpha1WorkerPools  = schema.GroupVersionResource{Group: "ate.dev", Version: "v1alpha1", Resource: "workerpools"}
	v1alpha1CRDs         = []string{"workerpools.ate.dev", "sandboxconfigs.ate.dev", "csidriverconfigs.ate.dev"}
	workerPodLabel       = "ate.dev/worker-pool"
	preV1ControlPlane    = []string{"ate-api-server", "ate-controller"}
	preV1UpgradeStepName = "upgrade_from_v1alpha1"
)

// UpgradeFromV1alpha1 stops a pre-1.0 install so the caller can apply 1.0;
// see the file comment. It is a no-op unless workerpools.ate.dev serves
// v1alpha1.
func (e *Env) UpgradeFromV1alpha1(ctx context.Context, opts V1alpha1Upgrade) error {
	preV1, err := servesV1alpha1(ctx, e.Kube)
	if err != nil {
		return err
	}
	if !preV1 {
		return nil
	}
	log.Step(preV1UpgradeStepName)
	for _, ref := range opts.ScaleDown {
		namespace, name, ok := strings.Cut(ref, "/")
		if !ok || namespace == "" || name == "" {
			return fmt.Errorf("scale-down target %q is not namespace/name", ref)
		}
		if err := e.Kube.ScaleDeploymentToZero(ctx, namespace, name, opts.Timeout); err != nil {
			return err
		}
	}
	if err := deleteV1alpha1WorkerPools(ctx, e.Kube, opts.Timeout); err != nil {
		return err
	}
	for _, name := range preV1ControlPlane {
		if err := e.Kube.ScaleDeploymentToZero(ctx, NamespaceAteSystem, name, opts.Timeout); err != nil {
			return err
		}
	}
	return deleteV1alpha1CRDs(ctx, e.Kube, opts.Timeout)
}

// servesV1alpha1 reports whether the workerpools.ate.dev CRD on the cluster
// serves the pre-1.0 version.
func servesV1alpha1(ctx context.Context, c *kube.Client) (bool, error) {
	crd, err := c.Dynamic.Resource(crdResource).Get(ctx, "workerpools.ate.dev", metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("while reading the workerpools.ate.dev CRD: %w", err)
	}
	versions, _, err := unstructured.NestedSlice(crd.Object, "spec", "versions")
	if err != nil {
		return false, fmt.Errorf("while reading the workerpools.ate.dev CRD versions: %w", err)
	}
	for _, v := range versions {
		version, ok := v.(map[string]any)
		if !ok {
			continue
		}
		if name, _, _ := unstructured.NestedString(version, "name"); name == "v1alpha1" {
			return true, nil
		}
	}
	return false, nil
}

// deleteV1alpha1WorkerPools deletes every pre-1.0 WorkerPool and waits until
// no worker pod is left in the cluster. Each worker pod suspends its sandboxes
// on shutdown, which is what makes the wait take as long as the slowest
// checkpoint upload.
func deleteV1alpha1WorkerPools(ctx context.Context, c *kube.Client, timeout time.Duration) error {
	pools := c.Dynamic.Resource(v1alpha1WorkerPools)
	list, err := pools.List(ctx, metav1.ListOptions{})
	if apierrors.IsNotFound(err) {
		list = &unstructured.UnstructuredList{}
	} else if err != nil {
		return fmt.Errorf("while listing v1alpha1 WorkerPools: %w", err)
	}
	for _, pool := range list.Items {
		err := pools.Namespace(pool.GetNamespace()).Delete(ctx, pool.GetName(), metav1.DeleteOptions{})
		if err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("while deleting WorkerPool %s/%s: %w", pool.GetNamespace(), pool.GetName(), err)
		}
	}
	return c.WaitNoPods(ctx, workerPodLabel, timeout)
}

// deleteV1alpha1CRDs removes the finalizers from every remaining ate.dev
// object, deletes the CRDs, and waits for them to go. Only the old
// controller, stopped by now, would remove those finalizers.
func deleteV1alpha1CRDs(ctx context.Context, c *kube.Client, timeout time.Duration) error {
	crds := c.Dynamic.Resource(crdResource)
	for _, crdName := range v1alpha1CRDs {
		crd, err := crds.Get(ctx, crdName, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			continue
		}
		if err != nil {
			return fmt.Errorf("while reading the %s CRD: %w", crdName, err)
		}
		plural, _, _ := unstructured.NestedString(crd.Object, "spec", "names", "plural")
		versions, _, _ := unstructured.NestedSlice(crd.Object, "spec", "versions")
		for _, v := range versions {
			version, ok := v.(map[string]any)
			if !ok {
				continue
			}
			name, _, _ := unstructured.NestedString(version, "name")
			if served, _, _ := unstructured.NestedBool(version, "served"); !served {
				continue
			}
			res := c.Dynamic.Resource(schema.GroupVersionResource{Group: "ate.dev", Version: name, Resource: plural})
			if err := releaseFinalizers(ctx, res); err != nil {
				return fmt.Errorf("while releasing %s.ate.dev objects: %w", plural, err)
			}
			break
		}
		if err := crds.Delete(ctx, crdName, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("while deleting the %s CRD: %w", crdName, err)
		}
	}
	for _, crdName := range v1alpha1CRDs {
		if err := c.WaitResourceDeleted(ctx, crdResource, "", crdName, timeout); err != nil {
			return err
		}
	}
	c.InvalidateDiscovery()
	return nil
}

// releaseFinalizers clears the finalizers of every object of one resource,
// in every namespace.
func releaseFinalizers(ctx context.Context, res dynamic.NamespaceableResourceInterface) error {
	list, err := res.List(ctx, metav1.ListOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, item := range list.Items {
		if len(item.GetFinalizers()) == 0 {
			continue
		}
		scoped := res.Namespace(item.GetNamespace())
		err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			obj, err := scoped.Get(ctx, item.GetName(), metav1.GetOptions{})
			if err != nil {
				return err
			}
			if len(obj.GetFinalizers()) == 0 {
				return nil
			}
			obj.SetFinalizers(nil)
			_, err = scoped.Update(ctx, obj, metav1.UpdateOptions{})
			return err
		})
		if err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("%s/%s: %w", item.GetNamespace(), item.GetName(), err)
		}
	}
	return nil
}
