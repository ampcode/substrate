// Copyright 2026 Google LLC
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

// Package trustpublisher distributes signer trust anchors as a ConfigMap in
// every namespace, for clusters without the ClusterTrustBundle API. Pods mount
// the ConfigMap where they would otherwise project a clusterTrustBundle, and
// kubelet keeps the mounted file current the same way.
package trustpublisher

import (
	"context"
	"log/slog"
	"maps"
	"time"

	"github.com/agent-substrate/substrate/cmd/podcertcontroller/internal/signercontroller"
	"github.com/agent-substrate/substrate/internal/podcertapi"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
)

// ConfigMapName is the ConfigMap the publisher maintains in each namespace.
const ConfigMapName = podcertapi.TrustConfigMapName

// Key returns the ConfigMap data key holding signerName's trust bundle.
func Key(signerName string) string {
	return podcertapi.TrustKey(signerName)
}

// Hasher decides which replica maintains the ConfigMaps.
type Hasher interface {
	AssignedToThisReplica(ctx context.Context, item string) bool
}

// Publisher writes the signers' trust bundles to ConfigMapName in every
// active namespace.
type Publisher struct {
	kc      kubernetes.Interface
	hasher  Hasher
	signers []signercontroller.Issuer
}

// New returns a Publisher for signers.
func New(kc kubernetes.Interface, hasher Hasher, signers ...signercontroller.Issuer) *Publisher {
	return &Publisher{kc: kc, hasher: hasher, signers: signers}
}

// Run reconciles every namespace on a jittered period until ctx ends.
func (p *Publisher) Run(ctx context.Context, period time.Duration) {
	wait.JitterUntilWithContext(ctx, p.reconcileAll, period, 0.5, true)
}

func (p *Publisher) reconcileAll(ctx context.Context) {
	if !p.hasher.AssignedToThisReplica(ctx, "maintain-trust-configmaps") {
		return
	}

	want, err := p.desiredData()
	if err != nil {
		slog.ErrorContext(ctx, "Error while rendering trust bundles", slog.Any("err", err))
		return
	}

	namespaces, err := p.kc.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		slog.ErrorContext(ctx, "Error while listing namespaces", slog.Any("err", err))
		return
	}
	for _, ns := range namespaces.Items {
		if ns.Status.Phase == corev1.NamespaceTerminating {
			continue
		}
		if err := p.reconcileNamespace(ctx, ns.Name, want); err != nil {
			slog.ErrorContext(ctx, "Error while reconciling trust ConfigMap",
				slog.String("namespace", ns.Name), slog.Any("err", err))
		}
	}
}

func (p *Publisher) desiredData() (map[string]string, error) {
	data := make(map[string]string, len(p.signers))
	for _, signer := range p.signers {
		bundle, err := signer.TrustBundlePEM()
		if err != nil {
			return nil, err
		}
		data[Key(signer.SignerName())] = bundle
	}
	return data, nil
}

// ReconcileNamespace makes namespace's ConfigMap match the signers' current
// trust bundles.
func (p *Publisher) ReconcileNamespace(ctx context.Context, namespace string) error {
	want, err := p.desiredData()
	if err != nil {
		return err
	}
	return p.reconcileNamespace(ctx, namespace, want)
}

func (p *Publisher) reconcileNamespace(ctx context.Context, namespace string, want map[string]string) error {
	cms := p.kc.CoreV1().ConfigMaps(namespace)
	existing, err := cms.Get(ctx, ConfigMapName, metav1.GetOptions{})
	if k8serrors.IsNotFound(err) {
		_, err = cms.Create(ctx, &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      ConfigMapName,
				Namespace: namespace,
				Labels:    signercontroller.LiveBundleLabels,
			},
			Data: want,
		}, metav1.CreateOptions{})
		if err == nil {
			slog.InfoContext(ctx, "Created trust ConfigMap", slog.String("namespace", namespace))
		}
		return err
	} else if err != nil {
		return err
	}

	if maps.Equal(existing.Data, want) && maps.Equal(existing.Labels, signercontroller.LiveBundleLabels) {
		return nil
	}
	updated := existing.DeepCopy()
	updated.Labels = signercontroller.LiveBundleLabels
	updated.Data = want
	_, err = cms.Update(ctx, updated, metav1.UpdateOptions{})
	if err == nil {
		slog.InfoContext(ctx, "Updated trust ConfigMap", slog.String("namespace", namespace))
	}
	return err
}
