//  Copyright 2026 Google LLC
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"

	certsv1beta1 "k8s.io/api/certificates/v1beta1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	certlisters "k8s.io/client-go/listers/certificates/v1beta1"
	corelisters "k8s.io/client-go/listers/core/v1"

	"github.com/agent-substrate/substrate/internal/egressmitmtrust"
)

// EgressTrustBundleName is the well-known name of the egress gateway CA
// bundle (#823): the trust anchors for the per-SNI leaves the egress gateway
// mints, maintained by atecontroller from the egress-mitm-ca-pool.
const EgressTrustBundleName = egressmitmtrust.BundleName

// supportedTrustBundles maps the bundle names the trustBundle data source
// may reference to their backing objects under each PKI delivery mode.
//
// TODO(#932): select by signer name + label selector, merging the matches, so
// a new root can be trialed on a subset of workloads.
var supportedTrustBundles = map[string]trustBundleObjects{
	EgressTrustBundleName: {
		clusterTrustBundle: egressmitmtrust.ClusterTrustBundleName,
		configMap:          egressmitmtrust.ConfigMapName,
	},
}

// trustBundleObjects names the object carrying a trust bundle under each
// delivery mode: a ClusterTrustBundle where certificates.k8s.io/v1beta1 is
// served, otherwise the ConfigMap atecontroller maintains in ate-system.
type trustBundleObjects struct {
	clusterTrustBundle string
	configMap          string
}

// supportedTrustBundleNames returns the allowlist, sorted, for error text.
func supportedTrustBundleNames() string {
	names := make([]string, 0, len(supportedTrustBundles))
	for name := range supportedTrustBundles {
		names = append(names, name)
	}
	slices.Sort(names)
	return strings.Join(names, ", ")
}

// trustBundleSource reads the raw PEM of a supported trust bundle from
// wherever this deployment publishes it, and recognizes that object in
// informer events.
type trustBundleSource interface {
	// objectName returns the name of the object carrying objects' bundle in
	// this delivery mode.
	objectName(objects trustBundleObjects) string
	// read returns the unsanitized bundle. A missing object is reported with
	// apierrors.IsNotFound.
	read(objects trustBundleObjects) (raw string, err error)
	// eventObjectName returns the name of an informer event's object when it
	// is of the type this source watches.
	eventObjectName(obj any) (string, bool)
}

// clusterTrustBundleSource reads certificates.k8s.io ClusterTrustBundles
// (projected PKI delivery: GKE, kind).
type clusterTrustBundleSource struct {
	lister certlisters.ClusterTrustBundleLister
}

func (s clusterTrustBundleSource) objectName(objects trustBundleObjects) string {
	return objects.clusterTrustBundle
}

func (s clusterTrustBundleSource) read(objects trustBundleObjects) (string, error) {
	ctb, err := s.lister.Get(objects.clusterTrustBundle)
	if err != nil {
		return "", err
	}
	return ctb.Spec.TrustBundle, nil
}

func (s clusterTrustBundleSource) eventObjectName(obj any) (string, bool) {
	ctb, ok := obj.(*certsv1beta1.ClusterTrustBundle)
	if !ok {
		return "", false
	}
	return ctb.Name, true
}

// configMapTrustBundleSource reads the ConfigMap atecontroller maintains in
// agent PKI delivery (clusters without certificates.k8s.io/v1beta1).
type configMapTrustBundleSource struct {
	lister corelisters.ConfigMapNamespaceLister
}

func (s configMapTrustBundleSource) objectName(objects trustBundleObjects) string {
	return egressmitmtrust.Namespace + "/" + objects.configMap
}

func (s configMapTrustBundleSource) read(objects trustBundleObjects) (string, error) {
	cm, err := s.lister.Get(objects.configMap)
	if err != nil {
		return "", err
	}
	bundle, ok := cm.Data[egressmitmtrust.ConfigMapKey]
	if !ok {
		return "", fmt.Errorf("has no %q key", egressmitmtrust.ConfigMapKey)
	}
	return bundle, nil
}

func (s configMapTrustBundleSource) eventObjectName(obj any) (string, bool) {
	cm, ok := obj.(*corev1.ConfigMap)
	if !ok || cm.Namespace != egressmitmtrust.Namespace {
		return "", false
	}
	return cm.Namespace + "/" + cm.Name, true
}

// bundleNamesFor returns the allowlisted bundle names that source backs with
// the object objectName.
func bundleNamesFor(source trustBundleSource, objectName string) []string {
	var names []string
	for name, objects := range supportedTrustBundles {
		if source.objectName(objects) == objectName {
			names = append(names, name)
		}
	}
	return names
}

// rawTrustBundle returns the unsanitized contents of the object backing the
// allowlisted bundle name, and that object's name.
func rawTrustBundle(source trustBundleSource, name string) (objectName, raw string, err error) {
	objects, supported := supportedTrustBundles[name]
	if !supported {
		return "", "", fmt.Errorf("trust bundle %q is not supported by this deployment (supported: %s)", name, supportedTrustBundleNames())
	}
	if source == nil {
		return "", "", fmt.Errorf("trust bundle %q: no trust bundle source configured", name)
	}
	objectName = source.objectName(objects)
	raw, err = source.read(objects)
	if apierrors.IsNotFound(err) {
		return "", "", fmt.Errorf("trust bundle %q: %s %q not found", name, sourceKind(source), objectName)
	} else if err != nil {
		return "", "", fmt.Errorf("trust bundle %q: while reading %s %q: %w", name, sourceKind(source), objectName, err)
	}
	return objectName, raw, nil
}

// sourceKind names the object kind a source reads, for error text.
func sourceKind(source trustBundleSource) string {
	if _, ok := source.(configMapTrustBundleSource); ok {
		return "ConfigMap"
	}
	return "ClusterTrustBundle"
}

// trustBundleHash hashes the raw backing contents. The sanitized output is
// not comparable as anchors are shuffled on every call.
func trustBundleHash(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}
