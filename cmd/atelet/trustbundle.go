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

package main

import (
	"fmt"
	"slices"
	"strings"

	"github.com/agent-substrate/substrate/internal/egressmitmtrust"
	"github.com/agent-substrate/substrate/internal/pemutil"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	certlisters "k8s.io/client-go/listers/certificates/v1beta1"
	corelisters "k8s.io/client-go/listers/core/v1"
)

// EgressTrustBundleName is the well-known name of the egress gateway CA
// bundle (#823): the trust anchors for the per-SNI leaves the egress gateway
// mints, maintained by atecontroller from the egress-mitm-ca-pool.
const EgressTrustBundleName = egressmitmtrust.BundleName

// supportedTrustBundles maps the bundle names the trustBundle data source
// may reference to their backing objects. Enforced here rather than in the
// CRD schema so a configurable backend registry (#932) can widen it without
// a template API change.
var supportedTrustBundles = map[string]trustBundleObjects{
	EgressTrustBundleName: {
		clusterTrustBundle: egressmitmtrust.ClusterTrustBundleName,
		configMap:          egressmitmtrust.ConfigMapName,
	},
}

// trustBundleObjects names the object carrying a trust bundle under each
// delivery mode.
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
// wherever this deployment publishes it.
type trustBundleSource interface {
	// Read returns the bundle's PEM and the name of the object it came from.
	// A missing object is reported with apierrors.IsNotFound.
	Read(objects trustBundleObjects) (pem string, objectName string, err error)
}

// clusterTrustBundleSource reads certificates.k8s.io ClusterTrustBundles
// (projected PKI delivery: GKE, kind).
type clusterTrustBundleSource struct {
	lister certlisters.ClusterTrustBundleLister
}

func (s clusterTrustBundleSource) Read(objects trustBundleObjects) (string, string, error) {
	name := "ClusterTrustBundle " + objects.clusterTrustBundle
	ctb, err := s.lister.Get(objects.clusterTrustBundle)
	if err != nil {
		return "", name, err
	}
	return ctb.Spec.TrustBundle, name, nil
}

// configMapTrustBundleSource reads the ConfigMap atecontroller maintains in
// agent PKI delivery (clusters without certificates.k8s.io/v1beta1).
type configMapTrustBundleSource struct {
	lister corelisters.ConfigMapNamespaceLister
}

func (s configMapTrustBundleSource) Read(objects trustBundleObjects) (string, string, error) {
	name := "ConfigMap " + egressmitmtrust.Namespace + "/" + objects.configMap
	cm, err := s.lister.Get(objects.configMap)
	if err != nil {
		return "", name, err
	}
	bundle, ok := cm.Data[egressmitmtrust.ConfigMapKey]
	if !ok {
		return "", name, fmt.Errorf("has no %q key", egressmitmtrust.ConfigMapKey)
	}
	return bundle, name, nil
}

// resolveTrustBundle returns the sanitized PEM of the named trust bundle,
// resolving the name against the allowlist and reading the backing object
// through atelet's informer-backed source. Every error fails the actor start:
// an actor that declared a trust bundle must not start without one.
func resolveTrustBundle(source trustBundleSource, name string) ([]byte, error) {
	objects, supported := supportedTrustBundles[name]
	if !supported {
		return nil, fmt.Errorf("trust bundle %q is not supported by this deployment (supported: %s)", name, supportedTrustBundleNames())
	}
	if source == nil {
		return nil, fmt.Errorf("trust bundle %q: no trust bundle source configured", name)
	}
	bundle, objectName, err := source.Read(objects)
	if apierrors.IsNotFound(err) {
		return nil, fmt.Errorf("trust bundle %q: %s not found", name, objectName)
	} else if err != nil {
		return nil, fmt.Errorf("trust bundle %q: while reading %s: %w", name, objectName, err)
	}
	pemBundle, err := pemutil.SanitizeCertificateBundle([]byte(bundle))
	if err != nil {
		return nil, fmt.Errorf("trust bundle %q: unusable %s: %w", name, objectName, err)
	}
	return pemBundle, nil
}
