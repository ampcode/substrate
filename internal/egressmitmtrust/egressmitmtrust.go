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

// Package egressmitmtrust names the objects that carry the egress gateway's
// MITM CA trust anchors between atecontroller (which derives them from the
// egress-mitm-ca-pool Secret) and atelet (which hands them to actors that
// declare the trust bundle).
//
// The bundle is published as a ClusterTrustBundle on clusters that serve
// certificates.k8s.io/v1beta1, and as a ConfigMap in ate-system otherwise.
// Both carry the same PEM.
package egressmitmtrust

const (
	// BundleName is the name actors reference in a trustBundle data source.
	BundleName = "egress-mitm.ate.dev"

	// SignerName identifies the MITM CA's trust domain.
	SignerName = "egress-mitm.ate.dev/mitm"

	// ClusterTrustBundleName is the cluster-scoped object in projected mode.
	ClusterTrustBundleName = "egress-mitm.ate.dev:mitm:primary-bundle"

	// Namespace, ConfigMapName, and ConfigMapKey locate the bundle in agent
	// mode.
	Namespace     = "ate-system"
	ConfigMapName = "egress-mitm-trust"
	ConfigMapKey  = "trust-bundle.pem"
)
