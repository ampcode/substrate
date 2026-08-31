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

// Package podcertapi defines the wire protocol and naming shared by
// podcertcontroller's issuer API and the podcert-agent sidecar.
//
// This is the "agent" delivery mode for pod certificates, used on clusters
// that do not serve certificates.k8s.io/v1beta1 (PodCertificateRequest and
// ClusterTrustBundle), such as AKS and EKS on Kubernetes 1.34-1.36. It
// produces exactly the files a projected podCertificate/clusterTrustBundle
// volume would: credential-bundle.pem and trust-bundle.pem.
package podcertapi

import (
	"strings"
	"time"
)

// DefaultAudience is the bound-token audience the issuer expects. Agents mint
// their token for it, so a token stolen from a pod cannot be replayed against
// the Kubernetes API or any other audience.
const DefaultAudience = "podcert.ate.dev"

// IssuePath is the HTTP path certificate requests are posted to.
const IssuePath = "/v1/certificates"

// TrustConfigMapName is the ConfigMap, maintained in every namespace, whose
// keys are TrustKey(signerName) and whose values are PEM trust bundles.
const TrustConfigMapName = "podcert-trust-bundles"

// TrustKey returns the ConfigMap data key holding signerName's trust bundle.
// "podidentity.podcert.ate.dev/identity" becomes
// "podidentity.podcert.ate.dev-identity.pem": ConfigMap keys cannot contain a
// slash.
func TrustKey(signerName string) string {
	return strings.ReplaceAll(signerName, "/", "-") + ".pem"
}

// Files written into a certificate directory, matching the paths Substrate
// manifests use for projected volumes.
const (
	CredentialBundleFile = "credential-bundle.pem"
	TrustBundleFile      = "trust-bundle.pem"
)

// IssueRequest is the JSON body of a certificate request.
type IssueRequest struct {
	SignerName string `json:"signerName"`
	// CSRPEM is a PEM-encoded PKCS#10 request. Only its public key and
	// signature (proof of possession) are used; requested names are ignored.
	CSRPEM               string `json:"csrPEM"`
	MaxExpirationSeconds int32  `json:"maxExpirationSeconds,omitempty"`
}

// IssueResponse is the JSON body of a successful issuance.
type IssueResponse struct {
	CertificateChainPEM string    `json:"certificateChainPEM"`
	NotBefore           time.Time `json:"notBefore"`
	BeginRefreshAt      time.Time `json:"beginRefreshAt"`
	NotAfter            time.Time `json:"notAfter"`
}
