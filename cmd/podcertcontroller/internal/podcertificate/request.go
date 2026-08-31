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

package podcertificate

import (
	"bytes"
	"crypto"
	"encoding/pem"
	"fmt"
	"time"

	certsv1beta1 "k8s.io/api/certificates/v1beta1"
	"k8s.io/apimachinery/pkg/types"
)

// Request is a transport-neutral certificate request for one pod. It carries
// exactly the attested facts a PodCertificateRequest carries, so a signer can
// issue the same certificate whether the request arrived as a
// PodCertificateRequest object (kubelet, certificates.k8s.io) or over the
// issuer API (podcert-agent, clusters without that API).
//
// Every field must come from an API-server-attested source: the PCR spec, or a
// TokenReview of a bound ServiceAccount token. Never from the requester's own
// claims.
type Request struct {
	Namespace          string
	PodName            string
	PodUID             types.UID
	ServiceAccountName string
	ServiceAccountUID  types.UID
	NodeName           types.NodeName
	NodeUID            types.UID

	// PublicKey is the subject public key to certify. Proof of possession is
	// the transport's responsibility.
	PublicKey crypto.PublicKey

	// MaxExpirationSeconds caps the certificate lifetime. Zero means no cap
	// beyond the signer's own maximum.
	MaxExpirationSeconds int32
}

// FromPCR builds a Request from a PodCertificateRequest. The public key is
// taken from the stub PKCS#10 request (or the deprecated PKIXPublicKey).
func FromPCR(pcr *certsv1beta1.PodCertificateRequest) (*Request, error) {
	subjectPublicKey, err := PublicKey(pcr)
	if err != nil {
		return nil, err
	}
	req := &Request{
		Namespace:          pcr.ObjectMeta.Namespace,
		PodName:            pcr.Spec.PodName,
		PodUID:             pcr.Spec.PodUID,
		ServiceAccountName: pcr.Spec.ServiceAccountName,
		ServiceAccountUID:  pcr.Spec.ServiceAccountUID,
		NodeName:           pcr.Spec.NodeName,
		NodeUID:            pcr.Spec.NodeUID,
		PublicKey:          subjectPublicKey,
	}
	if pcr.Spec.MaxExpirationSeconds != nil {
		req.MaxExpirationSeconds = *pcr.Spec.MaxExpirationSeconds
	}
	return req, nil
}

// Lifetime returns the certificate lifetime for the request: the signer's
// maximum, shortened to MaxExpirationSeconds when that is set and smaller.
func (r *Request) Lifetime(signerMax time.Duration) time.Duration {
	if r.MaxExpirationSeconds <= 0 {
		return signerMax
	}
	requested := time.Duration(r.MaxExpirationSeconds) * time.Second
	if requested < signerMax {
		return requested
	}
	return signerMax
}

// Issued is a signed certificate chain and its validity schedule.
type Issued struct {
	// ChainPEM is the leaf followed by intermediates, PEM encoded.
	ChainPEM       string
	NotBefore      time.Time
	BeginRefreshAt time.Time
	NotAfter       time.Time
}

// EncodeChainPEM PEM-encodes a DER certificate chain, leaf first.
func EncodeChainPEM(chainDER [][]byte) (string, error) {
	chainPEM := &bytes.Buffer{}
	for _, certDER := range chainDER {
		if err := pem.Encode(chainPEM, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
			return "", fmt.Errorf("while encoding certificate to PEM: %w", err)
		}
	}
	return chainPEM.String(), nil
}
