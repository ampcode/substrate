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

package podidentitysigner

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"net/url"
	"path"
	"time"

	"github.com/agent-substrate/substrate/cmd/podcertcontroller/internal/podcertificate"
	"github.com/agent-substrate/substrate/cmd/podcertcontroller/internal/signercontroller"
	"github.com/agent-substrate/substrate/internal/localca"
	"github.com/agent-substrate/substrate/internal/substratex509"
	certsv1beta1 "k8s.io/api/certificates/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/utils/clock"
)

const Name = "podidentity.podcert.ate.dev/identity"
const CTBPrefix = "podidentity.podcert.ate.dev:identity:"

type Impl struct {
	kc     kubernetes.Interface
	caPool localca.Pool

	clock clock.PassiveClock
}

func NewImpl(kc kubernetes.Interface, caPool localca.Pool, clock clock.PassiveClock) *Impl {
	return &Impl{
		kc:     kc,
		caPool: caPool,
		clock:  clock,
	}
}

var _ signercontroller.SignerImpl = (*Impl)(nil)

func (h *Impl) SignerName() string {
	return Name
}

// TrustBundlePEM returns the CA pool's trust anchors as PEM.
func (h *Impl) TrustBundlePEM() (string, error) {
	return signercontroller.TrustBundlePEM(h.caPool)
}

func (h *Impl) DesiredClusterTrustBundles() ([]*certsv1beta1.ClusterTrustBundle, error) {
	return signercontroller.PrimaryClusterTrustBundle(Name, CTBPrefix, h.caPool)
}

// MakeCert fulfills a PodCertificateRequest: it issues the certificate and
// writes it to the PCR status.
func (h *Impl) MakeCert(ctx context.Context, pcr *certsv1beta1.PodCertificateRequest) error {
	return signercontroller.FulfillPCR(ctx, h.kc, h.clock, h, pcr)
}

// Issue signs a pod identity certificate for an attested request.
func (h *Impl) Issue(ctx context.Context, req *podcertificate.Request) (*podcertificate.Issued, error) {
	// Fetch the pod to confirm it still exists under the attested UID.
	pod, err := h.kc.CoreV1().Pods(req.Namespace).Get(ctx, req.PodName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("while getting pod %s/%s: %w", req.Namespace, req.PodName, err)
	}

	if pod.ObjectMeta.UID != req.PodUID {
		return nil, fmt.Errorf("pod UID mismatch: expected %s, got %s", req.PodUID, pod.ObjectMeta.UID)
	}

	lifetime := req.Lifetime(24 * time.Hour)

	notBefore := h.clock.Now().Add(-2 * time.Minute)
	notAfter := notBefore.Add(lifetime)
	beginRefreshAt := notAfter.Add(-30 * time.Minute)

	spiffeURI := &url.URL{
		Scheme: "spiffe",
		Host:   "cluster.local",
		Path:   path.Join("ns", req.Namespace, "sa", req.ServiceAccountName),
	}

	template := &x509.Certificate{
		// Some golang certificate handling code assumes that if the parent and
		// template Subject fields compare equal, we are doing a self-signing
		// operation [1].
		//
		// I'm not sure if this is correct, but for defense in depth include
		// some random content in the subject.
		//
		// [1] https://cs.opensource.google/go/go/+/refs/tags/go1.27.0:src/crypto/x509/x509.go;l=1871
		Subject: pkix.Name{
			CommonName: rand.Text(),
		},
		BasicConstraintsValid: true,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		URIs:                  []*url.URL{spiffeURI},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		// AuthorityKeyID is automatically set to the SubjectKeyID of the parent
		// certificate.
	}

	// Fields are sourced from the attested request (PCR spec or TokenReview)
	// rather than the Pod object, which lacks the ServiceAccount and Node UIDs.
	podIdentity := &substratex509.PodIdentity{
		Namespace:          req.Namespace,
		ServiceAccountName: req.ServiceAccountName,
		ServiceAccountUID:  string(req.ServiceAccountUID),
		PodName:            req.PodName,
		PodUID:             string(req.PodUID),
		NodeName:           string(req.NodeName),
		NodeUID:            string(req.NodeUID),
	}
	if err := substratex509.AddPodIdentityToCertificate(podIdentity, template); err != nil {
		return nil, fmt.Errorf("while adding pod identity to certificate: %w", err)
	}

	chainDER, err := h.caPool.CreateCertificate(template, req.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("while signing certificate: %w", err)
	}

	chainPEM, err := podcertificate.EncodeChainPEM(chainDER)
	if err != nil {
		return nil, err
	}

	return &podcertificate.Issued{
		ChainPEM:       chainPEM,
		NotBefore:      notBefore,
		BeginRefreshAt: beginRefreshAt,
		NotAfter:       notAfter,
	}, nil
}
