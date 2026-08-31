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

package signercontroller

import (
	"bytes"
	"context"
	"encoding/pem"
	"fmt"

	"github.com/agent-substrate/substrate/cmd/podcertcontroller/internal/podcertificate"
	"github.com/agent-substrate/substrate/internal/localca"
	certsv1beta1 "k8s.io/api/certificates/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/utils/clock"
	"k8s.io/utils/ptr"
)

// Issuer signs certificates for attested pod requests, independently of how
// the request reached the controller. Both the PodCertificateRequest path and
// the issuer API path end here.
type Issuer interface {
	SignerName() string
	Issue(context.Context, *podcertificate.Request) (*podcertificate.Issued, error)
	// TrustBundlePEM returns the signer's current trust anchors.
	TrustBundlePEM() (string, error)
}

// FulfillPCR issues the certificate a PodCertificateRequest asks for and
// records it in the PCR status.
func FulfillPCR(ctx context.Context, kc kubernetes.Interface, clock clock.PassiveClock, issuer Issuer, pcr *certsv1beta1.PodCertificateRequest) error {
	req, err := podcertificate.FromPCR(pcr)
	if err != nil {
		return err
	}

	issued, err := issuer.Issue(ctx, req)
	if err != nil {
		return err
	}

	pcr = pcr.DeepCopy()
	pcr.Status.Conditions = []metav1.Condition{
		{
			Type:               certsv1beta1.PodCertificateRequestConditionTypeIssued,
			Status:             metav1.ConditionTrue,
			Reason:             "Reason",
			Message:            "Issued",
			LastTransitionTime: metav1.NewTime(clock.Now()),
		},
	}
	pcr.Status.CertificateChain = issued.ChainPEM
	pcr.Status.NotBefore = ptr.To(metav1.NewTime(issued.NotBefore))
	pcr.Status.BeginRefreshAt = ptr.To(metav1.NewTime(issued.BeginRefreshAt))
	pcr.Status.NotAfter = ptr.To(metav1.NewTime(issued.NotAfter))

	_, err = kc.CertificatesV1beta1().PodCertificateRequests(pcr.ObjectMeta.Namespace).UpdateStatus(ctx, pcr, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("while updating PodCertificateRequest: %w", err)
	}

	return nil
}

// TrustBundlePEM renders a CA pool's trust anchors as concatenated
// CERTIFICATE PEM blocks.
func TrustBundlePEM(caPool localca.Pool) (string, error) {
	trustAnchors, err := caPool.TrustAnchors()
	if err != nil {
		return "", fmt.Errorf("while retrieving CA pool trust anchors: %w", err)
	}

	bundle := bytes.Buffer{}
	for _, anchor := range trustAnchors {
		block := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: anchor.Raw,
		})
		_, _ = bundle.Write(block)
	}
	return bundle.String(), nil
}

// LiveBundleLabels marks the trust bundle consumers should select.
var LiveBundleLabels = map[string]string{
	"podcert.ate.dev/canarying": "live",
}

// PrimaryClusterTrustBundle returns the single live ClusterTrustBundle a
// signer publishes, named <ctbPrefix>primary-bundle.
func PrimaryClusterTrustBundle(signerName, ctbPrefix string, caPool localca.Pool) ([]*certsv1beta1.ClusterTrustBundle, error) {
	trustBundle, err := TrustBundlePEM(caPool)
	if err != nil {
		return nil, err
	}

	return []*certsv1beta1.ClusterTrustBundle{{
		ObjectMeta: metav1.ObjectMeta{
			Name:   ctbPrefix + "primary-bundle",
			Labels: LiveBundleLabels,
		},
		Spec: certsv1beta1.ClusterTrustBundleSpec{
			SignerName:  signerName,
			TrustBundle: trustBundle,
		},
	}}, nil
}
