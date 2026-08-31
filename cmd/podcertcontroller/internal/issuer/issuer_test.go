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

package issuer

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/agent-substrate/substrate/cmd/podcertcontroller/internal/podidentitysigner"
	"github.com/agent-substrate/substrate/internal/localca"
	"github.com/agent-substrate/substrate/internal/substratex509"
	authnv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

type fixedClock struct{ now time.Time }

func (c fixedClock) Now() time.Time                  { return c.now }
func (c fixedClock) Since(t time.Time) time.Duration { return c.now.Sub(t) }

var testNow = time.Now().UTC().Truncate(time.Second)

// tokenReviewReactor answers TokenReview creates from a table of tokens.
func tokenReviewReactor(t *testing.T, wantAudience string, tokens map[string]authnv1.TokenReviewStatus) k8stesting.ReactionFunc {
	return func(action k8stesting.Action) (bool, runtime.Object, error) {
		create, ok := action.(k8stesting.CreateAction)
		if !ok {
			return false, nil, nil
		}
		review, ok := create.GetObject().(*authnv1.TokenReview)
		if !ok {
			return false, nil, nil
		}
		if len(review.Spec.Audiences) != 1 || review.Spec.Audiences[0] != wantAudience {
			t.Errorf("TokenReview requested audiences %v, want [%s]", review.Spec.Audiences, wantAudience)
		}
		out := review.DeepCopy()
		status, ok := tokens[review.Spec.Token]
		if !ok {
			out.Status = authnv1.TokenReviewStatus{Error: "[invalid bearer token]"}
			return true, out, nil
		}
		out.Status = status
		return true, out, nil
	}
}

func boundPodStatus(namespace, sa, saUID, pod, podUID, node, nodeUID string) authnv1.TokenReviewStatus {
	extra := map[string]authnv1.ExtraValue{
		extraPodName: {pod},
		extraPodUID:  {podUID},
	}
	if node != "" {
		extra[extraNodeName] = authnv1.ExtraValue{node}
		extra[extraNodeUID] = authnv1.ExtraValue{nodeUID}
	}
	return authnv1.TokenReviewStatus{
		Authenticated: true,
		Audiences:     []string{DefaultAudience},
		User: authnv1.UserInfo{
			Username: "system:serviceaccount:" + namespace + ":" + sa,
			UID:      saUID,
			Extra:    extra,
		},
	}
}

func csrPEM(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatalf("while creating CSR: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

func post(t *testing.T, h http.Handler, token string, body any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("while marshalling body: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, Path, bytes.NewReader(raw))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestIssue(t *testing.T) {
	ca, err := localca.GenerateCA("test-ca", localca.KeyTypeED25519, 365*24*time.Hour)
	if err != nil {
		t.Fatalf("while generating CA: %v", err)
	}
	caPool := &localca.ConcretePool{CAs: []*localca.CA{ca}}

	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Namespace: "ate-system", Name: "atelet-abcde", UID: types.UID("pod-uid-1"),
	}}
	kc := fake.NewSimpleClientset(pod)
	kc.PrependReactor("create", "tokenreviews", tokenReviewReactor(t, DefaultAudience, map[string]authnv1.TokenReviewStatus{
		"good":      boundPodStatus("ate-system", "atelet", "sa-uid-1", "atelet-abcde", "pod-uid-1", "node-1", "node-uid-1"),
		"no-node":   boundPodStatus("ate-system", "atelet", "sa-uid-1", "atelet-abcde", "pod-uid-1", "", ""),
		"not-a-pod": {Authenticated: true, Audiences: []string{DefaultAudience}, User: authnv1.UserInfo{Username: "system:serviceaccount:ate-system:atelet", UID: "sa-uid-1"}},
		"human":     {Authenticated: true, Audiences: []string{DefaultAudience}, User: authnv1.UserInfo{Username: "alice@example.com"}},
		"wrong-aud": {Authenticated: true, Audiences: []string{"https://kubernetes.default.svc"}, User: authnv1.UserInfo{Username: "system:serviceaccount:ate-system:atelet"}},
		"unauthn":   {Authenticated: false},
	}))

	signer := podidentitysigner.NewImpl(kc, caPool, fixedClock{now: testNow})
	h := New(kc, DefaultAudience, signer).Handler()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("while generating key: %v", err)
	}
	goodCSR := csrPEM(t, key)

	t.Run("issues attested certificate", func(t *testing.T) {
		rec := post(t, h, "good", Request{SignerName: podidentitysigner.Name, CSRPEM: goodCSR, MaxExpirationSeconds: 3600})
		if rec.Code != http.StatusOK {
			t.Fatalf("got status %d, body %q", rec.Code, rec.Body.String())
		}
		var resp Response
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("while decoding response: %v", err)
		}

		block, _ := pem.Decode([]byte(resp.CertificateChainPEM))
		if block == nil {
			t.Fatalf("no certificate in response")
		}
		leaf, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("while parsing leaf: %v", err)
		}
		roots := x509.NewCertPool()
		roots.AddCert(ca.RootCertificate)
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: testNow, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
			t.Errorf("leaf does not verify: %v", err)
		}
		leafPub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
		if !ok || !leafPub.Equal(key.Public()) {
			t.Errorf("leaf carries the wrong public key")
		}
		if got := leaf.URIs[0].String(); got != "spiffe://cluster.local/ns/ate-system/sa/atelet" {
			t.Errorf("got URI %s", got)
		}
		id, err := substratex509.PodIdentityFromCertificate(leaf)
		if err != nil {
			t.Fatalf("while extracting PodIdentity: %v", err)
		}
		want := &substratex509.PodIdentity{
			Namespace: "ate-system", ServiceAccountName: "atelet", ServiceAccountUID: "sa-uid-1",
			PodName: "atelet-abcde", PodUID: "pod-uid-1", NodeName: "node-1", NodeUID: "node-uid-1",
		}
		if *id != *want {
			t.Errorf("got identity %+v, want %+v", id, want)
		}

		wantNotAfter := testNow.Add(-2 * time.Minute).Add(time.Hour)
		if !leaf.NotAfter.Equal(wantNotAfter) || !resp.NotAfter.Equal(wantNotAfter) {
			t.Errorf("got NotAfter cert=%v resp=%v, want %v", leaf.NotAfter, resp.NotAfter, wantNotAfter)
		}
		if !resp.BeginRefreshAt.Equal(wantNotAfter.Add(-30 * time.Minute)) {
			t.Errorf("got BeginRefreshAt %v", resp.BeginRefreshAt)
		}
	})

	rejections := []struct {
		name       string
		token      string
		req        Request
		wantStatus int
	}{
		{"missing token", "", Request{SignerName: podidentitysigner.Name, CSRPEM: goodCSR}, http.StatusUnauthorized},
		{"unknown token", "bogus", Request{SignerName: podidentitysigner.Name, CSRPEM: goodCSR}, http.StatusUnauthorized},
		{"unauthenticated", "unauthn", Request{SignerName: podidentitysigner.Name, CSRPEM: goodCSR}, http.StatusUnauthorized},
		{"wrong audience", "wrong-aud", Request{SignerName: podidentitysigner.Name, CSRPEM: goodCSR}, http.StatusUnauthorized},
		{"human user", "human", Request{SignerName: podidentitysigner.Name, CSRPEM: goodCSR}, http.StatusForbidden},
		{"token not bound to pod", "not-a-pod", Request{SignerName: podidentitysigner.Name, CSRPEM: goodCSR}, http.StatusForbidden},
		{"token without node claims", "no-node", Request{SignerName: podidentitysigner.Name, CSRPEM: goodCSR}, http.StatusForbidden},
		{"unknown signer", "good", Request{SignerName: "nope.example.com/x", CSRPEM: goodCSR}, http.StatusNotFound},
		{"garbage CSR", "good", Request{SignerName: podidentitysigner.Name, CSRPEM: "not pem"}, http.StatusBadRequest},
	}
	for _, tc := range rejections {
		t.Run(tc.name, func(t *testing.T) {
			rec := post(t, h, tc.token, tc.req)
			if rec.Code != tc.wantStatus {
				t.Errorf("got status %d (%q), want %d", rec.Code, rec.Body.String(), tc.wantStatus)
			}
		})
	}

	t.Run("CSR with forged signature is rejected", func(t *testing.T) {
		other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		// Take a valid CSR and swap in a different public key so the
		// self-signature no longer verifies.
		der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
		if err != nil {
			t.Fatal(err)
		}
		csr, err := x509.ParseCertificateRequest(der)
		if err != nil {
			t.Fatal(err)
		}
		otherPub, err := x509.MarshalPKIXPublicKey(other.Public())
		if err != nil {
			t.Fatal(err)
		}
		forged := csr.RawSubjectPublicKeyInfo
		if len(forged) != len(otherPub) {
			t.Skip("public key encodings differ in length; cannot splice")
		}
		raw := bytes.Replace(der, forged, otherPub, 1)
		rec := post(t, h, "good", Request{
			SignerName: podidentitysigner.Name,
			CSRPEM:     string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: raw})),
		})
		if rec.Code != http.StatusBadRequest {
			t.Errorf("got status %d (%q), want 400", rec.Code, rec.Body.String())
		}
	})
}

func TestServingCert(t *testing.T) {
	ca, err := localca.GenerateCA("test-ca", localca.KeyTypeED25519, 365*24*time.Hour)
	if err != nil {
		t.Fatalf("while generating CA: %v", err)
	}
	caPool := &localca.ConcretePool{CAs: []*localca.CA{ca}}
	clk := &fixedClock{now: testNow}
	sc := NewServingCert(caPool, []string{"podcert-issuer.podcertificate-controller-system.svc"}, 24*time.Hour, clk)

	first, err := sc.Get()
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.RootCertificate)
	if _, err := first.Leaf.Verify(x509.VerifyOptions{
		Roots: roots, DNSName: "podcert-issuer.podcertificate-controller-system.svc", CurrentTime: testNow,
	}); err != nil {
		t.Errorf("serving cert does not verify: %v", err)
	}

	again, err := sc.Get()
	if err != nil {
		t.Fatal(err)
	}
	if again != first {
		t.Errorf("certificate was reissued while still fresh")
	}

	clk.now = testNow.Add(17 * time.Hour)
	rotated, err := sc.Get()
	if err != nil {
		t.Fatal(err)
	}
	if rotated == first {
		t.Errorf("certificate was not reissued within a third of its lifetime of expiry")
	}
}
