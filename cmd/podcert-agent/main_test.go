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
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/agent-substrate/substrate/internal/credbundle"
	"github.com/agent-substrate/substrate/internal/localca"
	"github.com/agent-substrate/substrate/internal/podcertapi"
)

// fakeIssuer is a minimal issuer API: it checks the bearer token and signs
// whatever public key the CSR carries.
func fakeIssuer(t *testing.T, ca *localca.CA, wantToken string, calls *atomic.Int32) *httptest.Server {
	t.Helper()
	pool := &localca.ConcretePool{CAs: []*localca.CA{ca}}
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path != podcertapi.IssuePath || r.Method != http.MethodPost {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+wantToken {
			http.Error(w, "bad token", http.StatusUnauthorized)
			return
		}
		var req podcertapi.IssueRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		block, _ := pem.Decode([]byte(req.CSRPEM))
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil || csr.CheckSignature() != nil {
			http.Error(w, "bad csr", http.StatusBadRequest)
			return
		}
		now := time.Now()
		notAfter := now.Add(time.Duration(req.MaxExpirationSeconds) * time.Second)
		chain, err := pool.CreateCertificate(&x509.Certificate{
			NotBefore: now.Add(-2 * time.Minute), NotAfter: notAfter,
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}, csr.PublicKey)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		var chainPEM []byte
		for _, der := range chain {
			chainPEM = append(chainPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
		}
		_ = json.NewEncoder(w).Encode(podcertapi.IssueResponse{
			CertificateChainPEM: string(chainPEM),
			NotBefore:           now.Add(-2 * time.Minute),
			// Ask for an immediate refresh so the test can observe renewal.
			BeginRefreshAt: now,
			NotAfter:       notAfter,
		})
	}))
}

func TestAgentWritesBundlesAndRenews(t *testing.T) {
	ca, err := localca.GenerateCA("test-ca", localca.KeyTypeED25519, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	srv := fakeIssuer(t, ca, "tok-123", &calls)
	defer srv.Close()

	work := t.TempDir()
	caFile := filepath.Join(work, "issuer-ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	tokenFile := filepath.Join(work, "token")
	if err := os.WriteFile(tokenFile, []byte("tok-123\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	trustSrc := filepath.Join(work, "trust-src")
	if err := os.MkdirAll(trustSrc, 0o755); err != nil {
		t.Fatal(err)
	}
	const signer = "podidentity.podcert.ate.dev/identity"
	trustPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.RootCertificate.Raw})
	if err := os.WriteFile(filepath.Join(trustSrc, podcertapi.TrustKey(signer)), trustPEM, 0o644); err != nil {
		t.Fatal(err)
	}

	out := filepath.Join(work, "out")
	tgt := target{signer: signer, dir: out}
	client := &issuerClient{baseURL: srv.URL, caFile: caFile, tokenFile: tokenFile}

	if rc := runCheck([]target{tgt}, nil); rc != 1 {
		t.Errorf("--check before any files exist returned %d, want 1", rc)
	}

	minRefreshDelay = 200 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	go syncTrustBundle(ctx, tgt, trustSrc, 0o640, 50*time.Millisecond)
	go maintainCertificate(ctx, client, tgt, 3600, 0o640)

	deadline := time.Now().Add(10 * time.Second)
	for runCheck([]target{tgt}, nil) != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("files never appeared in %s", out)
		}
		time.Sleep(20 * time.Millisecond)
	}

	bundlePath := filepath.Join(out, podcertapi.CredentialBundleFile)
	cert, err := credbundle.Parse(bundlePath)
	if err != nil {
		t.Fatalf("credential bundle is not parseable by internal/credbundle: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.RootCertificate)
	if _, err := cert.Leaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Errorf("leaf does not chain to CA: %v", err)
	}
	fi, err := os.Stat(bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o640 {
		t.Errorf("bundle mode %o, want 0640", fi.Mode().Perm())
	}
	got, err := os.ReadFile(filepath.Join(out, podcertapi.TrustBundleFile))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(trustPEM) {
		t.Errorf("trust bundle not copied verbatim")
	}

	// BeginRefreshAt was "now", so the agent renews after minRefreshDelay.
	first := calls.Load()
	renewDeadline := time.Now().Add(5 * time.Second)
	for calls.Load() == first {
		if time.Now().After(renewDeadline) {
			t.Fatalf("agent did not renew its certificate")
		}
		time.Sleep(100 * time.Millisecond)
	}

	// A rotated trust bundle propagates.
	rotated := append(append([]byte(nil), trustPEM...), trustPEM...)
	if err := os.WriteFile(filepath.Join(trustSrc, podcertapi.TrustKey(signer)), rotated, 0o644); err != nil {
		t.Fatal(err)
	}
	rotDeadline := time.Now().Add(5 * time.Second)
	for {
		got, _ := os.ReadFile(filepath.Join(out, podcertapi.TrustBundleFile))
		if string(got) == string(rotated) {
			break
		}
		if time.Now().After(rotDeadline) {
			t.Fatalf("rotated trust bundle not propagated")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestParseTargets(t *testing.T) {
	got, err := parseTargets([]string{"a/b=/run/x", "c=/run/y"})
	if err != nil || len(got) != 2 || got[0].signer != "a/b" || got[0].dir != "/run/x" {
		t.Errorf("parseTargets = %+v, %v", got, err)
	}
	if _, err := parseTargets([]string{"nodir"}); err == nil {
		t.Errorf("expected error for spec without '='")
	}
}
