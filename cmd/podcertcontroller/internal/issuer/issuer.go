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

// Package issuer serves pod certificates over HTTPS to clusters that do not
// expose the certificates.k8s.io PodCertificateRequest API.
//
// The protocol mirrors what kubelet does with a PodCertificateRequest: the
// requester proves possession of a key with a PKCS#10 CSR, and every identity
// fact in the certificate comes from the API server, here through a TokenReview
// of the requester's bound ServiceAccount token. Bound tokens carry the pod
// name and UID and, since Kubernetes 1.32, the node name and UID, so the
// resulting certificate is identical to one issued through a PCR.
package issuer

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/agent-substrate/substrate/cmd/podcertcontroller/internal/podcertificate"
	"github.com/agent-substrate/substrate/cmd/podcertcontroller/internal/signercontroller"
	"github.com/agent-substrate/substrate/internal/podcertapi"
	authnv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
)

// DefaultAudience is the bound-token audience the issuer expects by default.
const DefaultAudience = podcertapi.DefaultAudience

// Path is the HTTP path certificate requests are posted to.
const Path = podcertapi.IssuePath

// Request and Response are the wire types, shared with podcert-agent.
type (
	Request  = podcertapi.IssueRequest
	Response = podcertapi.IssueResponse
)

// Server answers certificate requests for a set of signers.
type Server struct {
	kc       kubernetes.Interface
	audience string
	signers  map[string]signercontroller.Issuer
}

// New returns a Server that attests requests with TokenReview against kc,
// requiring tokens minted for audience.
func New(kc kubernetes.Interface, audience string, signers ...signercontroller.Issuer) *Server {
	s := &Server{
		kc:       kc,
		audience: audience,
		signers:  make(map[string]signercontroller.Issuer, len(signers)),
	}
	for _, signer := range signers {
		s.signers[signer.SignerName()] = signer
	}
	return s
}

// Handler returns the HTTP handler serving Path.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+Path, s.handleIssue)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	return mux
}

// httpError is an error with the HTTP status the client should see.
type httpError struct {
	status int
	err    error
}

func (e *httpError) Error() string { return e.err.Error() }
func (e *httpError) Unwrap() error { return e.err }

func fail(status int, format string, args ...any) error {
	return &httpError{status: status, err: fmt.Errorf(format, args...)}
}

func (s *Server) handleIssue(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	resp, err := s.issue(ctx, r)
	if err != nil {
		status := http.StatusInternalServerError
		var he *httpError
		if errors.As(err, &he) {
			status = he.status
		}
		if status >= 500 {
			slog.ErrorContext(ctx, "Certificate request failed", slog.Int("status", status), slog.Any("err", err))
		} else {
			slog.WarnContext(ctx, "Certificate request rejected", slog.Int("status", status), slog.Any("err", err))
		}
		http.Error(w, err.Error(), status)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		slog.ErrorContext(ctx, "Failed to write certificate response", slog.Any("err", err))
	}
}

func (s *Server) issue(ctx context.Context, r *http.Request) (*Response, error) {
	token, ok := bearerToken(r)
	if !ok {
		return nil, fail(http.StatusUnauthorized, "missing bearer token")
	}

	var body Request
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&body); err != nil {
		return nil, fail(http.StatusBadRequest, "invalid request body: %w", err)
	}

	signer, ok := s.signers[body.SignerName]
	if !ok {
		return nil, fail(http.StatusNotFound, "unknown signer %q", body.SignerName)
	}

	publicKey, err := publicKeyFromCSR(body.CSRPEM)
	if err != nil {
		return nil, fail(http.StatusBadRequest, "%w", err)
	}

	identity, err := s.attest(ctx, token)
	if err != nil {
		return nil, err
	}

	req := &podcertificate.Request{
		Namespace:            identity.namespace,
		PodName:              identity.podName,
		PodUID:               identity.podUID,
		ServiceAccountName:   identity.serviceAccountName,
		ServiceAccountUID:    identity.serviceAccountUID,
		NodeName:             identity.nodeName,
		NodeUID:              identity.nodeUID,
		PublicKey:            publicKey,
		MaxExpirationSeconds: body.MaxExpirationSeconds,
	}

	issued, err := signer.Issue(ctx, req)
	if err != nil {
		// Signer errors are transient from the requester's point of view (the
		// pod may not be selected by its Service yet); 503 tells the agent to
		// retry rather than give up.
		return nil, fail(http.StatusServiceUnavailable, "signer %s: %w", body.SignerName, err)
	}

	slog.InfoContext(ctx, "Issued certificate",
		slog.String("signer", body.SignerName),
		slog.String("pod", identity.namespace+"/"+identity.podName),
		slog.String("serviceAccount", identity.serviceAccountName),
		slog.Time("notAfter", issued.NotAfter),
	)

	return &Response{
		CertificateChainPEM: issued.ChainPEM,
		NotBefore:           issued.NotBefore,
		BeginRefreshAt:      issued.BeginRefreshAt,
		NotAfter:            issued.NotAfter,
	}, nil
}

func bearerToken(r *http.Request) (string, bool) {
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, prefix) {
		return "", false
	}
	token := strings.TrimSpace(strings.TrimPrefix(h, prefix))
	return token, token != ""
}

// publicKeyFromCSR parses a PEM PKCS#10 request and verifies its self
// signature, proving the requester holds the private key.
func publicKeyFromCSR(csrPEM string) (any, error) {
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, errors.New("csrPEM must contain one CERTIFICATE REQUEST block")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("while parsing CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("CSR signature does not verify: %w", err)
	}
	return csr.PublicKey, nil
}

// podIdentity is what a TokenReview attests about the requesting pod.
type podIdentity struct {
	namespace          string
	serviceAccountName string
	serviceAccountUID  types.UID
	podName            string
	podUID             types.UID
	nodeName           types.NodeName
	nodeUID            types.UID
}

// Extra keys the API server sets on bound ServiceAccount tokens.
const (
	extraPodName  = "authentication.kubernetes.io/pod-name"
	extraPodUID   = "authentication.kubernetes.io/pod-uid"
	extraNodeName = "authentication.kubernetes.io/node-name"
	extraNodeUID  = "authentication.kubernetes.io/node-uid"
)

// attest validates token with the API server and extracts the pod identity it
// is bound to. Only the API server's answer is trusted; the token is never
// parsed locally.
func (s *Server) attest(ctx context.Context, token string) (*podIdentity, error) {
	review, err := s.kc.AuthenticationV1().TokenReviews().Create(ctx, &authnv1.TokenReview{
		Spec: authnv1.TokenReviewSpec{
			Token:     token,
			Audiences: []string{s.audience},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		return nil, fail(http.StatusInternalServerError, "TokenReview failed: %w", err)
	}
	if review.Status.Error != "" {
		return nil, fail(http.StatusUnauthorized, "token rejected: %s", review.Status.Error)
	}
	if !review.Status.Authenticated {
		return nil, fail(http.StatusUnauthorized, "token not authenticated")
	}
	audienceOK := false
	for _, aud := range review.Status.Audiences {
		if aud == s.audience {
			audienceOK = true
			break
		}
	}
	if !audienceOK {
		return nil, fail(http.StatusUnauthorized, "token audience does not include %q", s.audience)
	}

	user := review.Status.User
	const saPrefix = "system:serviceaccount:"
	if !strings.HasPrefix(user.Username, saPrefix) {
		return nil, fail(http.StatusForbidden, "token subject %q is not a ServiceAccount", user.Username)
	}
	nsSA := strings.SplitN(strings.TrimPrefix(user.Username, saPrefix), ":", 2)
	if len(nsSA) != 2 || nsSA[0] == "" || nsSA[1] == "" {
		return nil, fail(http.StatusForbidden, "malformed ServiceAccount username %q", user.Username)
	}

	first := func(key string) string {
		if v := user.Extra[key]; len(v) > 0 {
			return v[0]
		}
		return ""
	}
	id := &podIdentity{
		namespace:          nsSA[0],
		serviceAccountName: nsSA[1],
		serviceAccountUID:  types.UID(user.UID),
		podName:            first(extraPodName),
		podUID:             types.UID(first(extraPodUID)),
		nodeName:           types.NodeName(first(extraNodeName)),
		nodeUID:            types.UID(first(extraNodeUID)),
	}
	// A token that is not bound to a pod (for example one minted with
	// `kubectl create token`) carries no pod claims. Refuse it: the
	// certificate would then assert an identity nothing attested.
	if id.podName == "" || id.podUID == "" {
		return nil, fail(http.StatusForbidden, "token is not bound to a pod (no pod-name/pod-uid claims); use a projected serviceAccountToken volume")
	}
	if id.nodeName == "" || id.nodeUID == "" {
		return nil, fail(http.StatusForbidden, "token carries no node claims; the cluster must run Kubernetes 1.32 or newer (ServiceAccountTokenPodNodeInfo)")
	}
	return id, nil
}
