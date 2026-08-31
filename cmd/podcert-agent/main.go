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

// Command podcert-agent is a sidecar that stands in for kubelet's projected
// podCertificate and clusterTrustBundle volumes on clusters that do not serve
// certificates.k8s.io/v1beta1 (for example AKS and EKS on Kubernetes
// 1.34-1.36).
//
// For every --cert signer=dir it generates an ECDSA P-256 key, obtains a
// certificate for it from podcertcontroller's issuer API (authenticating with
// the pod's bound ServiceAccount token, which the API server attests through
// TokenReview), writes dir/credential-bundle.pem in the same format kubelet
// uses, and renews it when the issuer says to. For every --cert and --trust
// signer=dir it copies the signer's trust bundle from the podcert-trust-bundles
// ConfigMap mount to dir/trust-bundle.pem and keeps it current.
//
// Run it as a native sidecar (initContainer with restartPolicy: Always) with a
// startupProbe of `podcert-agent --check <same flags>` so the main containers
// start only once every file exists.
package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/agent-substrate/substrate/internal/podcertapi"
	"github.com/agent-substrate/substrate/internal/version"
	"github.com/spf13/pflag"
)

var (
	issuerURL = pflag.String("issuer-url",
		"https://podcert-issuer.podcertificate-controller-system.svc",
		"Base URL of the podcertcontroller issuer API.")
	issuerCAFile = pflag.String("issuer-ca-file", "",
		"PEM trust anchors for the issuer's serving certificate. Defaults to the servicedns bundle in --trust-source-dir.")
	tokenFile = pflag.String("token-file", "/var/run/secrets/podcert.ate.dev/token",
		"Projected ServiceAccount token (audience "+podcertapi.DefaultAudience+") used to authenticate to the issuer.")
	trustSourceDir = pflag.String("trust-source-dir", "/run/podcert-trust",
		"Mount of the "+podcertapi.TrustConfigMapName+" ConfigMap.")
	certSpecs = pflag.StringArray("cert", nil,
		"signer=dir: obtain a certificate from signer and write dir/"+podcertapi.CredentialBundleFile+" and dir/"+podcertapi.TrustBundleFile+". Repeatable.")
	trustSpecs = pflag.StringArray("trust", nil,
		"signer=dir: write signer's trust bundle to dir/"+podcertapi.TrustBundleFile+" only. Repeatable.")
	maxExpirationSeconds = pflag.Int32("max-expiration-seconds", 86400,
		"Requested certificate lifetime; the signer may shorten it.")
	fileMode = pflag.Uint32("file-mode", 0o644,
		"Permission bits for written files, octal. Projected volumes default to 0644; use 0640 with an fsGroup for postgres.")
	trustPollInterval = pflag.Duration("trust-poll-interval", 30*time.Second,
		"How often to re-read the trust ConfigMap mount for changes.")
	check = pflag.Bool("check", false,
		"Exit 0 if every file the other flags describe exists and is non-empty, 1 otherwise. For use as a startupProbe.")
	showVersion = pflag.Bool("version", false, "Print version and exit.")
)

// target is one signer=dir mapping.
type target struct {
	signer string
	dir    string
}

func parseTargets(specs []string) ([]target, error) {
	out := make([]target, 0, len(specs))
	for _, spec := range specs {
		signer, dir, ok := strings.Cut(spec, "=")
		if !ok || signer == "" || dir == "" {
			return nil, fmt.Errorf("expected signer=dir, got %q", spec)
		}
		out = append(out, target{signer: signer, dir: dir})
	}
	return out, nil
}

func main() {
	pflag.Parse()
	if *showVersion {
		fmt.Println(version.String())
		return
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	certs, err := parseTargets(*certSpecs)
	if err != nil {
		slog.ErrorContext(ctx, "Invalid --cert", slog.Any("err", err))
		os.Exit(2)
	}
	trusts, err := parseTargets(*trustSpecs)
	if err != nil {
		slog.ErrorContext(ctx, "Invalid --trust", slog.Any("err", err))
		os.Exit(2)
	}
	if len(certs) == 0 && len(trusts) == 0 {
		slog.ErrorContext(ctx, "Nothing to do: pass at least one --cert or --trust")
		os.Exit(2)
	}

	if *check {
		os.Exit(runCheck(certs, trusts))
	}

	caFile := *issuerCAFile
	if caFile == "" {
		caFile = filepath.Join(*trustSourceDir, podcertapi.TrustKey("servicedns.podcert.ate.dev/identity"))
	}
	client := &issuerClient{
		baseURL:   strings.TrimRight(*issuerURL, "/"),
		caFile:    caFile,
		tokenFile: *tokenFile,
	}
	mode := os.FileMode(*fileMode)

	// Trust bundles first: the issuer CA is one of them, and a consumer that
	// finds credential-bundle.pem generally expects trust-bundle.pem next to it.
	trustAll := append(append([]target(nil), certs...), trusts...)
	for _, t := range trustAll {
		go syncTrustBundle(ctx, t, *trustSourceDir, mode, *trustPollInterval)
	}
	for _, t := range certs {
		go maintainCertificate(ctx, client, t, *maxExpirationSeconds, mode)
	}

	<-ctx.Done()
}

// runCheck implements --check.
func runCheck(certs, trusts []target) int {
	var want []string
	for _, t := range certs {
		want = append(want, filepath.Join(t.dir, podcertapi.CredentialBundleFile), filepath.Join(t.dir, podcertapi.TrustBundleFile))
	}
	for _, t := range trusts {
		want = append(want, filepath.Join(t.dir, podcertapi.TrustBundleFile))
	}
	rc := 0
	for _, path := range want {
		fi, err := os.Stat(path)
		if err != nil || fi.Size() == 0 {
			fmt.Fprintf(os.Stderr, "not ready: %s\n", path)
			rc = 1
		}
	}
	return rc
}

// syncTrustBundle keeps dir/trust-bundle.pem equal to the signer's bundle in
// the ConfigMap mount. Kubelet updates ConfigMap mounts atomically, so a
// periodic re-read is enough; rotations take up to a minute plus the kubelet
// sync period to land, well within the age-in window of a CA rotation.
func syncTrustBundle(ctx context.Context, t target, sourceDir string, mode os.FileMode, every time.Duration) {
	src := filepath.Join(sourceDir, podcertapi.TrustKey(t.signer))
	dst := filepath.Join(t.dir, podcertapi.TrustBundleFile)
	var last []byte
	backoff := time.Second
	for {
		data, err := os.ReadFile(src)
		switch {
		case err != nil:
			slog.WarnContext(ctx, "Trust bundle not readable yet", slog.String("path", src), slog.Any("err", err))
		case len(data) == 0:
			slog.WarnContext(ctx, "Trust bundle is empty", slog.String("path", src))
		case !bytes.Equal(data, last):
			if err := writeAtomic(dst, data, mode); err != nil {
				slog.ErrorContext(ctx, "Failed to write trust bundle", slog.String("path", dst), slog.Any("err", err))
			} else {
				slog.InfoContext(ctx, "Wrote trust bundle", slog.String("signer", t.signer), slog.String("path", dst))
				last = data
			}
		}

		wait := every
		if last == nil {
			// Still bootstrapping: retry quickly.
			wait = backoff
			if backoff < 10*time.Second {
				backoff *= 2
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

// minRefreshDelay bounds how soon after an issuance the agent asks again, so
// an issuer that always says "refresh now" cannot make the agent spin.
var minRefreshDelay = 10 * time.Second

// maintainCertificate obtains and renews dir/credential-bundle.pem.
func maintainCertificate(ctx context.Context, client *issuerClient, t target, maxExpirationSeconds int32, mode os.FileMode) {
	dst := filepath.Join(t.dir, podcertapi.CredentialBundleFile)
	backoff := time.Second
	for {
		resp, bundle, err := client.issue(ctx, t.signer, maxExpirationSeconds)
		if err == nil {
			err = writeAtomic(dst, bundle, mode)
		}
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			slog.WarnContext(ctx, "Certificate request failed; retrying",
				slog.String("signer", t.signer), slog.Duration("in", backoff), slog.Any("err", err))
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			if backoff < time.Minute {
				backoff *= 2
			}
			continue
		}
		backoff = time.Second

		// Kubelet refreshes at beginRefreshAt; do the same. Never sleep past
		// expiry if the issuer returned odd times, and never spin.
		refreshIn := time.Until(resp.BeginRefreshAt)
		if untilExpiry := time.Until(resp.NotAfter); refreshIn > untilExpiry {
			refreshIn = untilExpiry / 2
		}
		if refreshIn < minRefreshDelay {
			refreshIn = minRefreshDelay
		}
		slog.InfoContext(ctx, "Wrote credential bundle",
			slog.String("signer", t.signer), slog.String("path", dst),
			slog.Time("notAfter", resp.NotAfter), slog.Duration("refreshIn", refreshIn))
		select {
		case <-ctx.Done():
			return
		case <-time.After(refreshIn):
		}
	}
}

// issuerClient talks to podcertcontroller's issuer API.
type issuerClient struct {
	baseURL   string
	caFile    string
	tokenFile string
}

// issue generates a fresh key, has the issuer certify it, and returns the
// response plus a credential bundle: PKCS#8 PRIVATE KEY block followed by the
// CERTIFICATE chain, the layout kubelet writes and internal/credbundle parses.
func (c *issuerClient) issue(ctx context.Context, signer string, maxExpirationSeconds int32) (*podcertapi.IssueResponse, []byte, error) {
	caPEM, err := os.ReadFile(c.caFile)
	if err != nil {
		return nil, nil, fmt.Errorf("while reading issuer CA %s: %w", c.caFile, err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, nil, fmt.Errorf("issuer CA %s contains no certificates", c.caFile)
	}
	token, err := os.ReadFile(c.tokenFile)
	if err != nil {
		return nil, nil, fmt.Errorf("while reading token %s: %w", c.tokenFile, err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("while generating key: %w", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		return nil, nil, fmt.Errorf("while creating CSR: %w", err)
	}
	body, err := json.Marshal(podcertapi.IssueRequest{
		SignerName:           signer,
		CSRPEM:               string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})),
		MaxExpirationSeconds: maxExpirationSeconds,
	})
	if err != nil {
		return nil, nil, err
	}

	httpClient := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13},
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+podcertapi.IssuePath, bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
	req.Header.Set("Content-Type", "application/json")
	httpResp, err := httpClient.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("while calling issuer: %w", err)
	}
	defer httpResp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(httpResp.Body, 1<<20))
	if err != nil {
		return nil, nil, fmt.Errorf("while reading issuer response: %w", err)
	}
	if httpResp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("issuer returned %d: %s", httpResp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	var resp podcertapi.IssueResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, nil, fmt.Errorf("while decoding issuer response: %w", err)
	}
	if resp.CertificateChainPEM == "" {
		return nil, nil, errors.New("issuer returned an empty certificate chain")
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("while encoding key: %w", err)
	}
	bundle := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	bundle = append(bundle, resp.CertificateChainPEM...)
	return &resp, bundle, nil
}

// writeAtomic writes data to path via a temp file and rename, so readers
// (internal/credbundle watches inode and mtime) never see a partial file.
func writeAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		cleanup()
		return err
	}
	return nil
}
