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

package steps

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/agent-substrate/substrate/cmd/ate-setup/internal/config"
	"github.com/agent-substrate/substrate/cmd/ate-setup/internal/kustomize"
	"github.com/agent-substrate/substrate/cmd/ate-setup/internal/log"
	"github.com/agent-substrate/substrate/internal/podcertapi"
)

// agentPKIComponent is the kustomize Component that swaps every projected
// podCertificate and clusterTrustBundle volume for a podcert-agent sidecar.
const agentPKIComponent = "components/agent-pki"

// AgentPKI reports whether the install hands out certificates through
// podcert-agent sidecars instead of projected volumes.
func (e *Env) AgentPKI() bool {
	return e.Cfg.PKIDelivery == config.PKIDeliveryAgent
}

// RenderManifest renders a manifest source under manifests/ate-install with
// image references resolved. The source is an absolute path to a plain YAML
// file, the plain base directory, or a kustomize overlay directory, as
// returned by Config.Manifest.
//
// Under --pki-delivery=agent the agent-pki component is layered on top. The
// composition happens through a throwaway kustomization written next to the
// sources (kustomize rejects absolute paths in resources) rather than one
// static overlay per combination of kind, router, and PKI mode. This mirrors
// render_manifest in hack/install-ate.sh.
func (e *Env) RenderManifest(ctx context.Context, source string) ([]byte, error) {
	if !e.AgentPKI() {
		if isKustomization(source) {
			built, err := kustomize.Build(source)
			if err != nil {
				return nil, err
			}
			return e.KoResolveBytes(ctx, built)
		}
		return e.KoResolve(ctx, source)
	}

	built, err := e.kustomizeWithAgentPKI(source)
	if err != nil {
		return nil, err
	}
	return e.KoResolveBytes(ctx, built)
}

// kustomizeWithAgentPKI builds source with the agent-pki component applied.
func (e *Env) kustomizeWithAgentPKI(source string) ([]byte, error) {
	installRoot := e.Cfg.Manifest()
	rel, err := filepath.Rel(installRoot, source)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return nil, fmt.Errorf("manifest source %s is not under %s", source, installRoot)
	}

	info, err := os.Stat(source)
	if err != nil {
		return nil, fmt.Errorf("while inspecting manifest source %s: %w", source, err)
	}
	resource := "../" + filepath.ToSlash(rel)
	if info.IsDir() && !isKustomization(source) {
		// A plain directory (the GKE base) has a kustomize twin in ./base.
		resource = "../base"
	}

	renderDir, err := os.MkdirTemp(installRoot, ".render-")
	if err != nil {
		return nil, fmt.Errorf("while creating the render directory: %w", err)
	}
	defer func() {
		if err := os.RemoveAll(renderDir); err != nil {
			log.Warnf("Could not remove the render directory %s: %v", renderDir, err)
		}
	}()

	kustomization := strings.Join([]string{
		"apiVersion: kustomize.config.k8s.io/v1beta1",
		"kind: Kustomization",
		"resources:",
		"  - " + resource,
		"components:",
		"  - ../" + agentPKIComponent,
		"",
	}, "\n")
	if err := os.WriteFile(filepath.Join(renderDir, "kustomization.yaml"), []byte(kustomization), 0o644); err != nil {
		return nil, fmt.Errorf("while writing the render kustomization: %w", err)
	}
	return kustomize.Build(renderDir)
}

// isKustomization reports whether dir holds a kustomization.yaml.
func isKustomization(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, "kustomization.yaml"))
	return err == nil
}

// applyPodCertificateController deploys the podcertificate controller in the
// mode the PKI delivery calls for. In agent mode the component turns on the
// issuer API and turns off PodCertificateRequest handling.
func (e *Env) applyPodCertificateController(ctx context.Context) error {
	manifest, err := e.RenderManifest(ctx, e.Cfg.Manifest("pod-certificate-controller.yaml"))
	if err != nil {
		return err
	}
	return e.Kube.ApplyBytes(ctx, manifest)
}

// WaitForPodCertificateTrustBundles blocks until the podcertificate controller
// has published both identity bundles: as ClusterTrustBundles under projected
// delivery, or in the ate-system podcert-trust-bundles ConfigMap under agent
// delivery.
func (e *Env) WaitForPodCertificateTrustBundles(ctx context.Context) error {
	timeout := e.Cfg.WaitTimeout(BootstrapTimeout)
	if e.AgentPKI() {
		log.Infof("Waiting for the %s ConfigMap in %s...", podcertapi.TrustConfigMapName, NamespaceAteSystem)
		return e.Kube.WaitConfigMapKeys(ctx, NamespaceAteSystem, podcertapi.TrustConfigMapName, trustConfigMapKeys, timeout)
	}
	log.Infof("Waiting for podcertificate ClusterTrustBundles to be ready...")
	return e.Kube.WaitClusterTrustBundles(ctx, trustBundleNames, timeout)
}

// trustConfigMapKeys are the podcert-trust-bundles entries workloads read
// under agent delivery, one per identity signer.
var trustConfigMapKeys = []string{
	podcertapi.TrustKey("podidentity.podcert.ate.dev/identity"),
	podcertapi.TrustKey("servicedns.podcert.ate.dev/identity"),
}
