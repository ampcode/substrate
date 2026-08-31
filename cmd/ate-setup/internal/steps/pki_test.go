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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agent-substrate/substrate/cmd/ate-setup/internal/config"
)

// TestAgentPKIRendersEverySource composes the agent-pki component over each
// manifest source the installer renders and checks that no projected
// podCertificate or clusterTrustBundle volume survives: on a cluster without
// certificates.k8s.io/v1beta1, a single leftover would wedge that pod in
// ContainerCreating.
func TestAgentPKIRendersEverySource(t *testing.T) {
	root := repoRoot(t)
	env := &Env{Cfg: &config.Config{Root: root, PKIDelivery: config.PKIDeliveryAgent}}

	sources := []string{
		// deploy ate-system bundles, one per kind x router combination.
		env.Cfg.Manifest(),
		env.Cfg.Manifest("kind"),
		env.Cfg.Manifest("agentgateway"),
		env.Cfg.Manifest("kind-agentgateway"),
		env.Cfg.Manifest("aks"),
		env.Cfg.Manifest("aks", "atelet"),
		// Components the installer applies on their own.
		env.Cfg.Manifest("pod-certificate-controller.yaml"),
		env.Cfg.Manifest("postgres.yaml"),
		env.Cfg.Manifest("atelet.yaml"),
		env.Cfg.Manifest("kind", "atelet"),
		env.Cfg.Manifest("atenet-router.yaml"),
		env.Cfg.Manifest("agentgateway-router"),
		env.Cfg.Manifest("atenet-egress.yaml"),
		env.Cfg.Manifest("agentgateway-egress"),
	}

	for _, source := range sources {
		rel, _ := filepath.Rel(root, source)
		t.Run(rel, func(t *testing.T) {
			out, err := env.kustomizeWithAgentPKI(source)
			if err != nil {
				t.Fatalf("kustomizeWithAgentPKI(%s) error = %v", rel, err)
			}
			rendered := string(out)
			for _, projected := range []string{"podCertificate:", "clusterTrustBundle:"} {
				if strings.Contains(rendered, projected) {
					t.Errorf("%s still carries a projected %s volume under agent delivery", rel, strings.TrimSuffix(projected, ":"))
				}
			}
			// The controller is the issuer, so it is the one workload without
			// a sidecar; it must switch to serving the issuer API instead.
			want := "name: podcert-agent"
			if strings.HasSuffix(rel, "pod-certificate-controller.yaml") {
				want = "--serve-issuer-api=true"
			}
			if !strings.Contains(rendered, want) {
				t.Errorf("%s lacks %q under agent delivery", rel, want)
			}
		})
	}

	leftovers, err := filepath.Glob(filepath.Join(env.Cfg.Manifest(), ".render-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(leftovers) != 0 {
		t.Errorf("render directories were not cleaned up: %v", leftovers)
	}
}

// The throwaway kustomization references its source by a relative path, so
// anything outside manifests/ate-install would silently render the wrong
// thing; refuse it instead.
func TestAgentPKIRejectsSourcesOutsideInstallDir(t *testing.T) {
	root := repoRoot(t)
	env := &Env{Cfg: &config.Config{Root: root, PKIDelivery: config.PKIDeliveryAgent}}

	if _, err := env.kustomizeWithAgentPKI(filepath.Join(root, "manifests")); err == nil {
		t.Fatal("kustomizeWithAgentPKI accepted a source outside manifests/ate-install")
	}
	if _, err := env.kustomizeWithAgentPKI(filepath.Join(os.TempDir(), "nowhere.yaml")); err == nil {
		t.Fatal("kustomizeWithAgentPKI accepted a source outside the repository")
	}
}
