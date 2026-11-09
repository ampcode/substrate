// Copyright 2026 The Agent Substrate Authors
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
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"go.ate.dev/substrate/cmd/ate-setup/internal/kube"
)

const preV1ReleaseManifest = `---
# Source: orb-provider/templates/substrate/gke.yaml
apiVersion: ate.dev/v1alpha1
kind: SandboxConfig
metadata:
  name: gvisor-default
spec:
  runtime: gvisor
---
# Source: orb-provider/templates/substrate/gke.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ate-api-server
  namespace: ate-system
spec:
  template:
    spec:
      containers:
        - name: ate-api-server
          args:
            - --storage-backend=gcs
---
# Source: orb-provider/templates/provider/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: amp-orb-provider
  namespace: amp-orbs
`

func helmReleaseSecret(t *testing.T, name string, version int, status, manifest string) *corev1.Secret {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"name":      name,
		"version":   version,
		"namespace": "amp-orbs",
		"manifest":  manifest,
		"info":      map[string]any{"status": status},
		"chart":     map[string]any{"metadata": map[string]any{"name": "orb-provider", "version": "0.1.0"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := encodeHelmRelease(raw)
	if err != nil {
		t.Fatal(err)
	}
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "amp-orbs",
			Name:      "sh.helm.release.v1." + name + ".v" + string(rune('0'+version)),
			Labels:    map[string]string{"name": name, "owner": "helm", "status": status, "version": string(rune('0' + version))},
		},
		Type: helmReleaseSecretType,
		Data: map[string][]byte{helmReleaseDataKey: encoded},
	}
}

func storedManifest(t *testing.T, secret *corev1.Secret) (string, map[string]json.RawMessage) {
	t.Helper()
	raw, err := decodeHelmRelease(secret.Data[helmReleaseDataKey])
	if err != nil {
		t.Fatal(err)
	}
	var release map[string]json.RawMessage
	if err := json.Unmarshal(raw, &release); err != nil {
		t.Fatal(err)
	}
	var manifest string
	if err := json.Unmarshal(release["manifest"], &manifest); err != nil {
		t.Fatal(err)
	}
	return manifest, release
}

// Every stored version of the release loses its v1alpha1 objects and nothing
// else; versions without any, and other releases, are left alone.
func TestStripV1alpha1FromHelmRelease(t *testing.T) {
	ctx := context.Background()
	deployed := helmReleaseSecret(t, "orb-provider", 7, "deployed", preV1ReleaseManifest)
	failed := helmReleaseSecret(t, "orb-provider", 8, "failed", "---\n# Source: x\napiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: amp-orb-provider\n")
	other := helmReleaseSecret(t, "something-else", 1, "deployed", preV1ReleaseManifest)
	failedBefore := failed.Data[helmReleaseDataKey]
	otherBefore := other.Data[helmReleaseDataKey]
	cs := fake.NewClientset(deployed, failed, other)
	env := &Env{Kube: kube.NewFromClients(nil, cs, nil, cs.Discovery())}

	if err := env.StripV1alpha1FromHelmRelease(ctx, "amp-orbs", "orb-provider"); err != nil {
		t.Fatalf("StripV1alpha1FromHelmRelease: %v", err)
	}

	got, err := cs.CoreV1().Secrets("amp-orbs").Get(ctx, deployed.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	manifest, release := storedManifest(t, got)
	if strings.Contains(manifest, "v1alpha1") || strings.Contains(manifest, "SandboxConfig") {
		t.Errorf("v1alpha1 object still in the manifest:\n%s", manifest)
	}
	for _, want := range []string{"name: ate-api-server", "--storage-backend=gcs", "name: amp-orb-provider", "# Source: orb-provider/templates/provider/deployment.yaml"} {
		if !strings.Contains(manifest, want) {
			t.Errorf("manifest lost %q:\n%s", want, manifest)
		}
	}
	if !strings.HasPrefix(manifest, "---\n# Source: orb-provider/templates/substrate/gke.yaml\napiVersion: apps/v1") {
		t.Errorf("manifest no longer starts with a Helm document separator:\n%s", manifest)
	}
	if string(release["version"]) != "7" || string(release["info"]) != `{"status":"deployed"}` {
		t.Errorf("release fields changed: version %s info %s", release["version"], release["info"])
	}
	if got.Labels["status"] != "deployed" || got.Type != helmReleaseSecretType {
		t.Errorf("secret metadata changed: %v %s", got.Labels, got.Type)
	}

	got, err = cs.CoreV1().Secrets("amp-orbs").Get(ctx, failed.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Data[helmReleaseDataKey]) != string(failedBefore) {
		t.Error("a version without v1alpha1 objects was rewritten")
	}
	got, err = cs.CoreV1().Secrets("amp-orbs").Get(ctx, other.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Data[helmReleaseDataKey]) != string(otherBefore) {
		t.Error("another release was rewritten")
	}

	// Running again finds nothing to do.
	if err := env.StripV1alpha1FromHelmRelease(ctx, "amp-orbs", "orb-provider"); err != nil {
		t.Fatalf("second StripV1alpha1FromHelmRelease: %v", err)
	}
}

// Helm stored releases without compression before 3.x; both encodings read.
func TestStripV1alpha1FromHelmReleaseUncompressed(t *testing.T) {
	raw, err := json.Marshal(map[string]any{"manifest": preV1ReleaseManifest, "version": 3})
	if err != nil {
		t.Fatal(err)
	}
	rewritten, removed, err := stripV1alpha1FromHelmRelease([]byte(base64.StdEncoding.EncodeToString(raw)))
	if err != nil {
		t.Fatal(err)
	}
	if removed != 1 {
		t.Fatalf("removed %d, want 1", removed)
	}
	decoded, err := decodeHelmRelease(rewritten)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(decoded), "v1alpha1") {
		t.Errorf("v1alpha1 still present: %s", decoded)
	}
}

func TestStripV1alpha1Documents(t *testing.T) {
	for _, tc := range []struct {
		name    string
		in      string
		want    string
		removed int
	}{
		{name: "empty", in: "", want: "", removed: 0},
		{name: "none", in: "---\napiVersion: v1\nkind: ConfigMap\n", want: "---\napiVersion: v1\nkind: ConfigMap\n", removed: 0},
		{name: "quoted", in: "---\napiVersion: \"ate.dev/v1alpha1\"\nkind: WorkerPool\n---\napiVersion: v1\nkind: Secret\n", want: "---\napiVersion: v1\nkind: Secret\n", removed: 1},
		{name: "v1 kept", in: "---\napiVersion: ate.dev/v1\nkind: SandboxConfig\n", want: "---\napiVersion: ate.dev/v1\nkind: SandboxConfig\n", removed: 0},
		{name: "separator inside a string stays", in: "---\napiVersion: v1\nkind: ConfigMap\ndata:\n  a: |\n    not --- a separator\n", want: "---\napiVersion: v1\nkind: ConfigMap\ndata:\n  a: |\n    not --- a separator\n", removed: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, removed := stripV1alpha1Documents(tc.in)
			if got != tc.want || removed != tc.removed {
				t.Errorf("got (%q, %d), want (%q, %d)", got, removed, tc.want, tc.removed)
			}
		})
	}
}
