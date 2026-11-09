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
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"go.ate.dev/substrate/cmd/ate-setup/internal/kube"
	"go.ate.dev/substrate/cmd/ate-setup/internal/log"
)

// Helm keeps every version of a release as a Secret in the release namespace
// (sh.helm.release.v1.<name>.v<n>, type helm.sh/release.v1, labels name,
// owner=helm, status, version) whose "release" key holds the release as
// base64 of gzipped JSON. An upgrade or rollback starts by mapping every
// object in the deployed version's manifest against the cluster's API, so a
// manifest that names an API version the cluster stopped serving fails before
// any hook runs ("no matches for kind ... in version ate.dev/v1alpha1"). The
// pre-1.0 chart rendered its SandboxConfig at v1alpha1, and
// UpgradeFromV1alpha1 deletes that version: the upgrade that runs it still
// works, since Helm mapped the manifest before the hook, but a retry after it
// failed, the next upgrade, a rollback and an uninstall would all stop at
// that object. StripV1alpha1FromHelmRelease removes those objects from every
// stored version of the release, the way the helm mapkubeapis plugin
// retires removed APIs, so each of those keeps working. It is idempotent and
// touches nothing when no version names v1alpha1.

const (
	helmReleaseSecretType = "helm.sh/release.v1"
	helmReleaseDataKey    = "release"
)

var (
	helmGzipMagic         = []byte{0x1f, 0x8b, 0x08}
	helmManifestSeparator = regexp.MustCompile(`(?m)^---[ \t]*$`)
	v1alpha1APIVersion    = regexp.MustCompile(`(?m)^apiVersion:[ \t]*["']?ate\.dev/v1alpha1["']?[ \t]*$`)
)

// StripV1alpha1FromHelmRelease rewrites every stored version of the Helm
// release whose manifest contains ate.dev/v1alpha1 objects so that it no
// longer does; see the file comment.
func (e *Env) StripV1alpha1FromHelmRelease(ctx context.Context, namespace, name string) error {
	secrets := e.Kube.Typed.CoreV1().Secrets(namespace)
	list, err := secrets.List(ctx, metav1.ListOptions{LabelSelector: "owner=helm,name=" + name})
	if err != nil {
		return fmt.Errorf("while listing the versions of Helm release %s/%s: %w", namespace, name, err)
	}
	for i := range list.Items {
		secret := &list.Items[i]
		if secret.Type != helmReleaseSecretType {
			continue
		}
		encoded, ok := secret.Data[helmReleaseDataKey]
		if !ok {
			continue
		}
		rewritten, removed, err := stripV1alpha1FromHelmRelease(encoded)
		if err != nil {
			// Helm skips a stored version it cannot decode when it reads the
			// release's history, so such a version cannot stop an upgrade
			// either and is left alone.
			log.Warnf("skipping Helm release version %s, which Helm cannot read either: %v", secret.Name, err)
			continue
		}
		if removed == 0 {
			continue
		}
		secret.Data[helmReleaseDataKey] = rewritten
		if _, err := secrets.Update(ctx, secret, metav1.UpdateOptions{FieldManager: kube.FieldManager}); err != nil {
			return fmt.Errorf("while rewriting Helm release version %s: %w", secret.Name, err)
		}
		log.Infof("removed %d ate.dev/v1alpha1 object(s) from the manifest of Helm release version %s", removed, secret.Name)
	}
	return nil
}

// stripV1alpha1FromHelmRelease decodes one stored release, drops the
// ate.dev/v1alpha1 documents from its manifest, and encodes it again. It
// returns how many documents it dropped; with none, the encoded release is
// returned unchanged. Only the manifest is decoded, so every other field of
// the release is kept byte for byte.
func stripV1alpha1FromHelmRelease(encoded []byte) ([]byte, int, error) {
	raw, err := decodeHelmRelease(encoded)
	if err != nil {
		return nil, 0, err
	}
	var release map[string]json.RawMessage
	if err := json.Unmarshal(raw, &release); err != nil {
		return nil, 0, fmt.Errorf("while decoding the release: %w", err)
	}
	var manifest string
	if m, ok := release["manifest"]; ok {
		if err := json.Unmarshal(m, &manifest); err != nil {
			return nil, 0, fmt.Errorf("while decoding the release manifest: %w", err)
		}
	}
	stripped, removed := stripV1alpha1Documents(manifest)
	if removed == 0 {
		return encoded, 0, nil
	}
	m, err := json.Marshal(stripped)
	if err != nil {
		return nil, 0, err
	}
	release["manifest"] = m
	raw, err = json.Marshal(release)
	if err != nil {
		return nil, 0, err
	}
	rewritten, err := encodeHelmRelease(raw)
	if err != nil {
		return nil, 0, err
	}
	return rewritten, removed, nil
}

// stripV1alpha1Documents removes the YAML documents whose apiVersion is
// ate.dev/v1alpha1 from a Helm manifest and reports how many it removed.
// Helm writes a manifest as documents each introduced by a "---" line, and
// reads it back by splitting on those lines, which is what this reproduces.
func stripV1alpha1Documents(manifest string) (string, int) {
	var kept []string
	removed := 0
	for _, doc := range helmManifestSeparator.Split(manifest, -1) {
		if strings.TrimSpace(doc) == "" {
			continue
		}
		if v1alpha1APIVersion.MatchString(doc) {
			removed++
			continue
		}
		kept = append(kept, "---"+strings.TrimRight(doc, "\n")+"\n")
	}
	if removed == 0 {
		return manifest, 0
	}
	return strings.Join(kept, ""), removed
}

func decodeHelmRelease(encoded []byte) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(string(encoded))
	if err != nil {
		return nil, fmt.Errorf("while decoding the release data: %w", err)
	}
	if len(b) > 3 && bytes.Equal(b[:3], helmGzipMagic) {
		r, err := gzip.NewReader(bytes.NewReader(b))
		if err != nil {
			return nil, fmt.Errorf("while decompressing the release: %w", err)
		}
		defer r.Close()
		if b, err = io.ReadAll(r); err != nil {
			return nil, fmt.Errorf("while decompressing the release: %w", err)
		}
	}
	return b, nil
}

func encodeHelmRelease(raw []byte) ([]byte, error) {
	var buf bytes.Buffer
	w, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(raw); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return []byte(base64.StdEncoding.EncodeToString(buf.Bytes())), nil
}
