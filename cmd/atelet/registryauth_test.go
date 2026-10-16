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
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
)

// fakeProviders stands in for the kubelet credential provider keychain and
// answers one credential for every registry.
type fakeProviders struct{ auth authn.Authenticator }

func (f fakeProviders) Resolve(authn.Resource) (authn.Authenticator, error) { return f.auth, nil }
func (f fakeProviders) Candidates(context.Context, authn.Resource) ([]authn.Authenticator, error) {
	return []authn.Authenticator{f.auth}, nil
}

func TestNewRegistryKeychain(t *testing.T) {
	if newRegistryKeychain(false, nil) != nil {
		t.Fatal("newRegistryKeychain() with no source = keychain, want nil (anonymous pulls)")
	}

	// A kubernetes.io/dockerconfigjson Secret mounted as DOCKER_CONFIG/config.json.
	dir := t.TempDir()
	auth := base64.StdEncoding.EncodeToString([]byte("robot:s3cret"))
	config := `{"auths":{"artifactory.example.com":{"auth":"` + auth + `"}}}`
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DOCKER_CONFIG", dir)
	cloud := &authn.Basic{Username: "cloud", Password: "token"}

	kc := newRegistryKeychain(true, fakeProviders{auth: cloud})
	if kc == nil {
		t.Fatal("newRegistryKeychain() = nil, want a keychain")
	}

	private, err := name.ParseReference("artifactory.example.com/amp/orbd:latest")
	if err != nil {
		t.Fatal(err)
	}
	candidates, err := kc.Candidates(t.Context(), private.Context())
	if err != nil {
		t.Fatalf("Candidates(private) error: %v", err)
	}
	if len(candidates) != 2 {
		t.Fatalf("Candidates(private) = %d candidates, want the Docker config entry then the provider's", len(candidates))
	}
	cfg, err := candidates[0].Authorization()
	if err != nil {
		t.Fatalf("Authorization() error: %v", err)
	}
	if cfg.Username != "robot" || cfg.Password != "s3cret" {
		t.Errorf("Candidates(private)[0] = %q/%q, want robot/s3cret from the Docker config file", cfg.Username, cfg.Password)
	}
	if candidates[1] != cloud {
		t.Errorf("Candidates(private)[1] = %#v, want the credential provider's credential", candidates[1])
	}

	public, err := name.ParseReference("registry.k8s.io/pause:3.10.2")
	if err != nil {
		t.Fatal(err)
	}
	candidates, err = kc.Candidates(t.Context(), public.Context())
	if err != nil {
		t.Fatalf("Candidates(public) error: %v", err)
	}
	if len(candidates) != 1 || candidates[0] != cloud {
		t.Errorf("Candidates(public) = %#v, want only the provider's credential for a registry the file does not list", candidates)
	}

	// Docker config alone: a registry the file does not list is anonymous.
	kc = newRegistryKeychain(true, nil)
	authenticator, err := kc.Resolve(public.Context())
	if err != nil {
		t.Fatalf("Resolve(public) error: %v", err)
	}
	if authenticator != authn.Anonymous {
		t.Errorf("Resolve(public) = %#v, want authn.Anonymous", authenticator)
	}
}
