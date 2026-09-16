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
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
)

func TestNewRegistryKeychain(t *testing.T) {
	if newRegistryKeychain(registryKeychainOptions{}) != nil {
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

	kc := newRegistryKeychain(registryKeychainOptions{DockerConfig: true, ECR: true})
	if kc == nil {
		t.Fatal("newRegistryKeychain() = nil, want a keychain")
	}

	private, err := name.ParseReference("artifactory.example.com/amp/orbd:latest")
	if err != nil {
		t.Fatal(err)
	}
	authenticator, err := kc.Resolve(private.Context())
	if err != nil {
		t.Fatalf("Resolve(private) error: %v", err)
	}
	cfg, err := authenticator.Authorization()
	if err != nil {
		t.Fatalf("Authorization() error: %v", err)
	}
	if cfg.Username != "robot" || cfg.Password != "s3cret" {
		t.Errorf("Resolve(private) = %q/%q, want robot/s3cret from the Docker config file", cfg.Username, cfg.Password)
	}

	public, err := name.ParseReference("registry.k8s.io/pause:3.10.2")
	if err != nil {
		t.Fatal(err)
	}
	authenticator, err = kc.Resolve(public.Context())
	if err != nil {
		t.Fatalf("Resolve(public) error: %v", err)
	}
	if authenticator != authn.Anonymous {
		t.Errorf("Resolve(public) = %#v, want authn.Anonymous for a registry the file does not list", authenticator)
	}
}
