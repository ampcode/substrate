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
	"fmt"

	"github.com/google/go-containerregistry/pkg/authn"
	"go.ate.dev/substrate/internal/imagecache"
)

// registryKeychain is the imagecache.CandidateKeychain atelet pulls images
// with. It tries the Docker config file first and the node's kubelet
// credential provider plugins second, so an explicit credential for a
// registry wins over the ambient cloud identity. Either source may be nil.
type registryKeychain struct {
	// dockerConfig reads $DOCKER_CONFIG/config.json, else
	// $HOME/.docker/config.json. This is the file a kubernetes.io/dockerconfigjson
	// Secret holds, so a private registry that kubelet would reach through
	// imagePullSecrets can be reached by atelet, which pulls images itself, by
	// mounting that Secret. Credential helpers named in the file are honored.
	// It answers Anonymous for a registry the file has no entry for.
	dockerConfig authn.Keychain
	// providers are the node's kubelet credential provider plugins.
	providers imagecache.CandidateKeychain
}

var _ imagecache.CandidateKeychain = (*registryKeychain)(nil)

// newRegistryKeychain combines the selected sources, or returns nil when
// neither is selected (pulls are then anonymous). A nil providers keychain
// means the node has no credential provider config.
func newRegistryKeychain(dockerConfig bool, providers imagecache.CandidateKeychain) imagecache.CandidateKeychain {
	if !dockerConfig && providers == nil {
		return nil
	}
	kc := &registryKeychain{providers: providers}
	if dockerConfig {
		kc.dockerConfig = authn.DefaultKeychain
	}
	return kc
}

// Resolve implements authn.Keychain.
func (k *registryKeychain) Resolve(target authn.Resource) (authn.Authenticator, error) {
	return k.ResolveContext(context.Background(), target)
}

// ResolveContext implements authn.ContextKeychain. It returns the first
// candidate, or authn.Anonymous if there are none.
func (k *registryKeychain) ResolveContext(ctx context.Context, target authn.Resource) (authn.Authenticator, error) {
	candidates, err := k.Candidates(ctx, target)
	if err != nil {
		return nil, err
	}
	if len(candidates) == 0 {
		return authn.Anonymous, nil
	}
	return candidates[0], nil
}

// Candidates implements imagecache.CandidateKeychain: the Docker config
// credential when the file has one for target, followed by every credential
// provider candidate.
func (k *registryKeychain) Candidates(ctx context.Context, target authn.Resource) ([]authn.Authenticator, error) {
	var candidates []authn.Authenticator
	if k.dockerConfig != nil {
		auth, err := authn.Resolve(ctx, k.dockerConfig, target)
		if err != nil {
			return nil, fmt.Errorf("while reading the Docker config file: %w", err)
		}
		if auth != authn.Anonymous {
			candidates = append(candidates, auth)
		}
	}
	if k.providers != nil {
		fromProviders, err := k.providers.Candidates(ctx, target)
		if err != nil {
			return nil, err
		}
		candidates = append(candidates, fromProviders...)
	}
	return candidates, nil
}
