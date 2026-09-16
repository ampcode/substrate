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
	"io"

	ecrlogin "github.com/awslabs/amazon-ecr-credential-helper/ecr-login"
	"github.com/google/go-containerregistry/pkg/authn"
)

// registryKeychainOptions selects the credential sources atelet consults for
// image pulls from registries that are not covered by the GCP authenticator
// (see imagecache.Store.remoteOpts).
type registryKeychainOptions struct {
	// DockerConfig reads credentials from the Docker config file:
	// $DOCKER_CONFIG/config.json, else $HOME/.docker/config.json. This is the
	// file a kubernetes.io/dockerconfigjson Secret holds, so a private
	// registry that kubelet would reach through imagePullSecrets can be
	// reached by atelet, which pulls images itself, by mounting that Secret.
	// Credential helpers named in the file are honored.
	DockerConfig bool
	// ECR authenticates pulls from Amazon ECR registries with the AWS SDK
	// default credential chain (IRSA on EKS).
	ECR bool
}

// newRegistryKeychain builds the keychain for the selected sources, or nil
// when none is selected (pulls are then anonymous). The Docker config file is
// consulted first so an explicit credential for an ECR registry wins over the
// ambient AWS identity. Every source answers Anonymous for a registry it has
// nothing for, so enabling one never breaks pulls from public registries.
func newRegistryKeychain(opts registryKeychainOptions) authn.Keychain {
	var keychains []authn.Keychain
	if opts.DockerConfig {
		keychains = append(keychains, authn.DefaultKeychain)
	}
	if opts.ECR {
		// The helper answers only for *.dkr.ecr.*.amazonaws.com and
		// public.ecr.aws.
		keychains = append(keychains, authn.NewKeychainFromHelper(ecrlogin.NewECRHelper(ecrlogin.WithLogger(io.Discard))))
	}
	if len(keychains) == 0 {
		return nil
	}
	return authn.NewMultiKeychain(keychains...)
}
