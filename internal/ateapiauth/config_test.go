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

package ateapiauth

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadAuthenticationConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "authentication.yaml")
	if err := os.WriteFile(path, []byte(`
actorIdentityJWTProvider: kubernetes
jwtProviders:
- name: kubernetes
  issuer: https://oidc.eks.us-east-1.amazonaws.com/id/ABCDEF
  audiences: [api.ate-system.svc]
  jwksURI: https://kubernetes.default.svc/openid/v1/jwks
  certificateAuthorityFile: /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
  discoveryTokenFile: /var/run/secrets/kubernetes.io/serviceaccount/token
- name: google
  issuer: https://accounts.google.com
  audiences: [cloud-sdk-client]
`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadAuthenticationConfig(path)
	if err != nil {
		t.Fatalf("LoadAuthenticationConfig() error = %v", err)
	}
	if got := len(cfg.JWTProviders); got != 2 {
		t.Fatalf("len(JWTProviders) = %d, want 2", got)
	}
	if got := cfg.JWTProviders[0].JWKSURI; got != "https://kubernetes.default.svc/openid/v1/jwks" {
		t.Fatalf("JWTProviders[0].JWKSURI = %q", got)
	}
	if got := cfg.JWTProviders[1].JWKSURI; got != "" {
		t.Fatalf("JWTProviders[1].JWKSURI = %q, want empty", got)
	}
}

func TestLoadAuthenticationConfigRejectsUnknownField(t *testing.T) {
	path := filepath.Join(t.TempDir(), "authentication.yaml")
	if err := os.WriteFile(path, []byte(`
actorIdentityJWTProvider: kubernetes
jwtProviders:
- name: kubernetes
  issuer: https://kubernetes.default.svc
  audiences: [api.ate-system.svc]
  typo: true
`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadAuthenticationConfig(path)
	if err == nil || !strings.Contains(err.Error(), `unknown field "typo"`) {
		t.Fatalf("LoadAuthenticationConfig() error = %v, want unknown-field error", err)
	}
}

func TestValidateAuthenticationConfig(t *testing.T) {
	valid := func() *AuthenticationConfig {
		return &AuthenticationConfig{
			ActorIdentityJWTProvider: "kubernetes",
			JWTProviders: []JWTProviderConfig{{
				Name:      "kubernetes",
				Issuer:    "https://kubernetes.default.svc",
				Audiences: []string{"api.ate-system.svc"},
			}},
		}
	}

	tests := []struct {
		name   string
		mutate func(*AuthenticationConfig)
	}{
		{name: "no providers", mutate: func(c *AuthenticationConfig) { c.JWTProviders = nil }},
		{name: "unknown actor identity provider", mutate: func(c *AuthenticationConfig) { c.ActorIdentityJWTProvider = "missing" }},
		{name: "insecure issuer", mutate: func(c *AuthenticationConfig) { c.JWTProviders[0].Issuer = "http://issuer.example" }},
		{name: "no audiences", mutate: func(c *AuthenticationConfig) { c.JWTProviders[0].Audiences = nil }},
		{name: "duplicate provider", mutate: func(c *AuthenticationConfig) { c.JWTProviders = append(c.JWTProviders, c.JWTProviders[0]) }},
		{name: "insecure jwksURI", mutate: func(c *AuthenticationConfig) {
			c.JWTProviders[0].JWKSURI = "http://kubernetes.default.svc/openid/v1/jwks"
		}},
		{name: "relative jwksURI", mutate: func(c *AuthenticationConfig) { c.JWTProviders[0].JWKSURI = "/openid/v1/jwks" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := valid()
			tt.mutate(cfg)
			if err := ValidateAuthenticationConfig(cfg); err == nil {
				t.Fatal("ValidateAuthenticationConfig() succeeded, want error")
			}
		})
	}
}
