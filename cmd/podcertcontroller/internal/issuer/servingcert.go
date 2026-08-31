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

package issuer

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"sync"
	"time"

	"github.com/agent-substrate/substrate/internal/localca"
	"k8s.io/utils/clock"
)

// ServingCert mints and rotates the issuer's own TLS serving certificate from
// the servicedns CA pool, so agents verify the issuer with the same trust
// bundle they use for every other Substrate service.
type ServingCert struct {
	caPool   localca.Pool
	dnsNames []string
	lifetime time.Duration
	clock    clock.PassiveClock

	mu      sync.Mutex
	current *tls.Certificate
	expires time.Time
}

// NewServingCert returns a ServingCert for dnsNames with certificates valid
// for lifetime, renewed once a third of that remains.
func NewServingCert(caPool localca.Pool, dnsNames []string, lifetime time.Duration, clock clock.PassiveClock) *ServingCert {
	return &ServingCert{caPool: caPool, dnsNames: dnsNames, lifetime: lifetime, clock: clock}
}

// TLSConfig returns a server tls.Config that serves the current certificate.
func (s *ServingCert) TLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion:     tls.VersionTLS13,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return s.Get() },
	}
}

// Get returns the current certificate, minting a new one when none exists or
// the current one is within a third of its lifetime of expiring.
func (s *ServingCert) Get() (*tls.Certificate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.clock.Now()
	if s.current != nil && now.Add(s.lifetime/3).Before(s.expires) {
		return s.current, nil
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("while generating serving key: %w", err)
	}
	notBefore := now.Add(-2 * time.Minute)
	notAfter := notBefore.Add(s.lifetime)
	template := &x509.Certificate{
		BasicConstraintsValid: true,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		DNSNames:              s.dnsNames,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	chainDER, err := s.caPool.CreateCertificate(template, key.Public())
	if err != nil {
		return nil, fmt.Errorf("while signing serving certificate: %w", err)
	}
	leaf, err := x509.ParseCertificate(chainDER[0])
	if err != nil {
		return nil, fmt.Errorf("while parsing serving certificate: %w", err)
	}

	s.current = &tls.Certificate{Certificate: chainDER, PrivateKey: key, Leaf: leaf}
	s.expires = notAfter
	return s.current, nil
}
