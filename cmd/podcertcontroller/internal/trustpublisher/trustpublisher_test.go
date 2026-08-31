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

package trustpublisher

import (
	"context"
	"testing"

	"github.com/agent-substrate/substrate/cmd/podcertcontroller/internal/podcertificate"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

type fakeSigner struct {
	name   string
	bundle string
}

func (s *fakeSigner) SignerName() string { return s.name }
func (s *fakeSigner) Issue(context.Context, *podcertificate.Request) (*podcertificate.Issued, error) {
	panic("not used")
}
func (s *fakeSigner) TrustBundlePEM() (string, error) { return s.bundle, nil }

type alwaysAssigned struct{}

func (alwaysAssigned) AssignedToThisReplica(context.Context, string) bool { return true }

func TestKey(t *testing.T) {
	if got, want := Key("podidentity.podcert.ate.dev/identity"), "podidentity.podcert.ate.dev-identity.pem"; got != want {
		t.Errorf("Key = %q, want %q", got, want)
	}
}

func TestReconcileAll(t *testing.T) {
	ctx := context.Background()
	kc := fake.NewSimpleClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "ate-system"}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "ate-demo-counter"}},
		&corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: "going-away"},
			Status:     corev1.NamespaceStatus{Phase: corev1.NamespaceTerminating},
		},
		// A stale ConfigMap that must be brought up to date.
		&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Name: ConfigMapName, Namespace: "ate-system"},
			Data:       map[string]string{"stale": "x"},
		},
	)

	podid := &fakeSigner{name: "podidentity.podcert.ate.dev/identity", bundle: "-----BEGIN CERTIFICATE-----\npodid\n"}
	svcdns := &fakeSigner{name: "servicedns.podcert.ate.dev/identity", bundle: "-----BEGIN CERTIFICATE-----\nsvcdns\n"}
	p := New(kc, alwaysAssigned{}, podid, svcdns)
	p.reconcileAll(ctx)

	want := map[string]string{
		"podidentity.podcert.ate.dev-identity.pem": podid.bundle,
		"servicedns.podcert.ate.dev-identity.pem":  svcdns.bundle,
	}
	for _, ns := range []string{"ate-system", "ate-demo-counter"} {
		cm, err := kc.CoreV1().ConfigMaps(ns).Get(ctx, ConfigMapName, metav1.GetOptions{})
		if err != nil {
			t.Fatalf("namespace %s: %v", ns, err)
		}
		if len(cm.Data) != len(want) {
			t.Errorf("namespace %s: got data %v, want %v", ns, cm.Data, want)
		}
		for k, v := range want {
			if cm.Data[k] != v {
				t.Errorf("namespace %s: key %s = %q, want %q", ns, k, cm.Data[k], v)
			}
		}
		if cm.Labels["podcert.ate.dev/canarying"] != "live" {
			t.Errorf("namespace %s: missing live label, got %v", ns, cm.Labels)
		}
	}
	if _, err := kc.CoreV1().ConfigMaps("going-away").Get(ctx, ConfigMapName, metav1.GetOptions{}); err == nil {
		t.Errorf("ConfigMap was created in a terminating namespace")
	}

	// A second pass with unchanged bundles must not issue updates.
	kc.ClearActions()
	p.reconcileAll(ctx)
	for _, a := range kc.Actions() {
		if a.GetVerb() == "update" || a.GetVerb() == "create" {
			t.Errorf("unexpected %s on %s during steady state", a.GetVerb(), a.GetResource().Resource)
		}
	}

	// Rotating a CA propagates.
	podid.bundle += "-----BEGIN CERTIFICATE-----\npodid-next\n"
	p.reconcileAll(ctx)
	cm, err := kc.CoreV1().ConfigMaps("ate-system").Get(ctx, ConfigMapName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if cm.Data["podidentity.podcert.ate.dev-identity.pem"] != podid.bundle {
		t.Errorf("rotated bundle not propagated")
	}
}
