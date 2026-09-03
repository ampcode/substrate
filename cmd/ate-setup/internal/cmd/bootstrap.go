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

package cmd

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	applyconfigcorev1 "k8s.io/client-go/applyconfigurations/core/v1"

	"github.com/agent-substrate/substrate/cmd/ate-setup/internal/config"
	"github.com/agent-substrate/substrate/cmd/ate-setup/internal/kube"
	"github.com/agent-substrate/substrate/cmd/ate-setup/internal/steps"
)

var helmRelease, helmReleaseNamespace string

// bootstrapCmd is the part of "deploy ate-system" that manifests cannot carry:
// the generated key material and the config derived from the cluster. It runs
// inside the cluster (a Helm pre-install hook, for instance) with the pod's
// service account, so it needs no repository checkout, kubeconfig or registry.
var bootstrapCmd = &cobra.Command{
	Use:   "bootstrap",
	Short: "Create the generated secrets and config for ate-system from inside the cluster",
	Long: `Create the namespaces, the actor-identity and podcertificate signing pools, and
the ate-api-server config that "deploy ate-system" generates, without the rest of
the install. Existing pools are kept. Meant to run in-cluster before the static
manifests are applied; with --helm-release the namespaces carry Helm's ownership
metadata so a chart that also lists them can adopt them.`,
	Args: cobra.NoArgs,
	PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
		var err error
		env, err = steps.NewEnv(&config.Config{Kubeconfig: opts.Kubeconfig, Context: opts.Context})
		return err
	},
	RunE: func(cmd *cobra.Command, _ []string) error {
		ctx := cmd.Context()
		for _, name := range []string{steps.NamespaceAteSystem, steps.NamespacePodCert, "otel-system"} {
			if err := applyNamespace(ctx, name); err != nil {
				return err
			}
		}
		return env.EnsureAPIServerPrerequisites(ctx)
	},
}

func applyNamespace(ctx context.Context, name string) error {
	ns := applyconfigcorev1.Namespace(name)
	if helmRelease != "" {
		ns.WithLabels(map[string]string{"app.kubernetes.io/managed-by": "Helm"}).
			WithAnnotations(map[string]string{
				"meta.helm.sh/release-name":      helmRelease,
				"meta.helm.sh/release-namespace": helmReleaseNamespace,
			})
	}
	// Its own field manager: the later steps apply the bare namespace as ate-setup, which would
	// otherwise drop the metadata again.
	opts := metav1.ApplyOptions{FieldManager: kube.FieldManager + "-bootstrap", Force: true}
	if _, err := env.Kube.Typed.CoreV1().Namespaces().Apply(ctx, ns, opts); err != nil {
		return fmt.Errorf("while applying namespace %s: %w", name, err)
	}
	return nil
}

func init() {
	rootCmd.AddCommand(bootstrapCmd)
	f := bootstrapCmd.Flags()
	f.StringVar(&helmRelease, "helm-release", "", "Helm release name to mark the namespaces as owned by")
	f.StringVar(&helmReleaseNamespace, "helm-release-namespace", "", "Namespace of that Helm release")
}
