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

	"go.ate.dev/substrate/cmd/ate-setup/internal/config"
	"go.ate.dev/substrate/cmd/ate-setup/internal/kube"
	"go.ate.dev/substrate/cmd/ate-setup/internal/log"
	"go.ate.dev/substrate/cmd/ate-setup/internal/steps"
)

var helmRelease, helmReleaseNamespace, crdsPath string

// bootstrapCmd is the part of "deploy ate-system" that manifests cannot carry:
// the generated key material and the config derived from the cluster. It runs
// inside the cluster (a Helm pre-install hook, for instance) with the pod's
// service account, so it needs no repository checkout or registry; the
// kubeconfig comes from the pod when none is configured.
var bootstrapCmd = &cobra.Command{
	Use:   "bootstrap",
	Short: "Create the generated secrets and config for ate-system from inside the cluster",
	Long: `Create the namespaces, the actor-identity and podcertificate signing pools, and
the ate-api-server config that "deploy ate-system" generates, without the rest of
the install. Existing pools are kept; the PostgreSQL connection settings are
rewritten from the configuration every time, as on deploy. Meant to run
in-cluster before the static manifests are applied; with --helm-release the
namespaces carry Helm's ownership metadata so a chart that also lists them can
adopt them. With --crds the CRDs in that directory are applied too, which is
how a chart upgrades them: Helm installs a chart's CRDs once and never changes
them.`,
	Args: cobra.NoArgs,
	// Replaces the root hook: that one needs a repository checkout for
	// .ate-dev-env.sh and the manifests, and fetches GKE credentials, none of
	// which exist in a hook pod. The settings themselves still come from the
	// same registry, so the chart configures the hook with the same
	// environment variables and flags as ate-setup.
	PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
		cfg, err := config.LoadFlags(cmd.Flags(), config.LoadOptions{
			ConfigPath: configPath,
			NoDevEnv:   true,
			NoRepo:     true,
		})
		if err != nil {
			return err
		}
		resolved = cfg.Resolved()
		resolved.Report(log.Writer(), config.ReportOptions{OmitDefaults: noReportDefaults})
		env, err = steps.NewEnv(cfg)
		return err
	},
	RunE: func(cmd *cobra.Command, _ []string) error {
		ctx := cmd.Context()
		for _, name := range []string{steps.NamespaceAteSystem, steps.NamespacePodCert, "otel-system"} {
			if err := applyNamespace(ctx, name); err != nil {
				return err
			}
		}
		// Before the controllers that serve the new schema roll, so a
		// WorkerPool or SandboxConfig the chart applies next is not pruned
		// to the old one.
		if crdsPath != "" {
			if err := env.ApplyCRDs(ctx, crdsPath); err != nil {
				return err
			}
		}
		// The podcertificate controller mounts every signer pool, so the
		// pools have to exist before its Deployment is applied.
		if err := env.EnsurePodCertificateCAs(ctx); err != nil {
			return err
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
	f.StringVar(&crdsPath, "crds", "", "Directory of CRD manifests to apply before anything else (none by default)")
}
