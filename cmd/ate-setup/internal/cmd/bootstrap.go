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

package cmd

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	applyconfigcorev1 "k8s.io/client-go/applyconfigurations/core/v1"

	"go.ate.dev/substrate/cmd/ate-setup/internal/config"
	"go.ate.dev/substrate/cmd/ate-setup/internal/kube"
	"go.ate.dev/substrate/cmd/ate-setup/internal/log"
	"go.ate.dev/substrate/cmd/ate-setup/internal/steps"
)

var (
	helmRelease, helmReleaseNamespace, crdsPath, admissionPoliciesPath, sandboxConfigsPath string
	v1alpha1Upgrade                                                                        bool
	v1alpha1UpgradeScaleDown                                                               []string
	v1alpha1UpgradeTimeout                                                                 time.Duration
)

// bootstrapCmd is the part of "deploy ate-system" that manifests cannot carry:
// the generated key material and the config derived from the cluster. It runs
// inside the cluster (a Helm pre-install hook, for instance) with the pod's
// service account, so it needs no repository checkout or registry; the
// kubeconfig comes from the pod when none is configured.
var bootstrapCmd = &cobra.Command{
	Use:   "bootstrap",
	Short: "Create the generated secrets and config for ate-system from inside the cluster",
	Long: `Create the namespaces, the actor-identity, podcertificate and egress MITM
signing pools, and the ate-api-server config that "deploy ate-system" generates,
without the rest of the install. Existing pools are kept; the PostgreSQL connection settings are
rewritten from the configuration every time, as on deploy. Meant to run
in-cluster before the static manifests are applied; with --helm-release the
namespaces carry Helm's ownership metadata so a chart that also lists them can
adopt them. With --crds the CRDs in that directory are applied too, which is
how a chart upgrades them: Helm installs a chart's CRDs once and never changes
them. --admission-policies applies the manifests in that directory right after
the CRDs, so the resources applied next are checked by the current policies and
not by the previous release's. --sandbox-configs applies the SandboxConfigs in
that directory after the policies: a chart cannot carry them itself, since Helm
rejects a release whose custom resources name an API version the cluster does
not serve yet, as across a CRD version change. --v1alpha1-upgrade stops an install from before
1.0 first (scales down the Deployments named by --v1alpha1-upgrade-scale-down,
deletes its WorkerPools so every running sandbox is suspended, stops its
control plane, and deletes its v1alpha1 CRDs) and does nothing on a cluster
that is not one.`,
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
		// Before the new CRDs: 1.0 has no conversion from v1alpha1, so the
		// old CRDs are replaced, after the old install stopped cleanly.
		if v1alpha1Upgrade {
			if err := env.UpgradeFromV1alpha1(ctx, steps.V1alpha1Upgrade{
				ScaleDown: v1alpha1UpgradeScaleDown,
				Timeout:   v1alpha1UpgradeTimeout,
			}); err != nil {
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
		// Helm applies a release's resources sorted by kind, custom resources
		// before ValidatingAdmissionPolicy, so a SandboxConfig in the new
		// shape would otherwise be checked by the policy of the old release.
		if admissionPoliciesPath != "" {
			log.Step("apply_admission_policies")
			if err := env.Kube.ApplyPath(ctx, admissionPoliciesPath); err != nil {
				return err
			}
		}
		// After the CRDs and the policies that check them.
		if sandboxConfigsPath != "" {
			log.Step("apply_sandbox_configs")
			if err := env.Kube.ApplyPath(ctx, sandboxConfigsPath); err != nil {
				return err
			}
		}
		// The podcertificate controller mounts every signer pool, so the
		// pools have to exist before its Deployment is applied.
		if err := env.EnsurePodCertificateCAs(ctx); err != nil {
			return err
		}
		// atenet-egress mounts this pool; "deploy ate-system" creates it
		// right before applying the egress manifests.
		if err := env.EnsureEgressMITMCAPoolSecret(ctx); err != nil {
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
	f.StringVar(&admissionPoliciesPath, "admission-policies", "", "Directory of admission policy manifests to apply after the CRDs (none by default)")
	f.StringVar(&sandboxConfigsPath, "sandbox-configs", "", "Directory of SandboxConfig manifests to apply after the admission policies (none by default)")
	f.BoolVar(&v1alpha1Upgrade, "v1alpha1-upgrade", false, "Stop a pre-1.0 install (v1alpha1 CRDs) before applying the CRDs; no-op on any other cluster")
	f.StringSliceVar(&v1alpha1UpgradeScaleDown, "v1alpha1-upgrade-scale-down", nil, "Deployments (namespace/name) to scale to zero before the pre-1.0 worker pools are deleted")
	f.DurationVar(&v1alpha1UpgradeTimeout, "v1alpha1-upgrade-timeout", time.Hour, "How long to wait for each step of the pre-1.0 upgrade: the scale-downs, the worker pods suspending their sandboxes, and the CRD deletion")
}
