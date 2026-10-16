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

// Command podcertcontroller is a pod certificate controller that implements three signers.
//
//   - servicedns.podcert.ate.dev/identity: Issues certificate for Kubernetes service DNS names, backed by a
//     local CA.
//
//   - podidentity.podcert.ate.dev/identity: Issues certificates equivalent to KSA tokens, backed by a local CA.
//
//   - postgres.podcert.ate.dev/identity: Issues PostgreSQL login certificates to ate-api-server.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/spf13/pflag"
	"go.ate.dev/substrate/cmd/podcertcontroller/internal/issuer"
	"go.ate.dev/substrate/cmd/podcertcontroller/internal/podcertificate"
	"go.ate.dev/substrate/cmd/podcertcontroller/internal/podidentitysigner"
	"go.ate.dev/substrate/cmd/podcertcontroller/internal/postgressigner"
	"go.ate.dev/substrate/cmd/podcertcontroller/internal/rendezvous"
	"go.ate.dev/substrate/cmd/podcertcontroller/internal/servicednssigner"
	"go.ate.dev/substrate/cmd/podcertcontroller/internal/signercontroller"
	"go.ate.dev/substrate/cmd/podcertcontroller/internal/trustpublisher"
	"go.ate.dev/substrate/internal/clustertrustbundle"
	"go.ate.dev/substrate/internal/installdefaults"
	"go.ate.dev/substrate/internal/localca"
	"go.ate.dev/substrate/internal/preview"
	"go.ate.dev/substrate/internal/version"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
	"k8s.io/utils/clock"
)

var kubeConfigDefault string

func init() {
	if home := homedir.HomeDir(); home != "" {
		kubeConfigDefault = filepath.Join(home, ".kube", "config")
	}
}

var (
	kubeconfig = pflag.String("kubeconfig", kubeConfigDefault, "absolute path to the kubeconfig file")
	inCluster  = pflag.Bool("in-cluster", false, "Is the controller running in the cluster it should connect to?")

	shardingNamespace       = pflag.String("sharding-pod-namespace", "", "(Work Sharding) The namespace the controller is running in")
	shardingPodName         = pflag.String("sharding-pod-name", "", "(Work Sharding) The pod name of the controller")
	shardingPodUID          = pflag.String("sharding-pod-uid", "", "(Work Sharding) The pod UID of the controller")
	shardingApplicationName = pflag.String("sharding-application-name", "", "(Work Sharding) The application name to disambiguate Leases")

	serviceDNSCAPoolFile = pflag.String(
		"service-dns-ca-pool",
		"",
		"File that contains the CA pool state for "+servicednssigner.Name,
	)

	podCAPoolFile = pflag.String(
		"pod-identity-ca-pool",
		"",
		"File that contains the CA pool state for "+podidentitysigner.Name,
	)

	postgresCAPoolFile = pflag.String(
		"postgres-ca-pool",
		"",
		"File that contains the CA pool state for "+postgressigner.Name,
	)

	postgresClientNamespace = pflag.String(
		"postgres-client-namespace",
		installdefaults.SystemNamespace,
		"Namespace whose ate-api-server service account may request PostgreSQL login certificates",
	)

	workersPerSigner = pflag.Int(
		"workers-per-signer",
		1,
		"Number of concurrent worker goroutines per signer.",
	)

	kubeAPIQPS = pflag.Float32(
		"kube-api-qps",
		0,
		"Sustained queries per second allowed against the Kubernetes API. 0 keeps the client-go default.",
	)
	kubeAPIBurst = pflag.Int(
		"kube-api-burst",
		0,
		"Burst queries allowed against the Kubernetes API. 0 keeps the client-go default.",
	)

	// Delivery modes. The projected mode uses the certificates.k8s.io
	// PodCertificateRequest and ClusterTrustBundle APIs (v1beta1 in 1.34-1.36,
	// v1 from 1.37; enabled on GKE and kind). The agent mode serves the same
	// certificates over HTTPS to podcert-agent sidecars and publishes trust
	// bundles as ConfigMaps, for clusters (AKS, EKS) where those APIs are
	// unavailable. Both may be on at once during a migration.
	servePodCertificateRequests = pflag.Bool(
		"serve-pod-certificate-requests",
		true,
		"Fulfill certificates.k8s.io PodCertificateRequests and publish ClusterTrustBundles. Disable on clusters without that API.",
	)
	serveIssuerAPI = pflag.Bool(
		"serve-issuer-api",
		false,
		"Serve the podcert-agent issuer API and publish trust bundles as ConfigMaps in every namespace.",
	)
	issuerListenAddress = pflag.String(
		"issuer-listen-address",
		":8443",
		"Address the issuer API listens on.",
	)
	issuerAudience = pflag.String(
		"issuer-audience",
		issuer.DefaultAudience,
		"Bound ServiceAccount token audience the issuer API requires.",
	)
	issuerDNSNames = pflag.StringSlice(
		"issuer-dns-name",
		[]string{"podcert-issuer.podcertificate-controller-system.svc"},
		"DNS names on the issuer API's serving certificate (signed by the "+servicednssigner.Name+" CA pool).",
	)
	trustConfigMapPeriod = pflag.Duration(
		"trust-configmap-period",
		30*time.Second,
		"How often to reconcile the trust ConfigMaps in every namespace.",
	)

	showVersion  = pflag.Bool("version", false, "Print version and exit.")
	previewFlags = pflag.StringSlice("preview", nil, "Preview gates to enable.")
)

func main() {
	ctx := context.Background()

	pflag.Parse()
	if *showVersion {
		fmt.Println(version.String())
		return
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))
	if err := preview.Init(*previewFlags...); err != nil {
		slog.ErrorContext(ctx, "Invalid --preview", slog.Any("err", err))
		os.Exit(1)
	}
	slog.InfoContext(ctx, "podcertcontroller starting", slog.String("version", version.Version))

	var kconfig *rest.Config
	var err error
	if *inCluster {
		kconfig, err = rest.InClusterConfig()
		if err != nil {
			slog.ErrorContext(ctx, "Error creating in-cluster config", slog.Any("err", err))
			os.Exit(1)
		}
	} else {
		// use the current context in kubeconfig
		kconfig, err = clientcmd.BuildConfigFromFlags("", *kubeconfig)
		if err != nil {
			slog.ErrorContext(ctx, "Error reading kubeconfig", slog.Any("err", err))
			os.Exit(1)
		}
	}

	if *kubeAPIQPS < 0 || *kubeAPIBurst < 0 {
		slog.ErrorContext(ctx, "Invalid rate limits: --kube-api-qps and --kube-api-burst must not be negative",
			slog.Any("kube-api-qps", *kubeAPIQPS), slog.Int("kube-api-burst", *kubeAPIBurst))
		os.Exit(1)
	}
	if *kubeAPIQPS > 0 {
		kconfig.QPS = *kubeAPIQPS
	}
	if *kubeAPIBurst > 0 {
		kconfig.Burst = *kubeAPIBurst
	}

	kc, err := kubernetes.NewForConfig(kconfig)
	if err != nil {
		slog.ErrorContext(ctx, "Error creating Kubernetes client", slog.Any("err", err))
		os.Exit(1)
	}

	if !*servePodCertificateRequests && !*serveIssuerAPI {
		slog.ErrorContext(ctx, "At least one of --serve-pod-certificate-requests or --serve-issuer-api must be enabled")
		os.Exit(1)
	}

	// The certificates.k8s.io clients refuse to start on clusters that serve
	// neither API version, so only discover them when the PCR path is on.
	var pcrClient *podcertificate.Client
	var trustBundles *clustertrustbundle.Client
	if *servePodCertificateRequests {
		pcrClient, err = podcertificate.NewClient(kc)
		if err != nil {
			slog.ErrorContext(ctx, "Error discovering PodCertificateRequest API", slog.Any("err", err))
			os.Exit(1)
		}

		trustBundles, err = clustertrustbundle.NewClient(kc, nil)
		if err != nil {
			slog.ErrorContext(ctx, "Error discovering ClusterTrustBundle API", slog.Any("err", err))
			os.Exit(1)
		}
	}

	hasher := rendezvous.New(
		kc,
		*shardingNamespace,
		*shardingApplicationName,
		*shardingPodName,
		types.UID(*shardingPodUID),
		clock.RealClock{},
	)
	go hasher.Run(ctx)

	// Create a signer for servicedns.podcert.ate.dev/identity
	serviceDNSCAPool, err := localca.NewRefreshingPool(*serviceDNSCAPoolFile)
	if err != nil {
		slog.ErrorContext(ctx, "Error loading servicedns.podcert.ate.dev/identity CA pool state", slog.Any("err", err))
		os.Exit(1)
	}
	serviceDNSSigner := servicednssigner.NewImpl(kc, serviceDNSCAPool, pcrClient)

	// Create a signer for podidentity.podcert.ate.dev/identity
	podIdentityCAPool, err := localca.NewRefreshingPool(*podCAPoolFile)
	if err != nil {
		slog.ErrorContext(ctx, "Error loading podidentity.podcert.ate.dev/identity CA pool state", slog.Any("err", err))
		os.Exit(1)
	}
	podIdentitySigner := podidentitysigner.NewImpl(podIdentityCAPool, pcrClient)

	// Create a signer for postgres.podcert.ate.dev/identity
	postgresCAPool, err := localca.NewRefreshingPool(*postgresCAPoolFile)
	if err != nil {
		slog.ErrorContext(ctx, "Error loading PostgreSQL CA pool state", slog.Any("err", err))
		os.Exit(1)
	}
	postgresSigner := postgressigner.NewImpl(*postgresClientNamespace, postgresCAPool, pcrClient)

	// TODO: Reload when the file changes.

	if *servePodCertificateRequests {
		serviceDNSSignerController := signercontroller.New(clock.RealClock{}, serviceDNSSigner, hasher, pcrClient, trustBundles)
		podIdentitySignerController := signercontroller.New(clock.RealClock{}, podIdentitySigner, hasher, pcrClient, trustBundles)
		postgresSignerController := signercontroller.New(clock.RealClock{}, postgresSigner, hasher, pcrClient, trustBundles)
		go pcrClient.Informer().Run(ctx.Done())
		go serviceDNSSignerController.Run(ctx, *workersPerSigner)
		go podIdentitySignerController.Run(ctx, *workersPerSigner)
		go postgresSignerController.Run(ctx, *workersPerSigner)
	}

	if *serveIssuerAPI {
		publisher := trustpublisher.New(kc, hasher, serviceDNSSigner, podIdentitySigner, postgresSigner)
		go publisher.Run(ctx, *trustConfigMapPeriod)

		servingCert := issuer.NewServingCert(serviceDNSCAPool, *issuerDNSNames, 24*time.Hour, clock.RealClock{})
		server := &http.Server{
			Addr:              *issuerListenAddress,
			Handler:           issuer.New(kc, *issuerAudience, serviceDNSSigner, podIdentitySigner, postgresSigner).Handler(),
			TLSConfig:         servingCert.TLSConfig(),
			ReadHeaderTimeout: 10 * time.Second,
		}
		go func() {
			slog.InfoContext(ctx, "Serving issuer API", slog.String("addr", *issuerListenAddress), slog.Any("dnsNames", *issuerDNSNames))
			// Certificate and key come from TLSConfig.GetCertificate.
			if err := server.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
				slog.ErrorContext(ctx, "Issuer API server failed", slog.Any("err", err))
				os.Exit(1)
			}
		}()
	}

	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, syscall.SIGINT, syscall.SIGTERM)

	<-signalCh
}
