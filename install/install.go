// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package install

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/runtime"

	"github.com/blang/semver/v4"
	"github.com/spf13/pflag"
	"helm.sh/helm/v3/pkg/cli/values"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/api/v1/models"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/versioncheck"

	"github.com/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium-cli/internal/certs"
	"github.com/cilium/cilium-cli/internal/helm"
	"github.com/cilium/cilium-cli/internal/utils"
	"github.com/cilium/cilium-cli/k8s"
	"github.com/cilium/cilium-cli/status"
)

const (
	DatapathTunnel    = "tunnel"
	DatapathAwsENI    = "aws-eni"
	DatapathGKE       = "gke"
	DatapathAzure     = "azure"
	DatapathAKSBYOCNI = "aks-byocni"
)

const (
	ipamKubernetes  = "kubernetes"
	ipamClusterPool = "cluster-pool"
	ipamENI         = "eni"
	ipamAzure       = "azure"
)

const (
	tunnelDisabled = "disabled"
	tunnelVxlan    = "vxlan"
)

const (
	encryptionDisabled  = "disabled"
	encryptionIPsec     = "ipsec"
	encryptionWireguard = "wireguard"
)

const (
	Microk8sSnapPath = "/var/snap/microk8s/current"
)

func (k *K8sInstaller) generateAgentDaemonSet() *appsv1.DaemonSet {
	var (
		dsFilename string
	)

	switch {
	case versioncheck.MustCompile(">1.10.99")(k.chartVersion):
		dsFilename = "templates/cilium-agent/daemonset.yaml"
	case versioncheck.MustCompile(">=1.9.0")(k.chartVersion):
		dsFilename = "templates/cilium-agent-daemonset.yaml"
	}

	dsFile := k.manifests[dsFilename]

	var ds appsv1.DaemonSet
	utils.MustUnmarshalYAML([]byte(dsFile), &ds)
	return &ds
}

func (k *K8sInstaller) generateOperatorDeployment() *appsv1.Deployment {
	var (
		deployFilename string
	)

	switch {
	case versioncheck.MustCompile(">1.10.99")(k.chartVersion):
		deployFilename = "templates/cilium-operator/deployment.yaml"
	case versioncheck.MustCompile(">=1.9.0")(k.chartVersion):
		deployFilename = "templates/cilium-operator-deployment.yaml"
	}

	deployFile := k.manifests[deployFilename]

	var deploy appsv1.Deployment
	utils.MustUnmarshalYAML([]byte(deployFile), &deploy)
	return &deploy
}

func (k *K8sInstaller) generateIngressClass() *networkingv1.IngressClass {
	var (
		ingressFileName string
	)

	switch {
	case versioncheck.MustCompile(">=1.12.0")(k.chartVersion):
		ingressFileName = "templates/cilium-operator-deployment.yaml"
	}

	ingressClassFile, exists := k.manifests[ingressFileName]
	if !exists {
		return nil
	}

	var ingressClass networkingv1.IngressClass
	utils.MustUnmarshalYAML([]byte(ingressClassFile), &ingressClass)
	return &ingressClass
}

func (k *K8sInstaller) getSecretNamespace() string {
	var (
		nsFilename string
	)

	switch {
	case versioncheck.MustCompile(">1.11.99")(k.chartVersion):
		nsFilename = "templates/cilium-secrets-namespace.yaml"
	}

	nsFile, ok := k.manifests[nsFilename]
	if !ok {
		return ""
	}

	var ns corev1.Namespace
	utils.MustUnmarshalYAML([]byte(nsFile), &ns)
	return ns.GetName()
}

type k8sInstallerImplementation interface {
	ResourceCreatorFor(namespace string, logFunc k8s.LogFunc) k8s.ResourceCreator
	ClusterName() string
	GetAPIServerHostAndPort() (string, string)
	ListNodes(ctx context.Context, options metav1.ListOptions) (*corev1.NodeList, error)
	PatchNode(ctx context.Context, nodeName string, pt types.PatchType, data []byte) (*corev1.Node, error)
	GetCiliumExternalWorkload(ctx context.Context, name string, opts metav1.GetOptions) (*ciliumv2.CiliumExternalWorkload, error)
	CreateCiliumExternalWorkload(ctx context.Context, cew *ciliumv2.CiliumExternalWorkload, opts metav1.CreateOptions) (*ciliumv2.CiliumExternalWorkload, error)
	DeleteCiliumExternalWorkload(ctx context.Context, name string, opts metav1.DeleteOptions) error
	ListCiliumExternalWorkloads(ctx context.Context, opts metav1.ListOptions) (*ciliumv2.CiliumExternalWorkloadList, error)
	CreateServiceAccount(ctx context.Context, namespace string, account *corev1.ServiceAccount, opts metav1.CreateOptions) (*corev1.ServiceAccount, error)
	DeleteServiceAccount(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error
	GetConfigMap(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*corev1.ConfigMap, error)
	CreateConfigMap(ctx context.Context, namespace string, config *corev1.ConfigMap, opts metav1.CreateOptions) (*corev1.ConfigMap, error)
	DeleteConfigMap(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error
	CreateClusterRole(ctx context.Context, config *rbacv1.ClusterRole, opts metav1.CreateOptions) (*rbacv1.ClusterRole, error)
	DeleteClusterRole(ctx context.Context, name string, opts metav1.DeleteOptions) error
	CreateClusterRoleBinding(ctx context.Context, role *rbacv1.ClusterRoleBinding, opts metav1.CreateOptions) (*rbacv1.ClusterRoleBinding, error)
	DeleteClusterRoleBinding(ctx context.Context, name string, opts metav1.DeleteOptions) error
	CreateRole(ctx context.Context, namespace string, role *rbacv1.Role, opts metav1.CreateOptions) (*rbacv1.Role, error)
	UpdateRole(ctx context.Context, namespace string, role *rbacv1.Role, opts metav1.UpdateOptions) (*rbacv1.Role, error)
	DeleteRole(ctx context.Context, namespace string, name string, opts metav1.DeleteOptions) error
	CreateRoleBinding(ctx context.Context, namespace string, roleBinding *rbacv1.RoleBinding, opts metav1.CreateOptions) (*rbacv1.RoleBinding, error)
	UpdateRoleBinding(ctx context.Context, namespace string, roleBinding *rbacv1.RoleBinding, opts metav1.UpdateOptions) (*rbacv1.RoleBinding, error)
	DeleteRoleBinding(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error
	CreateDaemonSet(ctx context.Context, namespace string, ds *appsv1.DaemonSet, opts metav1.CreateOptions) (*appsv1.DaemonSet, error)
	ListDaemonSet(ctx context.Context, namespace string, o metav1.ListOptions) (*appsv1.DaemonSetList, error)
	GetDaemonSet(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*appsv1.DaemonSet, error)
	DeleteDaemonSet(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error
	PatchDaemonSet(ctx context.Context, namespace, name string, pt types.PatchType, data []byte, opts metav1.PatchOptions) (*appsv1.DaemonSet, error)
	GetService(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*corev1.Service, error)
	GetEndpoints(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*corev1.Endpoints, error)
	CreateService(ctx context.Context, namespace string, service *corev1.Service, opts metav1.CreateOptions) (*corev1.Service, error)
	DeleteService(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error
	DeleteDeployment(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error
	CreateDeployment(ctx context.Context, namespace string, deployment *appsv1.Deployment, opts metav1.CreateOptions) (*appsv1.Deployment, error)
	GetDeployment(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*appsv1.Deployment, error)
	PatchDeployment(ctx context.Context, namespace, name string, pt types.PatchType, data []byte, opts metav1.PatchOptions) (*appsv1.Deployment, error)
	CheckDeploymentStatus(ctx context.Context, namespace, deployment string) error
	DeleteNamespace(ctx context.Context, namespace string, opts metav1.DeleteOptions) error
	CreateNamespace(ctx context.Context, namespace string, opts metav1.CreateOptions) (*corev1.Namespace, error)
	GetNamespace(ctx context.Context, namespace string, options metav1.GetOptions) (*corev1.Namespace, error)
	ListPods(ctx context.Context, namespace string, options metav1.ListOptions) (*corev1.PodList, error)
	DeletePod(ctx context.Context, namespace, name string, options metav1.DeleteOptions) error
	ExecInPod(ctx context.Context, namespace, pod, container string, command []string) (bytes.Buffer, error)
	CreateSecret(ctx context.Context, namespace string, secret *corev1.Secret, opts metav1.CreateOptions) (*corev1.Secret, error)
	UpdateSecret(ctx context.Context, namespace string, secret *corev1.Secret, opts metav1.UpdateOptions) (*corev1.Secret, error)
	DeleteSecret(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error
	GetSecret(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*corev1.Secret, error)
	PatchSecret(ctx context.Context, namespace, name string, pt types.PatchType, data []byte, opts metav1.PatchOptions) (*corev1.Secret, error)
	CreateResourceQuota(ctx context.Context, namespace string, r *corev1.ResourceQuota, opts metav1.CreateOptions) (*corev1.ResourceQuota, error)
	DeleteResourceQuota(ctx context.Context, namespace, name string, opts metav1.DeleteOptions) error
	AutodetectFlavor(ctx context.Context) k8s.Flavor
	ContextName() (name string)
	CiliumStatus(ctx context.Context, namespace, pod string) (*models.StatusResponse, error)
	ListCiliumEndpoints(ctx context.Context, namespace string, opts metav1.ListOptions) (*ciliumv2.CiliumEndpointList, error)
	GetRunningCiliumVersion(ctx context.Context, namespace string) (string, error)
	GetPlatform(ctx context.Context) (*k8s.Platform, error)
	GetServerVersion() (*semver.Version, error)
	CreateIngressClass(ctx context.Context, r *networkingv1.IngressClass, opts metav1.CreateOptions) (*networkingv1.IngressClass, error)
	DeleteIngressClass(ctx context.Context, name string, opts metav1.DeleteOptions) error
	CiliumLogs(ctx context.Context, namespace, pod string, since time.Time, filter *regexp.Regexp) (string, error)
	ListAPIResources(ctx context.Context) ([]string, error)
	GetHelmState(ctx context.Context, namespace string, secretName string) (*helm.State, error)
}

type K8sInstaller struct {
	client          k8sInstallerImplementation
	resourceCreator k8s.ResourceCreator
	params          Parameters
	flavor          k8s.Flavor
	certManager     *certs.CertManager
	rollbackSteps   []rollbackStep
	manifests       map[string]string
	helmYAMLValues  string
	chartVersion    semver.Version
}

type AzureParameters struct {
	ResourceGroupName    string
	AKSNodeResourceGroup string
	SubscriptionName     string
	SubscriptionID       string
	TenantID             string
	ClientID             string
	ClientSecret         string
	IsBYOCNI             bool
}

var (
	// FlagsToHelmOpts maps the deprecated install flags to the helm
	// options
	FlagsToHelmOpts = map[string]string{
		"agent-image":           "image.override",
		"azure-client-id":       "azure.clientID",
		"azure-client-secret":   "azure.clientSecret",
		"azure-resource-group":  "azure.resourceGroup",
		"azure-subscription-id": "azure.subscriptionID",
		"azure-tenant-id":       "azure.tenantID",
		"cluster-id":            "cluster.id",
		"cluster-name":          "cluster.name",
		"ipam":                  "ipam.mode",
		"ipv4-native-routing-cidr": "ipv4NativeRoutingCIDR",
		"kube-proxy-replacement":   "kubeProxyReplacement",
		"node-encryption":          "encryption.nodeEncryption",
		"operator-image":           "operator.image.override",
	}
	// FlagValues maps all FlagsToHelmOpts keys to their values
	FlagValues = map[string]pflag.Value{}
)

type Parameters struct {
	Namespace             string
	Writer                io.Writer
	ClusterName           string
	DisableChecks         []string
	Version               string
	AgentImage            string
	OperatorImage         string
	RelayImage            string
	ClusterMeshAPIImage   string
	InheritCA             string
	Wait                  bool
	WaitDuration          time.Duration
	DatapathMode          string
	IPv4NativeRoutingCIDR string
	ClusterID             int
	IPAM                  string
	KubeProxyReplacement  string
	Azure                 AzureParameters
	RestartUnmanagedPods  bool
	Encryption            string
	NodeEncryption        bool
	ConfigOverwrites      []string
	configOverwrites      map[string]string
	Rollback              bool

	// CiliumReadyTimeout defines the wait timeout for Cilium to become ready
	// after installing.
	CiliumReadyTimeout time.Duration

	// K8sVersion is the Kubernetes version that will be used to generate the
	// kubernetes manifests. If the auto-detection fails, this flag can be used
	// as a workaround.
	K8sVersion string

	// HelmChartDirectory points to the location of a helm chart directory.
	// Useful to test from upstream where a helm release is not available yet.
	HelmChartDirectory string

	// HelmOpts are all the options the user used to pass into the Cilium cli
	// template.
	HelmOpts values.Options

	// HelmGenValuesFile points to the file that will store the generated helm
	// options.
	HelmGenValuesFile string

	// ImageSuffix will set the suffix that should be set on all docker images
	// generated by cilium-cli
	ImageSuffix string

	// ImageTag will set the tags that will be set on all docker images
	// generated by cilium-cli
	ImageTag string

	// HelmValuesSecretName is the name of the secret where helm values will be
	// stored.
	HelmValuesSecretName string

	// ListVersions lists all the available versions for install without actually installing.
	ListVersions bool

	// NodesWithoutCilium lists all nodes on which Cilium is not installed.
	NodesWithoutCilium []string

	// APIVersions defines extra kubernetes api resources that can be passed to helm for capabilities validation,
	// specifically for CRDs.
	APIVersions []string
	// UserSetKubeProxyReplacement will be set as true if user passes helm opt or commadline flag for the Kube-Proxy replacement.
	UserSetKubeProxyReplacement bool
}

type rollbackStep func(context.Context)

func (p *Parameters) validate() error {
	p.configOverwrites = map[string]string{}
	for _, config := range p.ConfigOverwrites {
		t := strings.SplitN(config, "=", 2)
		if len(t) != 2 {
			return fmt.Errorf("invalid config overwrite %q, must be in the form key=valye", config)
		}

		p.configOverwrites[t[0]] = t[1]
	}
	if p.AgentImage != "" || p.OperatorImage != "" || p.RelayImage != "" {
		return nil
	} else if !utils.CheckVersion(p.Version) && p.Version != "" {
		return fmt.Errorf("invalid syntax %q for image tag", p.Version)
	}

	return nil
}

func (k *K8sInstaller) fqAgentImage(imagePathMode utils.ImagePathMode) string {
	return utils.BuildImagePath(k.params.AgentImage, k.params.Version, defaults.AgentImage, defaults.Version, imagePathMode)
}

func (k *K8sInstaller) fqOperatorImage(imagePathMode utils.ImagePathMode) string {
	defaultImage := defaults.OperatorImage
	switch k.params.DatapathMode {
	case DatapathAwsENI:
		defaultImage = defaults.OperatorImageAWS
	case DatapathAzure:
		defaultImage = defaults.OperatorImageAzure
	}

	return utils.BuildImagePath(k.params.OperatorImage, k.params.Version, defaultImage, defaults.Version, imagePathMode)
}

func (k *K8sInstaller) fqRelayImage(imagePathMode utils.ImagePathMode) string {
	return utils.BuildImagePath(k.params.RelayImage, k.params.Version, defaults.RelayImage, defaults.Version, imagePathMode)
}

func (k *K8sInstaller) fqClusterMeshAPIImage(imagePathMode utils.ImagePathMode) string {
	return utils.BuildImagePath(k.params.ClusterMeshAPIImage, k.params.Version, defaults.ClusterMeshApiserverImage, defaults.Version, imagePathMode)
}

func NewK8sInstaller(client k8sInstallerImplementation, p Parameters) (*K8sInstaller, error) {
	if err := (&p).validate(); err != nil {
		return nil, fmt.Errorf("invalid parameters: %w", err)
	}

	cm := certs.NewCertManager(client, certs.Parameters{Namespace: p.Namespace})
	chartVersion, err := helm.ResolveHelmChartVersion(p.Version, p.HelmChartDirectory)
	if err != nil {
		return nil, err
	}

	return &K8sInstaller{
		client: client,
		resourceCreator: client.ResourceCreatorFor(p.Namespace, func(msg string) {
			_, _ = fmt.Fprintf(p.Writer, msg+"\n")
		}),
		params:       p,
		certManager:  cm,
		chartVersion: chartVersion,
	}, nil
}

func (k *K8sInstaller) Log(format string, a ...interface{}) {
	fmt.Fprintf(k.params.Writer, format+"\n", a...)
}

func (k *K8sInstaller) Exec(command string, args ...string) ([]byte, error) {
	return utils.Exec(k, command, args...)
}

func (k *K8sInstaller) getImagesSHA() string {
	ersion := strings.TrimPrefix(k.params.Version, "v")
	_, err := versioncheck.Version(ersion)
	// If we got an error then it means this is a commit SHA that the user
	// wants to install on all images.
	if err != nil {
		return k.params.Version
	}
	return ""
}

func (k *K8sInstaller) generateConfigMap() (*corev1.ConfigMap, error) {
	var (
		cmFilename string
	)

	switch {
	case versioncheck.MustCompile(">=1.9.0")(k.chartVersion):
		cmFilename = "templates/cilium-configmap.yaml"
	default:
		return nil, fmt.Errorf("cilium version unsupported %s", k.chartVersion.String())
	}

	cmFile := k.manifests[cmFilename]

	var cm corev1.ConfigMap
	utils.MustUnmarshalYAML([]byte(cmFile), &cm)
	k.Log("🚀 Creating ConfigMap for Cilium version %s...", k.chartVersion)

	for key, value := range k.params.configOverwrites {
		k.Log("ℹ️ Manual overwrite in ConfigMap: %s=%s", key, value)
		cm.Data[key] = value
	}

	if cm.Data["install-no-conntrack-iptables-rules"] == "true" {
		switch k.params.DatapathMode {
		case DatapathAwsENI:
			return nil, fmt.Errorf("--install-no-conntrack-iptables-rules cannot be enabled on AWS EKS")
		case DatapathGKE:
			return nil, fmt.Errorf("--install-no-conntrack-iptables-rules cannot be enabled on Google GKE")
		case DatapathAzure:
			return nil, fmt.Errorf("--install-no-conntrack-iptables-rules cannot be enabled on Azure AKS")
		}

		if cm.Data["tunnel"] != "disabled" {
			return nil, fmt.Errorf("--install-no-conntrack-iptables-rules requires tunneling to be disabled")
		}

		if cm.Data["kube-proxy-replacement"] != "strict" {
			return nil, fmt.Errorf("--install-no-conntrack-iptables-rules requires kube-proxy replacement to be enabled")
		}

		if cm.Data["enable-bpf-masquerade"] != "true" {
			return nil, fmt.Errorf("--install-no-conntrack-iptables-rules requires eBPF masquerading to be enabled")
		}

		if cm.Data["cni-chaining-mode"] != "" {
			return nil, fmt.Errorf("--install-no-conntrack-iptables-rules cannot be enabled with CNI chaining")
		}
	}

	return &cm, nil
}

func (k *K8sInstaller) createResourceQuotas() k8s.ResourceSet {
	typeMeta := metav1.TypeMeta{
		// TODO obtain kind via reflection.
		Kind:       "ResourceQuota",
		APIVersion: corev1.SchemeGroupVersion.String(),
	}
	ciliumResourceQuota := &corev1.ResourceQuota{
		ObjectMeta: metav1.ObjectMeta{
			Name: defaults.AgentResourceQuota,
		},
		TypeMeta: typeMeta,
		Spec: corev1.ResourceQuotaSpec{
			Hard: corev1.ResourceList{
				// 5k nodes * 2 DaemonSets (Cilium and cilium node init)
				corev1.ResourcePods: resource.MustParse("10k"),
			},
			ScopeSelector: &corev1.ScopeSelector{
				MatchExpressions: []corev1.ScopedResourceSelectorRequirement{
					{
						ScopeName: corev1.ResourceQuotaScopePriorityClass,
						Operator:  corev1.ScopeSelectorOpIn,
						Values:    []string{"system-node-critical"},
					},
				},
			},
		},
	}
	operatorResourceQuota := &corev1.ResourceQuota{
		ObjectMeta: metav1.ObjectMeta{
			Name: defaults.OperatorResourceQuota,
		},
		TypeMeta: typeMeta,
		Spec: corev1.ResourceQuotaSpec{
			Hard: corev1.ResourceList{
				// 15 "clusterwide" Cilium Operator pods for HA
				corev1.ResourcePods: resource.MustParse("15"),
			},
			ScopeSelector: &corev1.ScopeSelector{
				MatchExpressions: []corev1.ScopedResourceSelectorRequirement{
					{
						ScopeName: corev1.ResourceQuotaScopePriorityClass,
						Operator:  corev1.ScopeSelectorOpIn,
						Values:    []string{"system-cluster-critical"},
					},
				},
			},
		},
	}

	return k8s.ResourceSet{
		LogMsg: "🚀 Creating Resource quotas...",
		Objects: []runtime.Object{
			ciliumResourceQuota,
			operatorResourceQuota},
	}
}

func (k *K8sInstaller) restartUnmanagedPods(ctx context.Context) error {
	var printed bool

	pods, err := k.client.ListPods(ctx, "", metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("unable to list pods: %w", err)
	}

	// If not pods are running, skip. This avoids attempting to retrieve
	// CiliumEndpoints if no pods are present at all. Cilium will not be
	// running either.
	if len(pods.Items) == 0 {
		return nil
	}

	cepMap := map[string]struct{}{}
	ceps, err := k.client.ListCiliumEndpoints(ctx, "", metav1.ListOptions{})
	if err != nil {
		// When the CEP has not been registered yet, it's impossible
		// for any pods to be managed by Cilium.
		if err.Error() != "the server could not find the requested resource (get ciliumendpoints.cilium.io)" {
			return fmt.Errorf("unable to list cilium endpoints: %w", err)
		}
	} else {
		for _, cep := range ceps.Items {
			cepMap[cep.Namespace+"/"+cep.Name] = struct{}{}
		}
	}

	for _, pod := range pods.Items {
		// PodSucceeded means that all containers in the pod have voluntarily terminated
		// with a container exit code of 0, and the system is not going to restart any of these containers.
		if pod.Status.Phase == corev1.PodSucceeded {
			continue
		}
		if !pod.Spec.HostNetwork {
			if _, ok := cepMap[pod.Namespace+"/"+pod.Name]; ok {
				continue
			}

			if !printed {
				k.Log("♻️  Restarting unmanaged pods...")
				printed = true
			}
			err := k.client.DeletePod(ctx, pod.Namespace, pod.Name, metav1.DeleteOptions{})
			if err != nil {
				k.Log("⚠️  Unable to restart pod %s/%s: %s", pod.Namespace, pod.Name, err)
			} else {
				k.Log("♻️  Restarted unmanaged pod %s/%s", pod.Namespace, pod.Name)
			}
		}
	}

	return nil

}

// TODO: APILifecycleReplacement
// is this function used by the k8s deprecation linter.

func (k *K8sInstaller) listVersions() error {
	versions, err := helm.ListVersions()
	if err != nil {
		return err
	}
	// Iterate backwards to print the newest version first.
	for i := len(versions) - 1; i >= 0; i-- {
		if versions[i] == defaults.Version {
			fmt.Println(versions[i], "(default)")
		} else {
			fmt.Println(versions[i])
		}
	}
	return err
}

func (k *K8sInstaller) Install(ctx context.Context) error {
	// If --list-versions flag is specified, print available versions and return.
	if k.params.ListVersions {
		return k.listVersions()
	}
	if err := k.autodetectAndValidate(ctx); err != nil {
		return err
	}

	switch k.flavor.Kind {
	case k8s.KindGKE:
		if k.params.IPv4NativeRoutingCIDR == "" {
			cidr, err := k.gkeNativeRoutingCIDR(ctx, k.client.ContextName())
			if err != nil {
				k.Log("❌ Unable to auto-detect GKE native routing CIDR. Is \"gcloud\" installed?")
				k.Log("ℹ️  You can set the native routing CIDR manually with --ipv4-native-routing-cidr")
				return err
			}
			k.params.IPv4NativeRoutingCIDR = cidr
		}

	case k8s.KindAKS:
		if k.params.DatapathMode == DatapathAzure {
			// The Azure Service Principal is only needed when using Azure IPAM
			if err := k.azureSetupServicePrincipal(ctx); err != nil {
				return err
			}
		}
	}

	if err := k.generateManifests(ctx); err != nil {
		return err
	}

	if k.params.HelmGenValuesFile != "" {
		k.Log("ℹ️  Generated helm values file %q successfully written", k.params.HelmGenValuesFile)
		return nil
	}

	k.Log("ℹ️  Storing helm values file in %s/%s Secret", k.params.Namespace, k.params.HelmValuesSecretName)

	helmSecret := k8s.NewSecret(k.params.HelmValuesSecretName, k.params.Namespace,
		map[string][]byte{
			defaults.HelmValuesSecretKeyName:       []byte(k.helmYAMLValues),
			defaults.HelmChartVersionSecretKeyName: []byte(k.chartVersion.String()),
		})
	if _, err := k.client.GetSecret(ctx, k.params.Namespace, k.params.HelmValuesSecretName, metav1.GetOptions{}); err == nil {
		if _, err := k.client.UpdateSecret(ctx, k.params.Namespace, helmSecret, metav1.UpdateOptions{}); err != nil {
			k.Log("❌ Unable to store helm values file %s/%s Secret", k.params.Namespace, k.params.HelmValuesSecretName)
			return err
		}
	} else {
		if _, err := k.client.CreateSecret(ctx, k.params.Namespace, helmSecret, metav1.CreateOptions{}); err != nil {
			k.Log("❌ Unable to store helm values file %s/%s Secret", k.params.Namespace, k.params.HelmValuesSecretName)
			return err
		}
	}

	var resourceSets []k8s.ResourceSet

	switch k.flavor.Kind {
	case k8s.KindEKS:
		cm, err := k.generateConfigMap()
		if err != nil {
			return err
		}
		// Do not stop AWS DS if we are running in chaining mode
		if cm.Data["cni-chaining-mode"] != "aws-cni" {
			if _, err := k.client.GetDaemonSet(ctx, AwsNodeDaemonSetNamespace, AwsNodeDaemonSetName, metav1.GetOptions{}); err == nil {
				k.Log("🔥 Patching the %q DaemonSet to evict its pods...", AwsNodeDaemonSetName)
				patch := []byte(fmt.Sprintf(`{"spec":{"template":{"spec":{"nodeSelector":{"%s":"%s"}}}}}`, AwsNodeDaemonSetNodeSelectorKey, AwsNodeDaemonSetNodeSelectorValue))
				if _, err := k.client.PatchDaemonSet(ctx, AwsNodeDaemonSetNamespace, AwsNodeDaemonSetName, types.StrategicMergePatchType, patch, metav1.PatchOptions{}); err != nil {
					k.Log("❌ Unable to patch the %q DaemonSet", AwsNodeDaemonSetName)
					return err
				}
			}
		}
	case k8s.KindGKE:
		// TODO(aanm) automate this as well in form of helm chart
		resourceSets = append(resourceSets, k.createResourceQuotas())

	case k8s.KindAKS:
		// We only made the secret-based azure installation available in >= 1.12.0
		// Introduced in https://github.com/cilium/cilium/pull/18010
		// Additionally, secrets are only needed when using Azure IPAM
		if k.params.DatapathMode == DatapathAzure && versioncheck.MustCompile(">=1.12.0")(k.chartVersion) {
			resourceSet, err := k.createAKSSecrets(ctx)
			if err != nil {
				return err
			}
			resourceSets = append(resourceSets, *resourceSet)
		}
	}
	// TODO: decide between a pointer type and value type for returning ResourceSet.

	if err := k.installCerts(ctx); err != nil {
		return err
	}

	for _, nodeName := range k.params.NodesWithoutCilium {
		k.Log("🚀 Setting label %q on node %q to prevent Cilium from being scheduled on it...", defaults.CiliumNoScheduleLabel, nodeName)
		label := utils.EscapeJSONPatchString(defaults.CiliumNoScheduleLabel)
		labelPatch := fmt.Sprintf(`[{"op":"add","path":"/metadata/labels/%s","value":"true"}]`, label)
		if _, err := k.client.PatchNode(ctx, nodeName, types.JSONPatchType, []byte(labelPatch)); err != nil {
			return err
		}
	}

	// Start here.
	//resourceHelper := k.client.ResourceHelper()

	resourceSets = append(resourceSets, k8s.ResourceSet{
		LogMsg: "🚀 Creating Service accounts...",
		Objects: []runtime.Object{
			k.NewServiceAccount(defaults.AgentServiceAccountName),
			k.NewServiceAccount(defaults.OperatorServiceAccountName),
		},
	}, k8s.ResourceSet{
		LogMsg: "🚀 Creating Cluster roles...",
		Objects: []runtime.Object{
			k.NewClusterRole(defaults.AgentClusterRoleName),
			k.NewClusterRoleBinding(defaults.AgentClusterRoleName),
			k.NewClusterRole(defaults.OperatorClusterRoleName),
			k.NewClusterRoleBinding(defaults.OperatorClusterRoleName),
		},
	})

	if k.params.Encryption == encryptionIPsec {
		// TODO(aanm) automate this as well in form of helm chart
		resourceSet, err := k.createEncryptionSecret(ctx)
		if err != nil {
			return err
		}
		if resourceSet != nil {
			resourceSets = append(resourceSets, *resourceSet)
		}
	}

	// TODO: use generics to make a slice of Resource | ResourceSet.
	if ingressClass := k.generateIngressClass(); ingressClass != nil {
		resourceSets = append(resourceSets, k8s.ResourceSet{
			Objects: []runtime.Object{ingressClass},
		})
	}

	if secretsNamespace := k.getSecretNamespace(); len(secretsNamespace) != 0 {
		namespace := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: secretsNamespace,
			},
			TypeMeta: metav1.TypeMeta{
				Kind:       "Namespace",
				APIVersion: corev1.SchemeGroupVersion.Version,
			},
		}
		resourceSets = append(resourceSets, k8s.ResourceSet{
			Objects: []runtime.Object{namespace},
		})
	}

	var createOrUpdateResources []runtime.Object
	for _, roleName := range []string{defaults.AgentSecretsRoleName, defaults.OperatorSecretsRoleName} {
		for _, r := range k.NewRole(roleName) {
			createOrUpdateResources = append(createOrUpdateResources, r)
		}
		for _, rb := range k.NewRoleBinding(roleName) {
			createOrUpdateResources = append(createOrUpdateResources, rb)
		}
	}
	fmt.Println("create or update", createOrUpdateResources)
	resourceSets = append(resourceSets, k8s.ResourceSet{
		Objects:        createOrUpdateResources,
		UpdateIfExists: true,
	})

	configMap, err := k.generateConfigMap()
	if err != nil {
		return fmt.Errorf("cannot generate ConfigMap: %w", err)
	}
	resourceSets = append(resourceSets, k8s.ResourceSet{
		Objects: []runtime.Object{configMap},
	})

	// Create the node-init daemonset if one is required for the current kind.
	if needsNodeInit(k.flavor.Kind) {
		ds := k.generateNodeInitDaemonSet(k.flavor.Kind)
		resourceSets = append(resourceSets, k8s.ResourceSet{
			LogMsg:  fmt.Sprintf("🚀 Creating %s Node Init DaemonSet...", k.flavor.Kind.String()),
			Objects: []runtime.Object{ds},
		})
	}

	resourceSets = append(resourceSets, k8s.ResourceSet{
		LogMsg:  "🚀 Creating Agent DaemonSet...",
		Objects: []runtime.Object{k.generateAgentDaemonSet()},
	}, k8s.ResourceSet{
		LogMsg:  "🚀 Creating Operator Deployment...",
		Objects: []runtime.Object{k.generateOperatorDeployment()},
	})

	if err := k.resourceCreator.CreateOrRollback(resourceSets); err != nil {
		return err
	}

	if k.params.Wait || k.params.RestartUnmanagedPods {
		// In case unmanaged pods should be restarted we need to make sure that Cilium
		// DaemonSet is up and running to guarantee the CNI configuration and binary
		// are deployed on the node.  See https://github.com/cilium/cilium/issues/14128
		// for details.
		k.Log("⌛ Waiting for Cilium to be installed and ready...")
		collector, err := status.NewK8sStatusCollector(k.client, status.K8sStatusParameters{
			Namespace:       k.params.Namespace,
			Wait:            true,
			WaitDuration:    k.params.WaitDuration,
			WarningFreePods: []string{defaults.AgentDaemonSetName, defaults.OperatorDeploymentName},
		})
		if err != nil {
			return err
		}

		s, err := collector.Status(ctx)
		if err != nil {
			fmt.Print(s.Format())
			return err
		}
	}

	if k.params.RestartUnmanagedPods {
		if err := k.restartUnmanagedPods(ctx); err != nil {
			return err
		}
	}

	k.Log("✅ Cilium was successfully installed! Run 'cilium status' to view installation health")

	return nil
}

func (k *K8sInstaller) pushRollbackStep(step rollbackStep) {
	// Prepend the step to the steps slice so that, in case rollback is
	// performed, steps are rolled back in the reverse order
	k.rollbackSteps = append([]rollbackStep{step}, k.rollbackSteps...)
}

func (k *K8sInstaller) RollbackInstallation(ctx context.Context) {
	if !k.params.Rollback {
		k.Log("ℹ️  Rollback disabled with '--rollback=false', leaving installed resources behind")
		return
	}
	k.Log("↩️ Rolling back installation...")

	for _, r := range k.rollbackSteps {
		r(ctx)
	}
}
