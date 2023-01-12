package k8s

import (
	"fmt"
	"sync"

	"k8s.io/client-go/dynamic"

	"k8s.io/apimachinery/pkg/runtime/schema"

	apierrors "k8s.io/apimachinery/pkg/api/errors"

	"k8s.io/cli-runtime/pkg/resource"

	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
)

// ResourceCreator allows creating a set of Kubernetes resources, and optionally, rolling back resources if any
// resource fails to create.
type ResourceCreator interface {
	CreateOrRollback(resourceSets []ResourceSet) error
}

type RESTClientForFunc func(config *rest.Config) (resource.RESTClient, error)

type LogFunc func(msg string)

type HelperForFunc func(restConfig *rest.Config, gvk schema.GroupVersionKind, mapper RESTMapper) (Helper, error)

//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 -generate

// RESTMapper is a subset of meta.RESTMapper.
//counterfeiter:generate . RESTMapper
type RESTMapper interface {
	RESTMapping(gk schema.GroupKind, versions ...string) (*meta.RESTMapping, error)
}

// ResourceHelper TODO
// Safe for concurrent use.
type ResourceHelper struct {
	restConfig *rest.Config
	restMapper RESTMapper
	helperFor  HelperForFunc
	//  mu guards gvkHelperMap
	mu           sync.RWMutex
	gvkHelperMap map[schema.GroupVersionKind]Helper
	namespace    string
	// TODO the format specifier arg isn't utilised.
	Log LogFunc
}

// NewResourceHelper creates a new ResourceHelper.
func NewResourceHelper(restConfig *rest.Config, restMapper RESTMapper, helperFor HelperForFunc, namespace string, logFunc LogFunc) *ResourceHelper {
	return &ResourceHelper{
		restConfig:   restConfig,
		restMapper:   restMapper,
		helperFor:    helperFor,
		gvkHelperMap: make(map[schema.GroupVersionKind]Helper),
		namespace:    namespace,
		Log:          logFunc,
	}
}

// TODO check out go docs for this module.

// Helper is a subset of *resource.Helper.
//counterfeiter:generate . Helper
type Helper interface {
	Create(namespace string, modify bool, obj runtime.Object) (runtime.Object, error)
	Replace(namespace, name string, overwrite bool, obj runtime.Object) (runtime.Object, error)
	Delete(namespace, name string) (runtime.Object, error)
	NamespaceScoped() bool
}

// A ResourceSet contains a set of Kubernetes resources to create.
type ResourceSet struct {
	// Objects is a slice of Kubernetes objects.
	Objects []runtime.Object
	// LogMsg specifies a message to log before starting creation of resources.
	LogMsg string
	// UpdateIfExists replaces the resource if it already exists.
	UpdateIfExists bool
}

// CreateOrRollback creates a set of resources specified in resourceSets.
// If a log message is specified in a ResourceSet, it logs it before attempting creation of resources
// in that ResourceSet.
// If creation of a resource fails, it rolls back all previously created resources by deleting them.
func (h *ResourceHelper) CreateOrRollback(resourceSets []ResourceSet) error {
	for i, rs := range resourceSets {
		if rs.LogMsg != "" {
			h.Log(rs.LogMsg)
		}
		for j, obj := range rs.Objects {
			helper, err := h.forResource(obj)
			if err != nil {
				return fmt.Errorf("unexpected error mapping resource %T: %w", obj, err)
			}
			if origErr := h.create(obj, helper, rs.UpdateIfExists); origErr != nil {
				if i == 0 && j == 0 {
					return origErr
				}
				// This optimises for the success case by not pushing the rollback operations here after every successful create.
				// The mapping is looked up again if an error is encountered and the create operations need to be rolled back.
				// TODO mutation?
				deleteResourceSets := resourceSets[:i+1]
				deleteResourceSets[len(deleteResourceSets)-1].Objects = rs.Objects[:j]
				if err := h.delete(deleteResourceSets); err != nil {
					return fmt.Errorf("%v: %w", err, origErr)
				}
				return origErr
			}
		}
	}
	return nil
}

// TODO: acquire namespace from metaAccessor?
// Verify that the same namespace is used everywhere.
func (h *ResourceHelper) create(obj runtime.Object, helper Helper, updateIfExists bool) error {
	name, err := meta.NewAccessor().Name(obj)
	if err != nil {
		panic(err)
		// TODO: remove.
	}
	fmt.Printf("creating: %T %s\n", obj, name)
	if _, err := helper.Create(h.namespace, true, obj); err != nil {
		if updateIfExists && apierrors.IsAlreadyExists(err) {
			metaAccessor := meta.NewAccessor()
			name, err := metaAccessor.Name(obj)
			if err != nil {
				return fmt.Errorf("unexpected error accessing name for %T: %w", obj, err)
			}
			if _, err := helper.Replace(h.namespace, name, false, obj); err != nil {
				return fmt.Errorf("error updating resource %s: %w", name, err)
			}
		}
		return err
	}
	return nil
}

func (h *ResourceHelper) delete(resourceSets []ResourceSet) error {
	metaAccessor := meta.NewAccessor()
	for i := len(resourceSets) - 1; i >= 0; i-- {
		rs := resourceSets[i]
		for j := len(rs.Objects) - 1; j >= 0; j-- {
			// TODO: check resource dependency issues. ConfigMap with Deployment.
			obj := rs.Objects[j]
			helper, err := h.forResource(obj)
			if err != nil {
				return err
			}
			name, err := metaAccessor.Name(obj)
			if err != nil {
				return fmt.Errorf("unexpected error accessing name for %T: %w", obj, err)
			}
			if _, err := helper.Delete(h.namespace, name); err != nil {
				// Preserve the existing behaviour of continuing to attempt deletion of other resources.
				var resourceName string
				if helper.NamespaceScoped() {
					resourceName = fmt.Sprintf("%s/%s", h.namespace, name)
				} else {
					resourceName = name
				}
				// TODO: verify.
				h.Log(fmt.Sprintf("Cannot delete %s %T: %v", resourceName, obj, err))
			}
		}
	}
	return nil
}

func (h *ResourceHelper) forResource(obj runtime.Object) (Helper, error) {
	// Slow path, fast path thingy.
	gvk := obj.GetObjectKind().GroupVersionKind()
	h.mu.RLock()
	helper, ok := h.gvkHelperMap[gvk]
	h.mu.RUnlock()
	if ok {
		return helper, nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()

	if helper, ok := h.gvkHelperMap[gvk]; ok {
		return helper, nil
	}

	restConfig := *h.restConfig
	gv := gvk.GroupVersion()
	restConfig.GroupVersion = &gv
	restConfig.APIPath = dynamic.LegacyAPIPathResolverFunc(gvk)
	if restConfig.NegotiatedSerializer == nil {
		restConfig.NegotiatedSerializer = scheme.Codecs.WithoutConversion()
	}
	helper, err := h.helperFor(&restConfig, gvk, h.restMapper)
	if err != nil {
		return nil, err
	}
	h.gvkHelperMap[gvk] = helper
	return helper, nil
}

// helperWrapper is a small wrapper around *resource.Helper that adds a NamespaceScoped method.
type helperWrapper struct {
	*resource.Helper
}

// NamespaceScoped returns true if the resource type is scoped to namespaces.
func (w *helperWrapper) NamespaceScoped() bool {
	return w.Helper.NamespaceScoped
}

// HelperFor creates a new Helper for the specified arguments.
func HelperFor(restConfig *rest.Config, gvk schema.GroupVersionKind, restMapper RESTMapper) (Helper, error) {
	mappedClient, err := rest.RESTClientFor(restConfig)
	if err != nil {
		return nil, fmt.Errorf("error creating RESTClient for %s: %w", gvk.String(), err)
	}
	mapping, err := restMapper.RESTMapping(gvk.GroupKind(), gvk.Version)
	if err != nil {
		return nil, fmt.Errorf("error obtaining RESTMapping for %s: %w", gvk.String(), err)
	}
	return &helperWrapper{
		Helper: resource.NewHelper(mappedClient, mapping),
	}, nil
}
