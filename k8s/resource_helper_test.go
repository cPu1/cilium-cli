package k8s_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/cilium/cilium-cli/k8s/k8sfakes"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime/schema"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"

	"github.com/cilium/cilium-cli/k8s"
)

type resourceHelperCase struct {
	name         string
	resourceSets []k8s.ResourceSet
	shouldFail   func(runtime.Object) bool

	expectedCreateCallsCount int
	expectedDeleteCallsCount int
	expectedErr              string
}

const defaultNamespace = "test"

var resourceHelperCases = []resourceHelperCase{
	{
		name: "single ResourceSet",
		resourceSets: []k8s.ResourceSet{
			{
				Objects: []runtime.Object{
					&corev1.Secret{
						TypeMeta: metav1.TypeMeta{
							Kind:       "Secret",
							APIVersion: "v1",
						},
						ObjectMeta: metav1.ObjectMeta{
							Name:      "s",
							Namespace: defaultNamespace,
						},
					},
					&rbacv1.Role{
						TypeMeta: metav1.TypeMeta{
							Kind:       "Role",
							APIVersion: rbacv1.SchemeGroupVersion.String(),
						},
						ObjectMeta: metav1.ObjectMeta{
							Name:      "r",
							Namespace: defaultNamespace,
						},
					},
					&corev1.ConfigMap{
						TypeMeta: metav1.TypeMeta{
							Kind:       "ConfigMap",
							APIVersion: corev1.SchemeGroupVersion.String(),
						},
						ObjectMeta: metav1.ObjectMeta{
							Name:      "cm",
							Namespace: defaultNamespace,
						},
					},
					&corev1.ServiceAccount{
						TypeMeta: metav1.TypeMeta{
							Kind:       "ServiceAccount",
							APIVersion: corev1.SchemeGroupVersion.String(),
						},
						ObjectMeta: metav1.ObjectMeta{
							Name:      "sa",
							Namespace: defaultNamespace,
						},
					},
				},
			},
		},

		expectedCreateCallsCount: 4,
	},

	{
		name: "multiple ResourceSets",
		resourceSets: []k8s.ResourceSet{
			{
				Objects: []runtime.Object{
					&corev1.Secret{
						TypeMeta: metav1.TypeMeta{
							Kind:       "Secret",
							APIVersion: "v1",
						},
						ObjectMeta: metav1.ObjectMeta{
							Name:      "c",
							Namespace: defaultNamespace,
						},
					},
					&rbacv1.Role{
						TypeMeta: metav1.TypeMeta{
							Kind:       "Role",
							APIVersion: rbacv1.SchemeGroupVersion.String(),
						},
						ObjectMeta: metav1.ObjectMeta{
							Name:      "r",
							Namespace: defaultNamespace,
						},
					},
					&rbacv1.RoleBinding{
						TypeMeta: metav1.TypeMeta{
							Kind:       "RoleBinding",
							APIVersion: rbacv1.SchemeGroupVersion.String(),
						},
						ObjectMeta: metav1.ObjectMeta{
							Name:      "rb",
							Namespace: defaultNamespace,
						},
					},
				},
			},
			{
				Objects: []runtime.Object{
					&corev1.ConfigMap{
						TypeMeta: metav1.TypeMeta{
							Kind:       "ConfigMap",
							APIVersion: corev1.SchemeGroupVersion.String(),
						},
						ObjectMeta: metav1.ObjectMeta{
							Name:      "cm",
							Namespace: defaultNamespace,
						},
					},
					&corev1.ServiceAccount{
						TypeMeta: metav1.TypeMeta{
							Kind:       "ServiceAccount",
							APIVersion: corev1.SchemeGroupVersion.String(),
						},
						ObjectMeta: metav1.ObjectMeta{
							Name:      "sa",
							Namespace: defaultNamespace,
						},
					},
				},
			},
		},

		expectedCreateCallsCount: 5,
	},

	{
		name: "roll back resources",
		resourceSets: []k8s.ResourceSet{
			{
				Objects: []runtime.Object{
					&corev1.Secret{
						TypeMeta: metav1.TypeMeta{
							Kind:       "Secret",
							APIVersion: "v1",
						},
						ObjectMeta: metav1.ObjectMeta{
							Name:      "s",
							Namespace: defaultNamespace,
						},
					},
					&rbacv1.Role{
						TypeMeta: metav1.TypeMeta{
							Kind:       "Role",
							APIVersion: rbacv1.SchemeGroupVersion.String(),
						},
						ObjectMeta: metav1.ObjectMeta{
							Name:      "r",
							Namespace: defaultNamespace,
						},
					},
					&rbacv1.RoleBinding{
						TypeMeta: metav1.TypeMeta{
							Kind:       "RoleBinding",
							APIVersion: rbacv1.SchemeGroupVersion.String(),
						},
						ObjectMeta: metav1.ObjectMeta{
							Name:      "rb",
							Namespace: defaultNamespace,
						},
					},
				},
			},
			{
				Objects: []runtime.Object{
					&corev1.ConfigMap{
						TypeMeta: metav1.TypeMeta{
							Kind:       "ConfigMap",
							APIVersion: corev1.SchemeGroupVersion.String(),
						},
						ObjectMeta: metav1.ObjectMeta{
							Name:      "fail",
							Namespace: defaultNamespace,
						},
					},
					&corev1.ServiceAccount{
						TypeMeta: metav1.TypeMeta{
							Kind:       "sa",
							APIVersion: corev1.SchemeGroupVersion.String(),
						},
						ObjectMeta: metav1.ObjectMeta{
							Name:      "cilium",
							Namespace: defaultNamespace,
						},
					},
				},
			},
		},

		shouldFail: func(object runtime.Object) bool {
			return mustGetName(object) == "fail"
		},

		expectedCreateCallsCount: 4,
		expectedDeleteCallsCount: 3,
		expectedErr:              "failed to create *v1.ConfigMap",
	},
}

func TestResourceHelper(t *testing.T) {
	noopLogger := func(_ string) {}
	for _, c := range resourceHelperCases {
		t.Run(c.name, func(t *testing.T) {
			helper := &k8sfakes.FakeHelper{}
			restMapper := &k8sfakes.FakeRESTMapper{}
			restMapper.RESTMappingReturns(&meta.RESTMapping{}, nil)

			var allResources []runtime.Object
			for _, rs := range c.resourceSets {
				allResources = append(allResources, rs.Objects...)
			}
			helper.CreateStub = func(namespace string, modify bool, object runtime.Object) (runtime.Object, error) {
				nextCreateIndex := helper.CreateCallCount() - 1
				if nextCreateIndex >= len(allResources) {
					t.Error("unexpected call to Create")
					t.FailNow()
				}
				expectedObj := allResources[nextCreateIndex]
				if object != expectedObj {
					t.Errorf("expected Create to be called with type %T, name: %s; got type %T, name: %s", expectedObj, mustGetName(expectedObj), object, mustGetName(object))
					t.FailNow()
				}

				nextCreateIndex++

				if c.shouldFail != nil && c.shouldFail(object) {
					return nil, fmt.Errorf("failed to create %T", object)
				}
				return object, nil
			}
			deleteCount := 0
			// Test objects are deleted in the reverse order.
			helper.DeleteStub = func(namespace, name string) (runtime.Object, error) {
				lastSuccessfulCreateIndex := helper.CreateCallCount() - 2
				index := lastSuccessfulCreateIndex - deleteCount
				if index < 0 || index >= len(allResources) {
					return nil, errors.New("unexpected call to Delete")
				}
				expectedObj := allResources[index]
				expectedNamespace, err := meta.NewAccessor().Namespace(expectedObj)
				if err != nil {
					t.Errorf("unexpected error accessing namespace for %T: %v", expectedObj, err)
					t.FailNow()
				}
				expectedName := mustGetName(expectedObj)
				if name != expectedName || namespace != expectedNamespace {
					t.Errorf("expected Delete to be called with %s/%s; got %s/%s", expectedName, expectedNamespace, name, namespace)
					t.FailNow()
				}
				deleteCount++
				return nil, nil
			}
			helperFor := func(restConfig *rest.Config, gvk schema.GroupVersionKind, mapper k8s.RESTMapper) (k8s.Helper, error) {
				return helper, nil
			}
			resourceHelper := k8s.NewResourceHelper(&rest.Config{}, restMapper, helperFor, "test", noopLogger)
			err := resourceHelper.CreateOrRollback(c.resourceSets)

			if helper.CreateCallCount() != c.expectedCreateCallsCount {
				t.Errorf("expected helper.Create to be called %d times; got %d", c.expectedCreateCallsCount, helper.CreateCallCount())
				return
			}

			if helper.DeleteCallCount() != c.expectedDeleteCallsCount {
				t.Errorf("expected helper.Delete to be called %d times; got %d", c.expectedDeleteCallsCount, helper.DeleteCallCount())
				return
			}
			if err != nil && c.expectedErr == "" {
				t.Errorf("unexpected err: %v", err)
			} else if err == nil && c.expectedErr != "" {
				t.Errorf("expected an error: %v", c.expectedErr)
			} else if err != nil && c.expectedErr != "" && !strings.Contains(err.Error(), c.expectedErr) {
				t.Errorf("expected error to contain %s; got %s", c.expectedErr, err)
			}
		})
	}

}

func mustGetName(object runtime.Object) string {
	name, err := meta.NewAccessor().Name(object)
	if err != nil {
		panic(fmt.Sprintf("unexpected error accessing name for %T: %v", object, err))
	}
	return name
}
