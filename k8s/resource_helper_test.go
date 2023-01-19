package k8s_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"

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

func TestResourceHelper(t *testing.T) {
	const defaultNamespace = "test"

	var resourceHelperTestCases = []struct {
		name         string
		resourceSets []k8s.ResourceSet
		shouldError  func(runtime.Object) error

		expectedCreateCallCount  int
		expectedDeleteCallCount  int
		expectedReplaceCallCount int
		expectedErr              string
	}{
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

			expectedCreateCallCount: 4,
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

			expectedCreateCallCount: 5,
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

			shouldError: func(obj runtime.Object) error {
				if mustGetName(obj) == "fail" {
					return errors.New("failed to create *v1.ConfigMap")
				}
				return nil
			},

			expectedCreateCallCount: 4,
			expectedDeleteCallCount: 3,
			expectedErr:             "failed to create *v1.ConfigMap",
		},

		{
			name: "first call to Create fails",
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
			},
			shouldError: func(obj runtime.Object) error {
				return errors.New("failed to create *v1.Secret")
			},

			expectedErr:             "failed to create *v1.Secret",
			expectedCreateCallCount: 1,
			expectedDeleteCallCount: 0,
		},

		{
			name: "update resource if it exists",
			resourceSets: []k8s.ResourceSet{
				{
					UpdateIfExists: true,
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
			},
			shouldError: func(obj runtime.Object) error {
				if mustGetName(obj) == "r" {
					return &apierrors.StatusError{
						ErrStatus: metav1.Status{
							Reason: metav1.StatusReasonAlreadyExists,
							Status: metav1.StatusFailure,
						},
					}
				}
				return nil
			},

			expectedCreateCallCount:  3,
			expectedDeleteCallCount:  0,
			expectedReplaceCallCount: 1,
		},
	}

	noopLogger := func(_ string) {}
	for _, tc := range resourceHelperTestCases[len(resourceHelperTestCases)-1:] {
		t.Run(tc.name, func(t *testing.T) {
			helper := &k8sfakes.FakeHelper{}
			restMapper := &k8sfakes.FakeRESTMapper{}
			restMapper.RESTMappingReturns(&meta.RESTMapping{}, nil)

			var allResources []runtime.Object
			for _, rs := range tc.resourceSets {
				allResources = append(allResources, rs.Objects...)
			}
			helper.CreateStub = func(namespace string, modify bool, obj runtime.Object) (runtime.Object, error) {
				nextCreateIndex := helper.CreateCallCount() - 1
				if nextCreateIndex >= len(allResources) {
					t.Error("unexpected call to Create")
					t.FailNow()
				}
				expectedObj := allResources[nextCreateIndex]
				if obj != expectedObj {
					t.Errorf("expected Create to be called with type %T, name: %s; got type %T, name: %s", expectedObj, mustGetName(expectedObj), obj, mustGetName(obj))
					t.FailNow()
				}

				nextCreateIndex++

				if tc.shouldError != nil {
					if err := tc.shouldError(obj); err != nil {
						return nil, err
					}
				}
				return obj, nil
			}
			// Test objects are deleted in the reverse order.
			helper.DeleteStub = func(namespace, name string) (runtime.Object, error) {
				lastSuccessfulCreateIndex := tc.expectedCreateCallCount - 2
				deleteCount := helper.DeleteCallCount() - 1
				index := lastSuccessfulCreateIndex - deleteCount
				if index < 0 || index >= len(allResources) {
					t.Error("unexpected call to Delete")
					t.FailNow()
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
				return nil, nil
			}
			helperFor := func(restConfig *rest.Config, gvk schema.GroupVersionKind, mapper k8s.RESTMapper) (k8s.Helper, error) {
				return helper, nil
			}
			resourceHelper := k8s.NewResourceHelper(&rest.Config{}, restMapper, helperFor, noopLogger)
			err := resourceHelper.CreateOrRollback(tc.resourceSets)

			assertCallCount := func(actualCount, expectedCount int, method string) {
				t.Helper()
				if actualCount != expectedCount {
					t.Errorf("expected %s to be called %d times; got %d", method, expectedCount, actualCount)
				}
			}
			assertCallCount(helper.CreateCallCount(), tc.expectedCreateCallCount, "helper.Create")
			assertCallCount(helper.DeleteCallCount(), tc.expectedDeleteCallCount, "helper.Delete")
			assertCallCount(helper.ReplaceCallCount(), tc.expectedReplaceCallCount, "helper.Replace")
			if t.Failed() {
				return
			}

			if err != nil && tc.expectedErr == "" {
				t.Errorf("unexpected err: %v", err)
			} else if err == nil && tc.expectedErr != "" {
				t.Errorf("expected an error: %v", tc.expectedErr)
			} else if err != nil && tc.expectedErr != "" && !strings.Contains(err.Error(), tc.expectedErr) {
				t.Errorf("expected error to contain %q; got %q", tc.expectedErr, err)
			}
		})
	}

}

func mustGetName(obj runtime.Object) string {
	name, err := meta.NewAccessor().Name(obj)
	if err != nil {
		panic(fmt.Sprintf("unexpected error accessing name for %T: %v", obj, err))
	}
	return name
}
