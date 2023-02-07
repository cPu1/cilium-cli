// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package install

import (
	"context"
	"crypto/rand"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium-cli/k8s"
)

func generateRandomKey() (string, error) {
	random := make([]byte, 20)
	_, err := rand.Read(random)
	if err != nil {
		return "", fmt.Errorf("unable to generate random sequence for key: %w", err)
	}

	key := "3 rfc4106(gcm(aes)) "
	for _, c := range random {
		key += fmt.Sprintf("%02x", c)
	}
	key += " 128"

	return key, nil
}

func (k *K8sInstaller) createEncryptionSecret(ctx context.Context) (*k8s.ResourceSet, error) {
	// Check if secret already exists and reuse it
	_, err := k.client.GetSecret(ctx, k.params.Namespace, defaults.EncryptionSecretName, metav1.GetOptions{})
	if err == nil {
		k.Log("🔑 Found existing encryption secret %s", defaults.EncryptionSecretName)
		return nil, nil
	}

	key, err := generateRandomKey()
	if err != nil {
		return nil, err
	}

	data := map[string][]byte{"keys": []byte(key)}
	secret := k8s.NewSecret(defaults.EncryptionSecretName, k.params.Namespace, data)
	return &k8s.ResourceSet{
		LogMsg:  fmt.Sprintf("🔑 Generated encryption secret %s", defaults.EncryptionSecretName),
		Objects: []runtime.Object{secret},
	}, nil

	// TODO note the bug in error message.
}
