// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package install

const (
	// TODO: rename.
	AwsNodeDaemonSetName              = "aws-node"
	AwsNodeDaemonSetNamespace         = "kube-system"
	AwsNodeDaemonSetNodeSelectorKey   = "io.cilium/aws-node-enabled"
	AwsNodeDaemonSetNodeSelectorValue = "true"
)
