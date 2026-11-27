/*
Copyright 2026 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controllers

import (
	"context"
	"slices"
	"testing"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	k8errors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	sandboxv1beta1 "sigs.k8s.io/agent-sandbox/api/v1beta1"
	extensionsv1beta1 "sigs.k8s.io/agent-sandbox/extensions/api/v1beta1"
	asmetrics "sigs.k8s.io/agent-sandbox/internal/metrics"
)

// assertManagedNetworkPolicySelectsTemplateBackedPod verifies the managed
// NetworkPolicy podSelector matches labels propagated to template-backed Pods
// by the core Sandbox controller (sandbox-template-ref-hash).
func assertManagedNetworkPolicySelectsTemplateBackedPod(t *testing.T, templateName string, np *networkingv1.NetworkPolicy) {
	t.Helper()

	selector, err := metav1.LabelSelectorAsSelector(&np.Spec.PodSelector)
	if err != nil {
		t.Fatalf("pod selector: %v", err)
	}

	expectedHash := SandboxTemplateRefHash(templateName)
	podLabels := labels.Set{
		sandboxv1beta1.SandboxTemplateRefHashLabel: expectedHash,
	}
	if selector.Empty() {
		t.Errorf("managed NetworkPolicy podSelector is empty (selects all pods in namespace)")
	} else if !selector.Matches(podLabels) {
		gotHash := np.Spec.PodSelector.MatchLabels[sandboxv1beta1.SandboxTemplateRefHashLabel]
		t.Errorf("managed NetworkPolicy podSelector: %s: expected %q, got %q",
			sandboxv1beta1.SandboxTemplateRefHashLabel, expectedHash, gotHash)
	}
}

func TestSandboxTemplateReconcileNetworkPolicy(t *testing.T) {
	templateDefault := &extensionsv1beta1.SandboxTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: "test-template", Namespace: "default", UID: "template-default-uid"},
		Spec: extensionsv1beta1.SandboxTemplateSpec{SandboxBlueprint: sandboxv1beta1.SandboxBlueprint{PodTemplate: sandboxv1beta1.PodTemplate{
			Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "c1", Image: "img"}}},
		}},
		},
	}

	templateWithNP := &extensionsv1beta1.SandboxTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: "test-template-custom", Namespace: "default", UID: "template-custom-uid"},
		Spec: extensionsv1beta1.SandboxTemplateSpec{
			NetworkPolicy: &extensionsv1beta1.NetworkPolicySpec{
				Ingress: []networkingv1.NetworkPolicyIngressRule{
					{
						From: []networkingv1.NetworkPolicyPeer{
							{PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "ingress"}}},
						},
					},
				},
				Egress: []networkingv1.NetworkPolicyEgressRule{
					{
						To: []networkingv1.NetworkPolicyPeer{
							{PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "metrics"}}},
						},
					},
				},
			},
		},
	}

	templateOptOut := &extensionsv1beta1.SandboxTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: "test-template-optout", Namespace: "default", UID: "template-optout-uid"},
		Spec: extensionsv1beta1.SandboxTemplateSpec{
			NetworkPolicyManagement: extensionsv1beta1.NetworkPolicyManagementUnmanaged,
			NetworkPolicy: &extensionsv1beta1.NetworkPolicySpec{
				Egress: []networkingv1.NetworkPolicyEgressRule{{}}, // Should be ignored
			},
		},
	}

	existingNPToDelete := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-template-optout-network-policy",
			Namespace: "default",
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: extensionsv1beta1.GroupVersion.String(),
					Kind:       extensionsv1beta1.SandboxTemplateKind,
					Name:       templateOptOut.Name,
					UID:        templateOptOut.UID,
					Controller: new(bool),
				},
			},
		},
		Spec: networkingv1.NetworkPolicySpec{},
	}
	*existingNPToDelete.OwnerReferences[0].Controller = true

	labeledNPToDelete := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-template-optout-network-policy",
			Namespace: "default",
			Labels:    map[string]string{sandboxTemplateRefHash: SandboxTemplateRefHash(templateOptOut.Name)},
		},
	}

	outdatedNPToUpdate := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-template-custom-network-policy",
			Namespace: "default",
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: extensionsv1beta1.GroupVersion.String(),
					Kind:       extensionsv1beta1.SandboxTemplateKind,
					Name:       templateWithNP.Name,
					UID:        templateWithNP.UID,
					Controller: new(bool),
				},
			},
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"old-label": "outdated"}}, // Will be overwritten
		},
	}
	*outdatedNPToUpdate.OwnerReferences[0].Controller = true

	legacyOwnedNP := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-template-network-policy",
			Namespace: "default",
			OwnerReferences: []metav1.OwnerReference{
				*metav1.NewControllerRef(templateDefault, extensionsv1beta1.GroupVersion.WithKind(extensionsv1beta1.SandboxTemplateKind)),
			},
		},
		Spec: buildDefaultNetworkPolicySpec(templateDefault.Name),
	}

	leftoverNP := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-template-custom-network-policy",
			Namespace: "default",
			Labels:    map[string]string{sandboxTemplateRefHash: SandboxTemplateRefHash(templateWithNP.Name)},
		},
		Spec: buildDefaultNetworkPolicySpec(templateWithNP.Name),
	}

	testCases := []struct {
		name                  string
		templateToReconcile   *extensionsv1beta1.SandboxTemplate
		existingObjects       []client.Object
		expectNetworkPolicy   bool
		validateNetworkPolicy func(t *testing.T, np *networkingv1.NetworkPolicy)
	}{
		{
			name:                "Creates Default Secure Policy (Strict Isolation) when template has none",
			templateToReconcile: templateDefault,
			existingObjects:     []client.Object{templateDefault},
			expectNetworkPolicy: true,
			validateNetworkPolicy: func(t *testing.T, np *networkingv1.NetworkPolicy) {
				if len(np.Spec.PolicyTypes) != 2 {
					t.Errorf("Expected 2 PolicyTypes, got %d", len(np.Spec.PolicyTypes))
				}
				if len(np.Spec.Ingress) != 1 || len(np.Spec.Ingress[0].From) != 1 {
					t.Fatalf("Expected Default Ingress rule to contain exactly 1 peer source, got %d", len(np.Spec.Ingress[0].From))
				}
				peer1 := np.Spec.Ingress[0].From[0]
				if peer1.PodSelector == nil || peer1.NamespaceSelector == nil {
					t.Fatalf("Expected both PodSelector and NamespaceSelector to be non-nil")
				}
				if peer1.PodSelector.MatchLabels["app"] != "sandbox-router" ||
					peer1.NamespaceSelector.MatchLabels["kubernetes.io/metadata.name"] != "agent-sandbox-system" {
					t.Errorf("Expected first Ingress peer to target sandbox-router in agent-sandbox-system namespace")
				}
				if len(np.Spec.Egress) != 1 {
					t.Fatalf("Expected 1 Default Egress rule, got %d", len(np.Spec.Egress))
				}
				if len(np.Spec.Egress[0].To) != 2 {
					t.Fatalf("Expected 2 Egress peers (IPv4 and IPv6), got %d", len(np.Spec.Egress[0].To))
				}
				if np.Spec.Egress[0].To[0].IPBlock == nil || np.Spec.Egress[0].To[0].IPBlock.CIDR != "0.0.0.0/0" {
					t.Fatalf("Expected Default Egress IPBlock 0.0.0.0/0")
				}
				ipv6Peer := np.Spec.Egress[0].To[1]
				if ipv6Peer.IPBlock == nil || ipv6Peer.IPBlock.CIDR != "::/0" {
					t.Fatalf("Expected Default Egress IPv6 IPBlock ::/0")
				}
				hasIPv6LinkLocalExcept := slices.Contains(ipv6Peer.IPBlock.Except, "fe80::/10")
				if !hasIPv6LinkLocalExcept {
					t.Errorf("Expected IPv6 Egress Except list to contain fe80::/10, got %v", ipv6Peer.IPBlock.Except)
				}
			},
		},
		{
			name:                "Creates custom network policy when defined in template",
			templateToReconcile: templateWithNP,
			existingObjects:     []client.Object{templateWithNP},
			expectNetworkPolicy: true,
			validateNetworkPolicy: func(t *testing.T, np *networkingv1.NetworkPolicy) {
				if np.Spec.Ingress[0].From[0].PodSelector.MatchLabels["app"] != "ingress" {
					t.Errorf("unexpected custom ingress rule")
				}
			},
		},
		{
			name:                "NetworkPolicy is not created when template is Unmanaged",
			templateToReconcile: templateOptOut,
			existingObjects:     []client.Object{templateOptOut},
			expectNetworkPolicy: false,
		},
		{
			name:                "Existing NetworkPolicy is deleted when template updates to Unmanaged",
			templateToReconcile: templateOptOut,
			existingObjects:     []client.Object{templateOptOut, existingNPToDelete},
			expectNetworkPolicy: false,
		},
		{
			name:                "Labeled NetworkPolicy is deleted when template updates to Unmanaged",
			templateToReconcile: templateOptOut,
			existingObjects:     []client.Object{templateOptOut, labeledNPToDelete},
			expectNetworkPolicy: false,
		},
		{
			name:                "Existing NetworkPolicy is updated when template spec changes",
			templateToReconcile: templateWithNP,
			existingObjects:     []client.Object{templateWithNP, outdatedNPToUpdate},
			expectNetworkPolicy: true,
			validateNetworkPolicy: func(t *testing.T, np *networkingv1.NetworkPolicy) {
				if _, exists := np.Spec.PodSelector.MatchLabels["old-label"]; exists {
					t.Errorf("expected old outdated labels to be removed")
				}
				if np.Spec.Ingress[0].From[0].PodSelector.MatchLabels["app"] != "ingress" {
					t.Errorf("expected updated ingress rule with app: ingress")
				}
			},
		},
		{
			name:                "Owner reference from an older version is replaced by the label",
			templateToReconcile: templateDefault,
			existingObjects:     []client.Object{templateDefault, legacyOwnedNP},
			expectNetworkPolicy: true,
		},
		{
			name:                "Recreated template adopts its leftover labeled NetworkPolicy",
			templateToReconcile: templateWithNP,
			existingObjects:     []client.Object{templateWithNP, leftoverNP},
			expectNetworkPolicy: true,
			validateNetworkPolicy: func(t *testing.T, np *networkingv1.NetworkPolicy) {
				if np.Spec.Ingress[0].From[0].PodSelector.MatchLabels["app"] != "ingress" {
					t.Errorf("expected adopted NetworkPolicy to follow the template's ingress rule")
				}
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			scheme := newScheme(t) // Assuming newScheme is in your other test file (it's package level)
			client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(tc.existingObjects...).Build()

			reconciler := &SandboxTemplateReconciler{
				Client:   client,
				Scheme:   scheme,
				Recorder: events.NewFakeRecorder(10),
				Tracer:   asmetrics.NewNoOp(),
			}

			req := reconcile.Request{
				NamespacedName: types.NamespacedName{Name: tc.templateToReconcile.Name, Namespace: "default"},
			}

			_, err := reconciler.Reconcile(context.Background(), req)
			if err != nil {
				t.Fatalf("reconcile: (%v)", err)
			}

			var np networkingv1.NetworkPolicy
			npName := types.NamespacedName{Name: tc.templateToReconcile.Name + "-network-policy", Namespace: req.Namespace}
			err = client.Get(context.Background(), npName, &np)

			if tc.expectNetworkPolicy && err != nil {
				t.Fatalf("expected network policy to exist, got err: %v", err)
			}
			if !tc.expectNetworkPolicy && !k8errors.IsNotFound(err) {
				t.Fatalf("expected network policy to not exist (err: %v)", err)
			}

			if tc.expectNetworkPolicy && tc.validateNetworkPolicy != nil {
				tc.validateNetworkPolicy(t, &np)
			}
			if tc.expectNetworkPolicy {
				assertManagedNetworkPolicySelectsTemplateBackedPod(t, tc.templateToReconcile.Name, &np)
				if len(np.OwnerReferences) != 0 {
					t.Errorf("expected NetworkPolicy without owner references so that it outlives the template, got %v", np.OwnerReferences)
				}
				if got, want := np.Labels[sandboxTemplateRefHash], SandboxTemplateRefHash(tc.templateToReconcile.Name); got != want {
					t.Errorf("expected NetworkPolicy to have label %q=%q, got %q", sandboxTemplateRefHash, want, got)
				}
			}

			var updatedTemplate extensionsv1beta1.SandboxTemplate
			if err := client.Get(context.Background(), req.NamespacedName, &updatedTemplate); err != nil {
				t.Fatalf("get sandbox template: %v", err)
			}
			expectedTemplateHash := SandboxTemplateRefHash(tc.templateToReconcile.Name)
			if val := updatedTemplate.Labels[sandboxTemplateRefHash]; val != expectedTemplateHash {
				t.Errorf("expected SandboxTemplate to have label %q=%q, got %q", sandboxTemplateRefHash, expectedTemplateHash, val)
			}

			resourceVersion := updatedTemplate.ResourceVersion
			_, err = reconciler.Reconcile(context.Background(), req)
			if err != nil {
				t.Fatalf("second reconcile: (%v)", err)
			}
			var relabeledTemplate extensionsv1beta1.SandboxTemplate
			if err := client.Get(context.Background(), req.NamespacedName, &relabeledTemplate); err != nil {
				t.Fatalf("get sandbox template after second reconcile: %v", err)
			}
			if relabeledTemplate.ResourceVersion != resourceVersion {
				t.Errorf("expected second reconcile to leave SandboxTemplate resourceVersion unchanged, got %q, want %q", relabeledTemplate.ResourceVersion, resourceVersion)
			}
			if tc.expectNetworkPolicy {
				var reconciledNP networkingv1.NetworkPolicy
				if err := client.Get(context.Background(), npName, &reconciledNP); err != nil {
					t.Fatalf("get network policy after second reconcile: %v", err)
				}
				if reconciledNP.ResourceVersion != np.ResourceVersion {
					t.Errorf("expected second reconcile to leave NetworkPolicy resourceVersion unchanged, got %q, want %q", reconciledNP.ResourceVersion, np.ResourceVersion)
				}
			}
		})
	}
}

func TestSandboxTemplateReconcile_Vulnerability(t *testing.T) {
	scheme := newScheme(t)

	t.Run("Does not delete unowned NetworkPolicy when Unmanaged", func(t *testing.T) {
		template := &extensionsv1beta1.SandboxTemplate{
			ObjectMeta: metav1.ObjectMeta{Name: "victim", Namespace: "default"},
			Spec: extensionsv1beta1.SandboxTemplateSpec{
				NetworkPolicyManagement: extensionsv1beta1.NetworkPolicyManagementUnmanaged,
			},
		}

		// This NetworkPolicy is NOT owned by the template
		unownedNP := &networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "victim-network-policy",
				Namespace: "default",
			},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"keep": "me"}},
			},
		}

		client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(template, unownedNP).Build()
		reconciler := &SandboxTemplateReconciler{
			Client:   client,
			Scheme:   scheme,
			Recorder: events.NewFakeRecorder(10),
			Tracer:   asmetrics.NewNoOp(),
		}

		req := reconcile.Request{
			NamespacedName: types.NamespacedName{Name: "victim", Namespace: "default"},
		}

		_, err := reconciler.Reconcile(context.Background(), req)
		if err != nil {
			t.Fatalf("reconcile: (%v)", err)
		}

		// Check if unownedNP still exists
		var np networkingv1.NetworkPolicy
		err = client.Get(context.Background(), types.NamespacedName{Name: "victim-network-policy", Namespace: "default"}, &np)
		if err != nil {
			if k8errors.IsNotFound(err) {
				t.Errorf("VULNERABILITY: Unowned NetworkPolicy was deleted!")
			} else {
				t.Fatalf("failed to get network policy: %v", err)
			}
		}
	})

	t.Run("Does not update unowned NetworkPolicy", func(t *testing.T) {
		template := &extensionsv1beta1.SandboxTemplate{
			ObjectMeta: metav1.ObjectMeta{Name: "victim", Namespace: "default"},
			Spec: extensionsv1beta1.SandboxTemplateSpec{
				NetworkPolicyManagement: extensionsv1beta1.NetworkPolicyManagementManaged,
			},
		}

		// This NetworkPolicy is NOT owned by the template
		unownedNP := &networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "victim-network-policy",
				Namespace: "default",
			},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"keep": "me"}},
			},
		}

		client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(template, unownedNP).Build()
		reconciler := &SandboxTemplateReconciler{
			Client:   client,
			Scheme:   scheme,
			Recorder: events.NewFakeRecorder(10),
			Tracer:   asmetrics.NewNoOp(),
		}

		req := reconcile.Request{
			NamespacedName: types.NamespacedName{Name: "victim", Namespace: "default"},
		}

		_, err := reconciler.Reconcile(context.Background(), req)
		// We expect an error here once fixed, but currently it might succeed and overwrite
		if err != nil {
			t.Logf("Reconcile returned error (expected after fix): %v", err)
		}

		// Check if unownedNP was updated
		var np networkingv1.NetworkPolicy
		err = client.Get(context.Background(), types.NamespacedName{Name: "victim-network-policy", Namespace: "default"}, &np)
		if err != nil {
			t.Fatalf("failed to get network policy: %v", err)
		}

		if _, ok := np.Spec.PodSelector.MatchLabels["keep"]; !ok {
			t.Errorf("VULNERABILITY: Unowned NetworkPolicy was updated/overwritten!")
		}
	})

	t.Run("Does not update labeled NetworkPolicy that another object controls", func(t *testing.T) {
		template := &extensionsv1beta1.SandboxTemplate{ObjectMeta: metav1.ObjectMeta{Name: "victim", Namespace: "default"}}
		otherOwner := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "other", UID: "other-uid"}}
		otherNP := &networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: "victim-network-policy", Namespace: "default",
				Labels:          map[string]string{sandboxTemplateRefHash: SandboxTemplateRefHash(template.Name)},
				OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(otherOwner, corev1.SchemeGroupVersion.WithKind("ConfigMap"))},
			},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"keep": "me"}},
			},
		}
		r, c := newTestTemplateReconciler(t, template, otherNP)

		if _, err := r.Reconcile(context.Background(), reconcile.Request{NamespacedName: types.NamespacedName{Name: "victim", Namespace: "default"}}); err == nil {
			t.Error("expected reconcile to refuse to update a NetworkPolicy that another object controls")
		}

		var np networkingv1.NetworkPolicy
		if err := c.Get(context.Background(), types.NamespacedName{Name: "victim-network-policy", Namespace: "default"}, &np); err != nil {
			t.Fatalf("failed to get network policy: %v", err)
		}
		if _, ok := np.Spec.PodSelector.MatchLabels["keep"]; !ok {
			t.Errorf("VULNERABILITY: NetworkPolicy controlled by another object was updated/overwritten!")
		}
	})
}

func newTestTemplateReconciler(t *testing.T, objects ...client.Object) (*SandboxTemplateReconciler, client.Client) {
	t.Helper()
	scheme := newScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()
	return &SandboxTemplateReconciler{
		Client:   c,
		Scheme:   scheme,
		Recorder: events.NewFakeRecorder(10),
		Tracer:   asmetrics.NewNoOp(),
	}, c
}

func TestSandboxTemplateCleanupUnusedNetworkPolicy(t *testing.T) {
	hashLabels := map[string]string{sandboxTemplateRefHash: SandboxTemplateRefHash("demo")}
	npKey := types.NamespacedName{Name: "demo-network-policy", Namespace: "default"}
	managedNP := func() *networkingv1.NetworkPolicy {
		return &networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: npKey.Name, Namespace: npKey.Namespace, Labels: hashLabels}}
	}
	otherOwner := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "other", UID: "other-uid"}}

	testCases := []struct {
		name string
		// objects are in both the informer cache and the API server.
		objects []client.Object
		// liveObjects are on the API server but not yet in the informer cache.
		liveObjects []client.Object
		// beforeDelete changes the API server right before the controller deletes the policy.
		beforeDelete func(ctx context.Context, c client.Client) error
		wantKept     bool
	}{
		{
			name:     "kept while a Sandbox uses it",
			objects:  []client.Object{managedNP(), &sandboxv1beta1.Sandbox{ObjectMeta: metav1.ObjectMeta{Name: "sb", Namespace: "default", Labels: hashLabels}}},
			wantKept: true,
		},
		{
			name:     "kept while a Pod outlives its Sandbox",
			objects:  []client.Object{managedNP(), &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod", Namespace: "default", Labels: hashLabels}}},
			wantKept: true,
		},
		{
			name:    "deleted once nothing uses it",
			objects: []client.Object{managedNP()},
		},
		{
			name:    "deleted when only another namespace uses the hash",
			objects: []client.Object{managedNP(), &sandboxv1beta1.Sandbox{ObjectMeta: metav1.ObjectMeta{Name: "sb", Namespace: "other", Labels: hashLabels}}},
		},
		{
			name:     "policy without the managed label is left alone",
			objects:  []client.Object{&networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: npKey.Name, Namespace: npKey.Namespace}}},
			wantKept: true,
		},
		{
			name: "labeled policy that another object controls is left alone",
			objects: []client.Object{&networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{
				Name: npKey.Name, Namespace: npKey.Namespace, Labels: hashLabels,
				OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(otherOwner, corev1.SchemeGroupVersion.WithKind("ConfigMap"))},
			}}},
			wantKept: true,
		},
		{
			name:        "kept while a Sandbox missing from the cache uses it",
			objects:     []client.Object{managedNP()},
			liveObjects: []client.Object{&sandboxv1beta1.Sandbox{ObjectMeta: metav1.ObjectMeta{Name: "sb", Namespace: "default", Labels: hashLabels}}},
			wantKept:    true,
		},
		{
			name:        "kept when the template is recreated but missing from the cache",
			objects:     []client.Object{managedNP()},
			liveObjects: []client.Object{&extensionsv1beta1.SandboxTemplate{ObjectMeta: metav1.ObjectMeta{Name: "demo", Namespace: "default"}}},
			wantKept:    true,
		},
		{
			name:    "kept when the policy changes before the delete",
			objects: []client.Object{managedNP()},
			beforeDelete: func(ctx context.Context, c client.Client) error {
				np := &networkingv1.NetworkPolicy{}
				if err := c.Get(ctx, npKey, np); err != nil {
					return err
				}
				np.Annotations = map[string]string{"edited": "true"}
				return c.Update(ctx, np)
			},
			wantKept: true,
		},
		{
			name:    "no error when the policy is gone before the delete",
			objects: []client.Object{managedNP()},
			beforeDelete: func(ctx context.Context, c client.Client) error {
				return c.Delete(ctx, managedNP())
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			scheme := newScheme(t)
			c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(tc.objects...).
				WithInterceptorFuncs(interceptor.Funcs{
					Delete: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
						if tc.beforeDelete != nil {
							if err := tc.beforeDelete(ctx, c); err != nil {
								return err
							}
						}
						return c.Delete(ctx, obj, opts...)
					},
				}).Build()
			r := &SandboxTemplateReconciler{
				Client:    c,
				APIReader: fake.NewClientBuilder().WithScheme(scheme).WithObjects(slices.Concat(tc.objects, tc.liveObjects)...).Build(),
				Scheme:    scheme,
				Recorder:  events.NewFakeRecorder(10),
				Tracer:    asmetrics.NewNoOp(),
			}
			req := reconcile.Request{NamespacedName: types.NamespacedName{Name: "demo", Namespace: "default"}}
			if _, err := r.Reconcile(ctx, req); err != nil {
				t.Fatalf("reconcile: %v", err)
			}
			err := c.Get(ctx, npKey, &networkingv1.NetworkPolicy{})
			if tc.wantKept && err != nil {
				t.Fatalf("expected NetworkPolicy to be kept, got err: %v", err)
			}
			if !tc.wantKept && !k8errors.IsNotFound(err) {
				t.Fatalf("expected NetworkPolicy to be deleted, got err: %v", err)
			}
		})
	}
}

func TestSandboxTemplateNetworkPolicyWatches(t *testing.T) {
	ctx := context.Background()
	hashLabels := map[string]string{sandboxTemplateRefHash: SandboxTemplateRefHash("demo")}
	template := &extensionsv1beta1.SandboxTemplate{ObjectMeta: metav1.ObjectMeta{Name: "demo", Namespace: "default"}}
	np := &networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "demo-network-policy", Namespace: "default", Labels: hashLabels}}
	labeled := &sandboxv1beta1.Sandbox{ObjectMeta: metav1.ObjectMeta{Name: "sb", Namespace: "default", Labels: hashLabels}}
	unlabeled := &sandboxv1beta1.Sandbox{ObjectMeta: metav1.ObjectMeta{Name: "sb", Namespace: "default"}}
	want := []reconcile.Request{{NamespacedName: client.ObjectKeyFromObject(template)}}

	if got := findTemplateForNetworkPolicy(ctx, np); !slices.Equal(got, want) {
		t.Errorf("findTemplateForNetworkPolicy() = %v, want %v", got, want)
	}
	r, _ := newTestTemplateReconciler(t, np)
	if got := r.findTemplatesForConsumer(ctx, labeled); !slices.Equal(got, want) {
		t.Errorf("findTemplatesForConsumer() for a deleted template = %v, want %v", got, want)
	}
	r, _ = newTestTemplateReconciler(t, np, template)
	if got := r.findTemplatesForConsumer(ctx, labeled); len(got) != 0 {
		t.Errorf("findTemplatesForConsumer() for an existing template = %v, want none", got)
	}

	pred := templateConsumerReleasedPredicate()
	if pred.Create(event.CreateEvent{Object: labeled}) {
		t.Error("expected create events to be filtered")
	}
	if !pred.Delete(event.DeleteEvent{Object: labeled}) {
		t.Error("expected delete of a labeled Sandbox to pass")
	}
	if pred.Delete(event.DeleteEvent{Object: unlabeled}) {
		t.Error("expected delete of an unlabeled Sandbox to be filtered")
	}
	if !pred.Update(event.UpdateEvent{ObjectOld: labeled, ObjectNew: unlabeled}) {
		t.Error("expected removal of the template ref hash label to pass")
	}
	if pred.Update(event.UpdateEvent{ObjectOld: labeled, ObjectNew: labeled}) {
		t.Error("expected updates that keep the label to be filtered")
	}
}
