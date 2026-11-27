// Copyright 2026 The Kubernetes Authors.
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

package controllers

import (
	"context"
	"fmt"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	k8errors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	sandboxv1beta1 "sigs.k8s.io/agent-sandbox/api/v1beta1"
	extensionsv1beta1 "sigs.k8s.io/agent-sandbox/extensions/api/v1beta1"
	asmetrics "sigs.k8s.io/agent-sandbox/internal/metrics"
	"sigs.k8s.io/agent-sandbox/internal/utils"
)

const networkPolicyNameSuffix = "-network-policy"

// SandboxTemplateReconciler reconciles a SandboxTemplate object.
type SandboxTemplateReconciler struct {
	client.Client
	// APIReader reads directly from the API server, bypassing the informer
	// cache. Used only to confirm that the NetworkPolicy of a deleted
	// SandboxTemplate is unused before deleting it. Falls back to Client when
	// unset (e.g. in unit tests with a fake client).
	APIReader client.Reader
	Scheme    *runtime.Scheme
	Recorder  events.EventRecorder
	Tracer    asmetrics.Instrumenter
}

//+kubebuilder:rbac:groups=extensions.agents.x-k8s.io,resources=sandboxtemplates,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=extensions.agents.x-k8s.io,resources=sandboxtemplates/finalizers,verbs=get;update;patch
//+kubebuilder:rbac:groups=networking.k8s.io,resources=networkpolicies,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=agents.x-k8s.io,resources=sandboxes,verbs=get;list;watch
//+kubebuilder:rbac:groups=core,resources=pods,verbs=get;list;watch
//+kubebuilder:rbac:groups=core,resources=events,verbs=create;patch;update
//+kubebuilder:rbac:groups=events.k8s.io,resources=events,verbs=create;patch;update

func (r *SandboxTemplateReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// 1. Fetch the SandboxTemplate
	template := &extensionsv1beta1.SandboxTemplate{}
	if err := r.Get(ctx, req.NamespacedName, template); err != nil {
		if k8errors.IsNotFound(err) {
			return ctrl.Result{}, r.cleanupUnusedNetworkPolicy(ctx, req.NamespacedName)
		}
		return ctrl.Result{}, fmt.Errorf("failed to get sandbox template %q: %w", req.NamespacedName, err)
	}

	ctx, end := r.Tracer.StartSpan(ctx, template, "ReconcileSandboxTemplate", nil)
	defer end()

	if err := r.ensureTemplateRefHashLabel(ctx, template); err != nil {
		return ctrl.Result{}, err
	}

	if !template.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil
	}

	// 2. Determine Scope and Desired State
	npName := template.Name + networkPolicyNameSuffix
	npNamespace := template.Namespace

	management := template.Spec.NetworkPolicyManagement
	if management == "" {
		management = extensionsv1beta1.NetworkPolicyManagementManaged
	}

	// 3. Handle "Unmanaged" Opt-Out
	if management == extensionsv1beta1.NetworkPolicyManagementUnmanaged {
		existingNP := &networkingv1.NetworkPolicy{}
		err := r.Get(ctx, types.NamespacedName{Name: npName, Namespace: npNamespace}, existingNP)
		if err == nil {
			if !isTemplateNetworkPolicy(existingNP, template) {
				logger.Info("Skipping deletion of NetworkPolicy not owned by template", "name", npName)
				return ctrl.Result{}, nil
			}
			if err := r.Delete(ctx, existingNP); err != nil {
				logger.Error(err, "Failed to clean up unmanaged NetworkPolicy")
				return ctrl.Result{}, err
			}
			logger.Info("Deleted unmanaged NetworkPolicy", "name", existingNP.Name)
		} else if !k8errors.IsNotFound(err) {
			return ctrl.Result{}, fmt.Errorf("failed to get NetworkPolicy: %w", err)
		}
		return ctrl.Result{}, nil
	}

	// 4. Construct Desired NetworkPolicy Spec
	var desiredSpec networkingv1.NetworkPolicySpec
	if template.Spec.NetworkPolicy == nil {
		desiredSpec = buildDefaultNetworkPolicySpec(template.Name)
	} else {
		desiredSpec = networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					sandboxTemplateRefHash: SandboxTemplateRefHash(template.Name),
				},
			},
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeIngress,
				networkingv1.PolicyTypeEgress,
			},
			Ingress: template.Spec.NetworkPolicy.Ingress,
			Egress:  template.Spec.NetworkPolicy.Egress,
		}
	}

	// 5. Reconcile Existing vs Desired
	existingNP := &networkingv1.NetworkPolicy{}
	err := r.Get(ctx, types.NamespacedName{Name: npName, Namespace: npNamespace}, existingNP)

	if err == nil {
		if !isTemplateNetworkPolicy(existingNP, template) {
			return ctrl.Result{}, fmt.Errorf("refusing to update NetworkPolicy %q as it is not controlled by SandboxTemplate %q", npName, template.Name)
		}
		// Older versions set the template as the owner.
		releasedOwner := removeTemplateOwnerRefs(existingNP, template.Name)
		// Policy exists: Semantic DeepEqual check for drift
		if !releasedOwner && equality.Semantic.DeepEqual(existingNP.Spec, desiredSpec) {
			return ctrl.Result{}, nil // Perfect match, O(1) efficiency.
		}

		if existingNP.Labels == nil {
			existingNP.Labels = make(map[string]string)
		}
		existingNP.Labels[sandboxTemplateRefHash] = SandboxTemplateRefHash(template.Name)
		existingNP.Spec = desiredSpec
		if err := r.Update(ctx, existingNP); err != nil {
			logger.Error(err, "Failed to update NetworkPolicy", "name", npName)
			return ctrl.Result{}, err
		}
		logger.Info("Successfully updated shared NetworkPolicy", "name", npName)
		return ctrl.Result{}, nil
	}

	if !k8errors.IsNotFound(err) {
		return ctrl.Result{}, fmt.Errorf("failed to get NetworkPolicy: %w", err)
	}

	// 6. Create New Policy
	// The template is not the owner because Sandboxes created from it can outlive
	// it; cleanupUnusedNetworkPolicy deletes the policy once nothing uses it.
	np := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      npName,
			Namespace: npNamespace,
			Labels:    map[string]string{sandboxTemplateRefHash: SandboxTemplateRefHash(template.Name)},
		},
		Spec: desiredSpec,
	}

	if err := r.Create(ctx, np); err != nil {
		logger.Error(err, "Failed to create NetworkPolicy", "name", npName)
		return ctrl.Result{}, err
	}

	logger.Info("Successfully created shared NetworkPolicy", "name", npName)
	return ctrl.Result{}, nil
}

func (r *SandboxTemplateReconciler) ensureTemplateRefHashLabel(ctx context.Context, template *extensionsv1beta1.SandboxTemplate) error {
	if !template.DeletionTimestamp.IsZero() {
		return nil
	}

	expectedHash := SandboxTemplateRefHash(template.Name)
	if template.Labels[sandboxTemplateRefHash] == expectedHash {
		return nil
	}

	original := template.DeepCopy()
	if template.Labels == nil {
		template.Labels = make(map[string]string)
	}
	template.Labels[sandboxTemplateRefHash] = expectedHash

	if err := r.Patch(ctx, template, client.MergeFrom(original)); err != nil {
		return fmt.Errorf("failed to label sandbox template %q with template ref hash: %w", client.ObjectKeyFromObject(template), err)
	}
	return nil
}

// cleanupUnusedNetworkPolicy deletes the managed NetworkPolicy of a deleted
// SandboxTemplate once nothing uses it.
func (r *SandboxTemplateReconciler) cleanupUnusedNetworkPolicy(ctx context.Context, templateKey types.NamespacedName) error {
	logger := log.FromContext(ctx)

	np := &networkingv1.NetworkPolicy{}
	npKey := types.NamespacedName{Name: templateKey.Name + networkPolicyNameSuffix, Namespace: templateKey.Namespace}
	if err := r.Get(ctx, npKey, np); err != nil {
		if k8errors.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("failed to get NetworkPolicy: %w", err)
	}
	if metav1.GetControllerOf(np) != nil || np.Labels[sandboxTemplateRefHash] != SandboxTemplateRefHash(templateKey.Name) {
		return nil
	}

	inUse, err := templateNetworkPolicyInUse(ctx, r.Client, templateKey, &sandboxv1beta1.SandboxList{}, &corev1.PodList{})
	if err == nil && !inUse {
		// The cache can miss a Sandbox that SandboxClaim or SandboxWarmPool just
		// created from a cached copy of the template. Pods need no live check: a
		// new Pod always has a Sandbox, and a terminating Pod is already cached.
		inUse, err = templateNetworkPolicyInUse(ctx, r.authoritativeReader(), templateKey, &sandboxv1beta1.SandboxList{})
	}
	if err != nil {
		return err
	}
	if inUse {
		logger.V(4).Info("Keeping NetworkPolicy of deleted SandboxTemplate while it is in use", "name", npKey.Name)
		return nil
	}

	preconditions := client.Preconditions{UID: &np.UID, ResourceVersion: &np.ResourceVersion}
	if err := r.Delete(ctx, np, preconditions); err != nil {
		if k8errors.IsNotFound(err) {
			return nil
		}
		// The NetworkPolicy watch requeues the template after the change.
		if k8errors.IsConflict(err) {
			logger.V(4).Info("Skipping delete of NetworkPolicy changed since it was read", "name", npKey.Name)
			return nil
		}
		return fmt.Errorf("failed to delete NetworkPolicy %q: %w", npKey.Name, err)
	}
	logger.Info("Deleted NetworkPolicy of deleted SandboxTemplate", "name", npKey.Name)
	return nil
}

// templateNetworkPolicyInUse reports whether the SandboxTemplate exists or any
// object of the given list types in its namespace carries its ref hash label.
// A Sandbox counts even without a Pod because a suspended Sandbox needs the
// policy when it resumes. A Pod counts because it keeps running through its
// termination grace period after its Sandbox is gone.
func templateNetworkPolicyInUse(ctx context.Context, reader client.Reader, templateKey types.NamespacedName, consumers ...client.ObjectList) (bool, error) {
	err := reader.Get(ctx, templateKey, &extensionsv1beta1.SandboxTemplate{})
	if err == nil {
		return true, nil
	}
	if !k8errors.IsNotFound(err) {
		return false, fmt.Errorf("failed to get sandbox template %q: %w", templateKey, err)
	}

	for _, list := range consumers {
		if err := reader.List(ctx, list,
			client.InNamespace(templateKey.Namespace),
			client.MatchingLabels{sandboxTemplateRefHash: SandboxTemplateRefHash(templateKey.Name)},
			client.Limit(1),
		); err != nil {
			return false, fmt.Errorf("failed to list %T for template %q: %w", list, templateKey.Name, err)
		}
		if meta.LenList(list) > 0 {
			return true, nil
		}
	}
	return false, nil
}

func (r *SandboxTemplateReconciler) authoritativeReader() client.Reader {
	if r.APIReader != nil {
		return r.APIReader
	}
	return r.Client
}

// isTemplateNetworkPolicy reports whether np is the managed NetworkPolicy of
// template. Older controller versions mark it with a controller reference
// instead of the label, and a policy that another object controls is never
// managed.
func isTemplateNetworkPolicy(np *networkingv1.NetworkPolicy, template *extensionsv1beta1.SandboxTemplate) bool {
	if metav1.GetControllerOf(np) != nil {
		return metav1.IsControlledBy(np, template)
	}
	return np.Labels[sandboxTemplateRefHash] == SandboxTemplateRefHash(template.Name)
}

// removeTemplateOwnerRefs removes the owner references to the named
// SandboxTemplate from np and reports whether it removed any.
func removeTemplateOwnerRefs(np *networkingv1.NetworkPolicy, templateName string) bool {
	refs := slices.DeleteFunc(slices.Clone(np.OwnerReferences), func(ref metav1.OwnerReference) bool {
		return ref.Name == templateName &&
			utils.MatchesGroupKind(&ref, extensionsv1beta1.GroupVersion.Group, extensionsv1beta1.SandboxTemplateKind)
	})
	if len(refs) == len(np.OwnerReferences) {
		return false
	}
	np.OwnerReferences = refs
	return true
}

// templateRequestForNetworkPolicy maps a managed NetworkPolicy to the
// SandboxTemplate it was created for, which may no longer exist.
func templateRequestForNetworkPolicy(np client.Object) (reconcile.Request, bool) {
	name, ok := strings.CutSuffix(np.GetName(), networkPolicyNameSuffix)
	if !ok || np.GetLabels()[sandboxTemplateRefHash] != SandboxTemplateRefHash(name) {
		return reconcile.Request{}, false
	}
	return reconcile.Request{NamespacedName: types.NamespacedName{Name: name, Namespace: np.GetNamespace()}}, true
}

func findTemplateForNetworkPolicy(_ context.Context, obj client.Object) []reconcile.Request {
	if req, ok := templateRequestForNetworkPolicy(obj); ok {
		return []reconcile.Request{req}
	}
	return nil
}

// findTemplatesForConsumer returns the deleted SandboxTemplates whose managed
// NetworkPolicy selects obj, so that the policy is cleaned up when its last
// Sandbox or Pod goes away. It skips templates that still exist because their
// delete event triggers the cleanup.
func (r *SandboxTemplateReconciler) findTemplatesForConsumer(ctx context.Context, obj client.Object) []reconcile.Request {
	hash := obj.GetLabels()[sandboxTemplateRefHash]
	if hash == "" {
		return nil
	}

	policies := &networkingv1.NetworkPolicyList{}
	if err := r.List(ctx, policies, client.InNamespace(obj.GetNamespace()), client.MatchingLabels{sandboxTemplateRefHash: hash}); err != nil {
		log.FromContext(ctx).Error(err, "Failed to list NetworkPolicies for template ref hash", "hash", hash)
		return nil
	}

	var requests []reconcile.Request
	for i := range policies.Items {
		req, ok := templateRequestForNetworkPolicy(&policies.Items[i])
		if !ok {
			continue
		}
		if err := r.Get(ctx, req.NamespacedName, &extensionsv1beta1.SandboxTemplate{}); err == nil {
			continue
		}
		requests = append(requests, req)
	}
	return requests
}

// templateConsumerReleasedPredicate passes only the events in which a Sandbox
// or Pod stops carrying a template ref hash, because only those can leave the
// NetworkPolicy of a deleted template unused.
func templateConsumerReleasedPredicate() predicate.Funcs {
	return predicate.Funcs{
		CreateFunc: func(event.CreateEvent) bool { return false },
		UpdateFunc: func(e event.UpdateEvent) bool {
			return e.ObjectOld.GetLabels()[sandboxTemplateRefHash] != e.ObjectNew.GetLabels()[sandboxTemplateRefHash]
		},
		DeleteFunc:  func(e event.DeleteEvent) bool { return e.Object.GetLabels()[sandboxTemplateRefHash] != "" },
		GenericFunc: func(event.GenericEvent) bool { return false },
	}
}

// buildDefaultNetworkPolicySpec generates the "Secure by Default" network policy.
func buildDefaultNetworkPolicySpec(templateName string) networkingv1.NetworkPolicySpec {
	peers := []networkingv1.NetworkPolicyPeer{
		{
			NamespaceSelector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"kubernetes.io/metadata.name": "agent-sandbox-system",
				},
			},
			PodSelector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app": "sandbox-router",
				},
			},
		},
	}

	return networkingv1.NetworkPolicySpec{
		PodSelector: metav1.LabelSelector{
			MatchLabels: map[string]string{
				sandboxTemplateRefHash: SandboxTemplateRefHash(templateName),
			},
		},
		PolicyTypes: []networkingv1.PolicyType{
			networkingv1.PolicyTypeIngress,
			networkingv1.PolicyTypeEgress,
		},
		// 1. INGRESS: Allow traffic only from the Sandbox Router
		Ingress: []networkingv1.NetworkPolicyIngressRule{
			{
				From: peers,
			},
		},
		// 2. EGRESS: Secure Default Configuration
		Egress: []networkingv1.NetworkPolicyEgressRule{
			// Public Internet Access (Strict Isolation)
			// This rule allows all ports to PUBLIC IPs, but explicitly blocks private LAN ranges.
			// NOTE: This intentionally blocks internal cluster DNS (CoreDNS) by default to prevent
			// agents from probing for service discovery and leaking internal service names.
			{
				To: []networkingv1.NetworkPolicyPeer{
					{
						IPBlock: &networkingv1.IPBlock{
							CIDR: "0.0.0.0/0",
							Except: []string{
								"10.0.0.0/8",     // Block Private Class A (Cluster/VPC Network)
								"172.16.0.0/12",  // Block Private Class B
								"192.168.0.0/16", // Block Private Class C
								"169.254.0.0/16", // Block Link-Local (Metadata Server)
							},
						},
					},
					{
						IPBlock: &networkingv1.IPBlock{
							CIDR: "::/0", // IPv6 Catch-all
							Except: []string{
								"fc00::/7",  // Block IPv6 Unique Local Addresses (Internal)
								"fe80::/10", // Block IPv6 Link-Local
							},
						},
					},
				},
			},
		},
	}
}

// SetupWithManager sets up the controller with the Manager.
func (r *SandboxTemplateReconciler) SetupWithManager(mgr ctrl.Manager, concurrentWorkers int) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&extensionsv1beta1.SandboxTemplate{}).
		Watches(&networkingv1.NetworkPolicy{}, handler.EnqueueRequestsFromMapFunc(findTemplateForNetworkPolicy)).
		Watches(&sandboxv1beta1.Sandbox{}, handler.EnqueueRequestsFromMapFunc(r.findTemplatesForConsumer),
			builder.WithPredicates(templateConsumerReleasedPredicate())).
		Watches(&corev1.Pod{}, handler.EnqueueRequestsFromMapFunc(r.findTemplatesForConsumer),
			builder.WithPredicates(templateConsumerReleasedPredicate())).
		WithOptions(controller.Options{MaxConcurrentReconciles: concurrentWorkers}).
		Complete(r)
}
