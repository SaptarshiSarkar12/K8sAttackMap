package io.github.SaptarshiSarkar12.k8sattackmap.analysis.chokepoint;

import io.github.SaptarshiSarkar12.k8sattackmap.analysis.remediation.RemediationPlan;
import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphNode;

import java.util.ArrayList;
import java.util.List;

import static io.github.SaptarshiSarkar12.k8sattackmap.util.StringUtils.safeLower;

public class ChokePointRemediationAdvisor {
    private ChokePointRemediationAdvisor() {
    }

    public static List<RemediationPlan> buildPlans(ChokePointResult chokePointResult, int topK) {
        if (chokePointResult == null
                || chokePointResult.rankedChokePoints() == null
                || chokePointResult.rankedChokePoints().isEmpty()) {
            return List.of();
        }

        List<RankedChokePoint> ranked = chokePointResult.rankedChokePoints();
        int limit = Math.clamp(topK, 1, ranked.size());
        List<RemediationPlan> plans = new ArrayList<>(limit);

        for (int i = 0; i < limit; i++) {
            RankedChokePoint rankedNode = ranked.get(i);
            GraphNode node = rankedNode.node();
            int severedPaths = rankedNode.pathsSevered();
            double weightedScore = rankedNode.weightedScore();

            NodeRef ref = parseNodeId(node.getId(), node.getType());
            plans.add(buildPlanForNode(ref, severedPaths, weightedScore));
        }

        return plans;
    }

    private static RemediationPlan buildPlanForNode(NodeRef ref, int severedPaths, double weightedScore) {
        return switch (ref.type) {
            case "serviceaccount" -> buildServiceAccountPlan(ref, severedPaths, weightedScore);
            case "rolebinding" -> buildRoleBindingPlan(ref, severedPaths, weightedScore);
            case "clusterrolebinding" -> buildClusterRoleBindingPlan(ref, severedPaths, weightedScore);
            case "deployment" -> buildDeploymentPlan(ref, severedPaths, weightedScore);
            case "pod" -> buildPodPlan(ref, severedPaths, weightedScore);
            case "secret" -> buildSecretPlan(ref, severedPaths, weightedScore);
            case "role" -> buildRolePlan(ref, severedPaths, weightedScore);
            case "clusterrole" -> buildClusterRolePlan(ref, severedPaths, weightedScore);
            case "group" -> buildGroupPlan(ref, severedPaths, weightedScore);
            default -> buildGenericPlan(ref, severedPaths, weightedScore);
        };
    }

    private static RemediationPlan buildServiceAccountPlan(NodeRef ref, int severedPaths, double weightedScore) {
        String rationale = String.format(
                "ServiceAccount [%s] is a choke point (paths=%d, weighted score=%.1f); hardening can significantly reduce attack routes.",
                ref.fullId, severedPaths, weightedScore);
        List<String> audit = List.of(
                String.format("kubectl get serviceaccount %s -n %s -o yaml", ref.name, ref.namespace),
                // Find which pods currently use this SA (breaking automount affects them)
                "# Check which pods use this ServiceAccount (if automount is enabled, these will lose token access):",
                String.format("kubectl get pods -n %s -o jsonpath='{range .items[?(@.spec.serviceAccountName==\"%s\")]}{.metadata.name}{\"\\n\"}{end}'",
                        ref.namespace, ref.name),
                String.format("kubectl get pod -n %s -o yaml | grep -A5 \"serviceAccountName: %s\"", ref.namespace, ref.name)
        );
        List<String> enforce = List.of(
                String.format("kubectl patch serviceaccount %s -n %s -p '{\"automountServiceAccountToken\": false}'",
                        ref.name, ref.namespace),
                // Restart pods that already have the token mounted so they pick up the change
                "# Restart affected pods so the change takes effect:",
                String.format("kubectl rollout restart deployment/<owner-deployment> -n %s", ref.namespace)
        );
        return new RemediationPlan(ref.fullId, rationale, audit, enforce, false);
    }

    private static RemediationPlan buildRoleBindingPlan(NodeRef ref, int severedPaths, double weightedScore) {
        String rationale = String.format(
                "RoleBinding [%s] may enable privilege traversal (paths=%d, weighted score=%.1f).", ref.fullId, severedPaths, weightedScore);
        List<String> audit = List.of(
                String.format("kubectl get rolebinding %s -n %s -o yaml", ref.name, ref.namespace),
                String.format("kubectl auth can-i --as=system:serviceaccount:%s:<sa-name> --list -n %s", ref.namespace, ref.namespace)
        );
        List<String> enforce = List.of(
                "kubectl apply -f least-privilege-rolebinding.yaml",
                String.format("# Optional (change-controlled): kubectl delete rolebinding %s -n %s", ref.name, ref.namespace)
        );
        return new RemediationPlan(ref.fullId, rationale, audit, enforce, true);
    }

    private static RemediationPlan buildClusterRoleBindingPlan(NodeRef ref, int severedPaths, double weightedScore) {
        String rationale = String.format(
                "ClusterRoleBinding [%s] grants broad access (paths=%d, weighted score=%.1f).", ref.fullId, severedPaths, weightedScore);
        List<String> audit = List.of(
                String.format("kubectl get clusterrolebinding %s -o yaml", ref.name),
                // List who is actually bound — critical for impact assessment
                "# Check which subjects are bound to this ClusterRoleBinding (these are the identities that gain the permissions):",
                String.format("kubectl get clusterrolebinding %s -o jsonpath='{.subjects}'", ref.name),
                "kubectl auth can-i --as=<subject> --list --all-namespaces"
        );
        List<String> enforce = List.of(
                "kubectl apply -f least-privilege-clusterrolebinding.yaml",
                String.format("# Optional (change-controlled): kubectl delete clusterrolebinding %s", ref.name)
        );
        return new RemediationPlan(ref.fullId, rationale, audit, enforce, true);
    }

    private static RemediationPlan buildDeploymentPlan(NodeRef ref, int severedPaths, double weightedScore) {
        String rationale = String.format(
                "Deployment [%s] appears on high-impact routes (paths=%d, weighted score=%.1f).", ref.fullId, severedPaths, weightedScore);
        List<String> audit = List.of(
                String.format("kubectl get deployment %s -n %s -o yaml", ref.name, ref.namespace),
                String.format("kubectl rollout history deployment/%s -n %s", ref.name, ref.namespace)
        );
        List<String> enforce = List.of(
                // For image vulnerability (most common reason a Deployment is a choke point):
                "# Update to a non-vulnerable image version (change <container>, <registry>, <image>, and <new-tag> accordingly). This triggers a rolling update of the pods.",
                String.format("kubectl set image deployment/%s <container>=<registry>/<image>:<new-tag> -n %s",
                        ref.name, ref.namespace),
                // For privileged container misconfiguration:
                "# Patch to remove privileged access from the container. This triggers a rolling update of the pods.",
                String.format("kubectl patch deployment %s -n %s --type=json "
                                + "-p '[{\"op\":\"replace\",\"path\":\"/spec/template/spec/containers/0/securityContext/privileged\",\"value\":false}]'",
                        ref.name, ref.namespace),
                "# After applying fixes, monitor the rollout status to ensure new pods are healthy:",
                String.format("kubectl rollout status deployment/%s -n %s", ref.name, ref.namespace)
        );
        return new RemediationPlan(ref.fullId, rationale, audit, enforce, false);
    }

    private static RemediationPlan buildPodPlan(NodeRef ref, int severedPaths, double weightedScore) {
        String rationale = String.format(
                "Pod [%s] is a lateral movement pivot (paths=%d, weighted score=%.1f).", ref.fullId, severedPaths, weightedScore);
        List<String> audit = List.of(
                String.format("kubectl get pod %s -n %s -o yaml", ref.name, ref.namespace),
                String.format("kubectl describe pod %s -n %s", ref.name, ref.namespace),
                // Find the controller managing this pod
                "# Check if this pod is managed by a controller (Deployment/DaemonSet/StatefulSet). If so, patch the controller instead of deleting the pod directly:",
                String.format("kubectl get pod %s -n %s -o jsonpath='{.metadata.ownerReferences[0].kind}/{.metadata.ownerReferences[0].name}'",
                        ref.name, ref.namespace)
        );
        List<String> enforce = List.of(
                "# Pods managed by a Deployment/DaemonSet/StatefulSet will be recreated if deleted.",
                "# Fix the owning controller instead:",
                String.format("kubectl patch deployment <owner-deployment> -n %s --type=strategic "
                                + "-p '{\"spec\":{\"template\":{\"spec\":{\"securityContext\":{\"runAsNonRoot\":true}}}}}'",
                        ref.namespace),
                "# Only delete if the pod is truly unmanaged (no ownerReferences):",
                String.format("kubectl delete pod %s -n %s", ref.name, ref.namespace)
        );
        return new RemediationPlan(ref.fullId, rationale, audit, enforce, true);
    }

    private static RemediationPlan buildSecretPlan(NodeRef ref, int severedPaths, double weightedScore) {
        String rationale = String.format(
                "Secret [%s] is on critical routes (paths=%d, weighted score=%.1f).", ref.fullId, severedPaths, weightedScore);
        List<String> audit = List.of(
                String.format("kubectl get secret %s -n %s -o yaml > %s-backup.yaml", ref.name, ref.namespace, ref.name),
                String.format("kubectl get role,rolebinding -n %s -o yaml | grep -i %s", ref.namespace, ref.name)
        );
        List<String> enforce = List.of(
                // Imperative rotation — works without a pre-existing yaml file
                "# Rotate the secret value (change <key> and <new-value> accordingly). This creates a new version of the Secret with the updated value.",
                String.format("kubectl create secret generic %s --from-literal=<key>=<new-value> --dry-run=client -o yaml -n %s | kubectl apply -f -",
                        ref.name, ref.namespace),
                String.format("kubectl rollout restart deployment/<consumer-deployment> -n %s", ref.namespace),
                String.format("# Verify old value is gone: kubectl get secret %s -n %s -o jsonpath='{.data.<key>}' | base64 -d",
                        ref.name, ref.namespace)
        );
        return new RemediationPlan(ref.fullId, rationale, audit, enforce, true);
    }

    private static RemediationPlan buildRolePlan(NodeRef ref, int severedPaths, double weightedScore) {
        String rationale = String.format(
                "Role [%s] is a high-traffic choke point (paths=%d, score=%.1f). "
                        + "It grants overly broad permissions; tightening it will sever the most attack paths.",
                ref.fullId, severedPaths, weightedScore);
        List<String> audit = List.of(
                String.format("kubectl get role %s -n %s -o yaml", ref.name, ref.namespace),
                // See exactly what this role allows
                String.format("kubectl auth can-i --list --as=system:serviceaccount:%s:<bound-sa>", ref.namespace),
                // Find all RoleBindings that reference it
                String.format("kubectl get rolebindings -n %s -o json | "
                        + "jq '.items[] | select(.roleRef.name==\"%s\") | .metadata.name'", ref.namespace, ref.name)
        );
        List<String> enforce = List.of(
                "# Create a least-privilege replacement that allows only required verbs/resources:",
                String.format("kubectl edit role %s -n %s", ref.name, ref.namespace),
                "# Or apply a pre-reviewed replacement:",
                String.format("kubectl apply -f least-privilege-role-%s.yaml", ref.name)
        );
        return new RemediationPlan(ref.fullId, rationale, audit, enforce, false);
    }

    private static RemediationPlan buildClusterRolePlan(NodeRef ref, int severedPaths, double weightedScore) {
        String rationale = String.format(
                "ClusterRole [%s] is a choke point (paths=%d, score=%.1f). "
                        + "It has cluster-wide scope; any SA bound to it can access resources in all namespaces.",
                ref.fullId, severedPaths, weightedScore);
        List<String> audit = List.of(
                String.format("kubectl get clusterrole %s -o yaml", ref.name),
                // All bindings referencing this ClusterRole
                String.format("kubectl get clusterrolebindings -o json | "
                                + "jq '.items[] | select(.roleRef.name==\"%s\") | {name:.metadata.name, subjects:.subjects}'",
                        ref.name),
                String.format("kubectl get rolebindings -A -o json | "
                                + "jq '.items[] | select(.roleRef.name==\"%s\") | {ns:.metadata.namespace, name:.metadata.name}'",
                        ref.name)
        );
        List<String> enforce = List.of(
                "# Replace with a namespace-scoped Role where possible (least privilege):",
                String.format("kubectl apply -f least-privilege-replacement-%s.yaml", ref.name),
                "# Or restrict its rules to only required verbs:",
                String.format("kubectl edit clusterrole %s", ref.name)
        );
        return new RemediationPlan(ref.fullId, rationale, audit, enforce, false);
    }

    private static RemediationPlan buildGroupPlan(NodeRef ref, int severedPaths, double weightedScore) {
        String rationale = String.format(
                "Group [%s] is bound to a ClusterRole that appears on %d attack path(s). "
                        + "Groups are not K8s API objects — remediation targets the binding(s) that reference this group.",
                ref.fullId, severedPaths);
        List<String> audit = List.of(
                "# Groups are not kubectl resources. Find the bindings that reference this group:",
                String.format("kubectl get clusterrolebindings -o json | "
                        + "jq '.items[] | select(.subjects[]?.name==\"%s\") | .metadata.name'", ref.name),
                String.format("kubectl get rolebindings -A -o json | "
                                + "jq '.items[] | select(.subjects[]?.name==\"%s\") | {ns:.metadata.namespace, name:.metadata.name}'",
                        ref.name)
        );
        List<String> enforce = List.of(
                "# Delete or restrict the ClusterRoleBinding that grants this group elevated access:",
                "kubectl delete clusterrolebinding <binding-name-from-audit-above>",
                "# Or replace the bound ClusterRole with a less privileged one:",
                "kubectl patch clusterrolebinding <binding-name> --type=json "
                        + "-p '[{\"op\":\"replace\",\"path\":\"/roleRef/name\",\"value\":\"<least-privilege-role>\"}]'"
        );
        return new RemediationPlan(ref.fullId, rationale, audit, enforce, true);
    }

    private static RemediationPlan buildGenericPlan(NodeRef ref, int severedPaths, double weightedScore) {
        String rationale = String.format("Node [%s] is a choke point (paths=%d, weighted score=%.1f).", ref.fullId, severedPaths, weightedScore);
        String getCmd = ref.namespace.isBlank()
                ? String.format("kubectl get %s %s -o yaml", resourceKind(ref.type), ref.name)
                : String.format("kubectl get %s %s -n %s -o yaml", resourceKind(ref.type), ref.name, ref.namespace);
        List<String> audit = List.of(getCmd);
        List<String> enforce = List.of("# Apply least-privilege, segmentation, and patching controls based on reviewed config.");
        return new RemediationPlan(ref.fullId, rationale, audit, enforce, false);
    }

    private static NodeRef parseNodeId(String nodeId, String fallbackType) {
        if (nodeId == null || nodeId.isBlank()) {
            return new NodeRef(safeLower(fallbackType), "default", "<unknown>", "<unknown>");
        }

        String[] parts = nodeId.split(":");
        if (parts.length >= 3) {
            String type = safeLower(parts[0]);
            String namespace = parts[1];
            StringBuilder nameBuilder = new StringBuilder(parts[2]);
            for (int i = 3; i < parts.length; i++) {
                nameBuilder.append(":").append(parts[i]);
            }
            return new NodeRef(type, namespace, nameBuilder.toString(), nodeId);
        }

        if (parts.length == 2) {
            return new NodeRef(safeLower(parts[0]), "default", parts[1], nodeId);
        }

        return new NodeRef(safeLower(fallbackType), "default", parts[0], nodeId);
    }

    private static String resourceKind(String type) {
        if (type == null || type.isBlank()) {
            return "<resource>";
        }
        return switch (type) {
            case "serviceaccount" -> "serviceaccount";
            case "rolebinding" -> "rolebinding";
            case "clusterrolebinding" -> "clusterrolebinding";
            case "deployment" -> "deployment";
            case "pod" -> "pod";
            case "secret" -> "secret";
            default -> type;
        };
    }

    private record NodeRef(String type, String namespace, String name, String fullId) {
    }
}