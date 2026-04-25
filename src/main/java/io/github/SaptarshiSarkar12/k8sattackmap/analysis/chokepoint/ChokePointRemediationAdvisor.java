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
            case "serviceaccount"    -> buildServiceAccountPlan(ref, severedPaths, weightedScore);
            case "rolebinding"       -> buildRoleBindingPlan(ref, severedPaths, weightedScore);
            case "clusterrolebinding"-> buildClusterRoleBindingPlan(ref, severedPaths, weightedScore);
            case "deployment"        -> buildDeploymentPlan(ref, severedPaths, weightedScore);
            case "pod"               -> buildPodPlan(ref, severedPaths, weightedScore);
            case "secret"            -> buildSecretPlan(ref, severedPaths, weightedScore);
            default                  -> buildGenericPlan(ref, severedPaths, weightedScore);
        };
    }

    private static RemediationPlan buildServiceAccountPlan(NodeRef ref, int severedPaths, double weightedScore) {
        String rationale = String.format(
                "ServiceAccount [%s] is a choke point (paths=%d, weightedScore=%.1f); hardening can significantly reduce attack routes.",
                ref.fullId, severedPaths, weightedScore);
        List<String> audit = List.of(
                String.format("kubectl get serviceaccount %s -n %s -o yaml", ref.name, ref.namespace),
                String.format("kubectl get pod -n %s -o yaml | grep -A5 \"serviceAccountName: %s\"", ref.namespace, ref.name)
        );
        List<String> enforce = List.of(
                String.format("kubectl patch serviceaccount %s -n %s -p '{\"automountServiceAccountToken\": false}'", ref.name, ref.namespace)
        );
        return new RemediationPlan(ref.fullId, rationale, audit, enforce, false);
    }

    private static RemediationPlan buildRoleBindingPlan(NodeRef ref, int severedPaths, double weightedScore) {
        String rationale = String.format(
                "RoleBinding [%s] may enable privilege traversal (paths=%d, weightedScore=%.1f).", ref.fullId, severedPaths, weightedScore);
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
                "ClusterRoleBinding [%s] grants broad access (paths=%d, weightedScore=%.1f).", ref.fullId, severedPaths, weightedScore);
        List<String> audit = List.of(
                String.format("kubectl get clusterrolebinding %s -o yaml", ref.name),
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
                "Deployment [%s] appears on high-impact routes (paths=%d, weightedScore=%.1f).", ref.fullId, severedPaths, weightedScore);
        List<String> audit = List.of(
                String.format("kubectl get deployment %s -n %s -o yaml", ref.name, ref.namespace),
                String.format("kubectl rollout history deployment/%s -n %s", ref.name, ref.namespace)
        );
        List<String> enforce = List.of(
                String.format("kubectl set image deployment/%s <container>=<registry>/<image>:<tag-or-digest> -n %s", ref.name, ref.namespace),
                String.format("kubectl rollout status deployment/%s -n %s", ref.name, ref.namespace)
        );
        return new RemediationPlan(ref.fullId, rationale, audit, enforce, false);
    }

    private static RemediationPlan buildPodPlan(NodeRef ref, int severedPaths, double weightedScore) {
        String rationale = String.format(
                "Pod [%s] is a lateral movement pivot (paths=%d, weightedScore=%.1f).", ref.fullId, severedPaths, weightedScore);
        List<String> audit = List.of(
                String.format("kubectl get pod %s -n %s -o yaml", ref.name, ref.namespace),
                String.format("kubectl describe pod %s -n %s", ref.name, ref.namespace)
        );
        List<String> enforce = List.of(
                "# Prefer fixing controller/deployment instead of single pod replacement.",
                String.format("kubectl delete pod %s -n %s  # only if managed and safe to recreate", ref.name, ref.namespace)
        );
        return new RemediationPlan(ref.fullId, rationale, audit, enforce, true);
    }

    private static RemediationPlan buildSecretPlan(NodeRef ref, int severedPaths, double weightedScore) {
        String rationale = String.format(
                "Secret [%s] is on critical routes (paths=%d, weightedScore=%.1f).", ref.fullId, severedPaths, weightedScore);
        List<String> audit = List.of(
                String.format("kubectl get secret %s -n %s -o yaml > %s-backup.yaml", ref.name, ref.namespace, ref.name),
                String.format("kubectl get role,rolebinding -n %s -o yaml | grep -i %s", ref.namespace, ref.name)
        );
        List<String> enforce = List.of(
                "kubectl apply -f rotated-secret.yaml",
                String.format("kubectl rollout restart deployment/<consumer-deployment> -n %s", ref.namespace),
                String.format("# Optional (change-controlled): kubectl delete secret %s -n %s", ref.name, ref.namespace)
        );
        return new RemediationPlan(ref.fullId, rationale, audit, enforce, true);
    }

    private static RemediationPlan buildGenericPlan(NodeRef ref, int severedPaths, double weightedScore) {
        String rationale = String.format(
                "Node [%s] is a choke point (paths=%d, weightedScore=%.1f).", ref.fullId, severedPaths, weightedScore);
        String getCmd = ref.namespace.isBlank()
                ? String.format("kubectl get %s %s -o yaml", resourceKind(ref.type), ref.name)
                : String.format("kubectl get %s %s -n %s -o yaml", resourceKind(ref.type), ref.name, ref.namespace);
        List<String> audit   = List.of(getCmd);
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