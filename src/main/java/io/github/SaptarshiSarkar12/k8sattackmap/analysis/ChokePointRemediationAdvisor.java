package io.github.SaptarshiSarkar12.k8sattackmap.analysis;

import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphNode;
import io.github.SaptarshiSarkar12.k8sattackmap.model.RankedChokePoint;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

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
        String type = ref.type;
        List<String> audit = new ArrayList<>();
        List<String> enforce = new ArrayList<>();
        String rationale;
        boolean destructive = false;

        switch (type) {
            case "serviceaccount" -> {
                rationale = String.format(
                        "ServiceAccount [%s] is a choke point (paths=%d, weightedScore=%.1f); hardening can significantly reduce attack routes.",
                        ref.fullId, severedPaths, weightedScore
                );
                audit.add(String.format("kubectl get serviceaccount %s -n %s -o yaml", ref.name, ref.namespace));
                audit.add(String.format("kubectl get pod -n %s -o yaml | grep -A5 \"serviceAccountName: %s\"", ref.namespace, ref.name));
                enforce.add(String.format(
                        "kubectl patch serviceaccount %s -n %s -p '{\"automountServiceAccountToken\": false}'",
                        ref.name, ref.namespace
                ));
            }
            case "rolebinding" -> {
                rationale = String.format(
                        "RoleBinding [%s] may enable privilege traversal (paths=%d, weightedScore=%.1f).",
                        ref.fullId, severedPaths, weightedScore
                );
                audit.add(String.format("kubectl get rolebinding %s -n %s -o yaml", ref.name, ref.namespace));
                audit.add(String.format("kubectl auth can-i --as=system:serviceaccount:%s:<sa-name> --list -n %s", ref.namespace, ref.namespace));
                enforce.add("kubectl apply -f least-privilege-rolebinding.yaml");
                enforce.add(String.format("# Optional (change-controlled): kubectl delete rolebinding %s -n %s", ref.name, ref.namespace));
                destructive = true;
            }
            case "clusterrolebinding" -> {
                rationale = String.format(
                        "ClusterRoleBinding [%s] grants broad access (paths=%d, weightedScore=%.1f).",
                        ref.fullId, severedPaths, weightedScore
                );
                audit.add(String.format("kubectl get clusterrolebinding %s -o yaml", ref.name));
                audit.add("kubectl auth can-i --as=<subject> --list --all-namespaces");
                enforce.add("kubectl apply -f least-privilege-clusterrolebinding.yaml");
                enforce.add(String.format("# Optional (change-controlled): kubectl delete clusterrolebinding %s", ref.name));
                destructive = true;
            }
            case "deployment" -> {
                rationale = String.format(
                        "Deployment [%s] appears on high-impact routes (paths=%d, weightedScore=%.1f).",
                        ref.fullId, severedPaths, weightedScore
                );
                audit.add(String.format("kubectl get deployment %s -n %s -o yaml", ref.name, ref.namespace));
                audit.add(String.format("kubectl rollout history deployment/%s -n %s", ref.name, ref.namespace));
                enforce.add(String.format("kubectl set image deployment/%s <container>=<registry>/<image>:<tag-or-digest> -n %s", ref.name, ref.namespace));
                enforce.add(String.format("kubectl rollout status deployment/%s -n %s", ref.name, ref.namespace));
            }
            case "pod" -> {
                rationale = String.format(
                        "Pod [%s] is a lateral movement pivot (paths=%d, weightedScore=%.1f).",
                        ref.fullId, severedPaths, weightedScore
                );
                audit.add(String.format("kubectl get pod %s -n %s -o yaml", ref.name, ref.namespace));
                audit.add(String.format("kubectl describe pod %s -n %s", ref.name, ref.namespace));
                enforce.add("# Prefer fixing controller/deployment instead of single pod replacement.");
                enforce.add(String.format("kubectl delete pod %s -n %s  # only if managed and safe to recreate", ref.name, ref.namespace));
                destructive = true;
            }
            case "secret" -> {
                rationale = String.format(
                        "Secret [%s] is on critical routes (paths=%d, weightedScore=%.1f).",
                        ref.fullId, severedPaths, weightedScore
                );
                audit.add(String.format("kubectl get secret %s -n %s -o yaml > %s-backup.yaml", ref.name, ref.namespace, ref.name));
                audit.add(String.format("kubectl get role,rolebinding -n %s -o yaml | grep -i %s", ref.namespace, ref.name));
                enforce.add("kubectl apply -f rotated-secret.yaml");
                enforce.add(String.format("kubectl rollout restart deployment/<consumer-deployment> -n %s", ref.namespace));
                enforce.add(String.format("# Optional (change-controlled): kubectl delete secret %s -n %s", ref.name, ref.namespace));
                destructive = true;
            }
            case null, default -> {
                rationale = String.format(
                        "Node [%s] is a choke point (paths=%d, weightedScore=%.1f).",
                        ref.fullId, severedPaths, weightedScore
                );
                if (ref.namespace.isBlank()) {
                    audit.add(String.format("kubectl get %s %s -o yaml", resourceKind(ref.type), ref.name));
                } else {
                    audit.add(String.format("kubectl get %s %s -n %s -o yaml", resourceKind(ref.type), ref.name, ref.namespace));
                }
                enforce.add("# Apply least-privilege, segmentation, and patching controls based on reviewed config.");
            }
        }

        return new RemediationPlan(ref.fullId, rationale, audit, enforce, destructive);
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

    private static String safeLower(String value) {
        return value == null ? "" : value.toLowerCase(Locale.ROOT);
    }

    private record NodeRef(String type, String namespace, String name, String fullId) {
    }
}