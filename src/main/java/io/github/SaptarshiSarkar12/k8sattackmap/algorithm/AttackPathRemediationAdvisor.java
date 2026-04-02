package io.github.SaptarshiSarkar12.k8sattackmap.algorithm;

import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphEdge;
import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphNode;
import org.jgrapht.GraphPath;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class AttackPathRemediationAdvisor {
    public static String recommendHighestImpactRemediation(List<GraphPath<GraphNode, GraphEdge>> allPaths) {
        if (allPaths == null || allPaths.isEmpty()) {
            return "✔ No action needed. Cluster is secure.";
        }

        Map<GraphNode, Integer> nodeDestructionCount = countNodeOccurrences(allPaths);

        if (nodeDestructionCount.isEmpty()) {
            return "Attack paths exist, but no intermediate choke points found (Direct Access).";
        }

        return getRemediationAdvice(nodeDestructionCount);
    }

    private static Map<GraphNode, Integer> countNodeOccurrences(List<GraphPath<GraphNode, GraphEdge>> allPaths) {
        Map<GraphNode, Integer> nodeDestructionCount = new HashMap<>();

        for (GraphPath<GraphNode, GraphEdge> path : allPaths) {
            List<GraphNode> nodesInPath = path.getVertexList();
            for (int i = 1; i < nodesInPath.size() - 1; i++) {
                GraphNode node = nodesInPath.get(i);
                nodeDestructionCount.put(node, nodeDestructionCount.getOrDefault(node, 0) + 1);
            }
        }

        return nodeDestructionCount;
    }

    private static String getRemediationAdvice(Map<GraphNode, Integer> nodeDestructionCount) {
        Map.Entry<GraphNode, Integer> criticalNodeEntry = nodeDestructionCount.entrySet().stream()
                .max(Map.Entry.comparingByValue())
                .orElse(null);

        if (criticalNodeEntry == null) {
            return "Manual review required.";
        }

        GraphNode target = criticalNodeEntry.getKey();
        int pathsSevered = criticalNodeEntry.getValue();
        String remediationAction = getRemediationAction(target.getType());

        return String.format("🛡️ SMART REMEDIATION: %s [%s] to instantly eliminate %d attack paths.", remediationAction, target.getId(), pathsSevered);
    }

    private static String getRemediationAction(String nodeType) {
        if (nodeType == null) {
            return "Harden or remove";
        }

        String type = nodeType.toLowerCase();

        if (type.equals("pod") || type.equals("deployment")) {
            return "Patch the container vulnerabilities (CVEs) in";
        } else if (type.contains("binding") || type.contains("role")) {
            return "Revoke, restrict, or delete the RBAC permissions of";
        } else if (type.equals("secret")) {
            return "Rotate credentials and restrict RBAC access to";
        }

        return "Harden or remove";
    }
}