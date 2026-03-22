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
        Map<GraphNode, Integer> nodeDestructionCount = new HashMap<>();

        for (GraphPath<GraphNode, GraphEdge> path : allPaths) {
            List<GraphNode> nodesInPath = path.getVertexList();
            // Start at index 1 and end at size-1 to IGNORE the Source and Target.
            // We only want to remediate the intermediate "bridge" nodes.
            for (int i = 1; i < nodesInPath.size() - 1; i++) {
                GraphNode node = nodesInPath.get(i);
                nodeDestructionCount.put(node, nodeDestructionCount.getOrDefault(node, 0) + 1);
            }
        }

        if (nodeDestructionCount.isEmpty()) {
            return "Attack paths exist, but no intermediate choke points found (Direct Access).";
        }

        // Find the intermediate node that appears in the most paths
        Map.Entry<GraphNode, Integer> criticalNodeEntry = nodeDestructionCount.entrySet().stream()
                .max(Map.Entry.comparingByValue())
                .orElse(null);

        if (criticalNodeEntry != null) {
            GraphNode target = criticalNodeEntry.getKey();
            int pathsSevered = criticalNodeEntry.getValue();
            String nodeType = target.getType() != null ? target.getType().toLowerCase() : "";

            // DYNAMIC REMEDIATION LOGIC based on what the user found
            String actionVerbs;
            if (nodeType.equals("pod") || nodeType.equals("deployment")) {
                actionVerbs = "Patch the container vulnerabilities (CVEs) in";
            } else if (nodeType.contains("binding") || nodeType.contains("role")) {
                actionVerbs = "Revoke, restrict, or delete the RBAC permissions of";
            } else if (nodeType.equals("secret")) {
                actionVerbs = "Rotate credentials and restrict RBAC access to";
            } else {
                actionVerbs = "Harden or remove";
            }

            return String.format("🛡️ SMART REMEDIATION: %s [%s] to instantly eliminate %d attack paths.", actionVerbs, target.getId(), pathsSevered);
        }
        return "Manual review required.";
    }
}
