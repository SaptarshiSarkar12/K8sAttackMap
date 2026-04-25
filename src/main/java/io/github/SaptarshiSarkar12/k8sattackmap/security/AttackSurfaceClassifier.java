package io.github.SaptarshiSarkar12.k8sattackmap.security;

import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphNode;
import io.github.SaptarshiSarkar12.k8sattackmap.model.SecurityFacts;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Set;

import static io.github.SaptarshiSarkar12.k8sattackmap.util.StringUtils.safeLower;

public class AttackSurfaceClassifier {
    private static final Logger log = LoggerFactory.getLogger(AttackSurfaceClassifier.class);

    public static void classifySourceAndTargetCandidates(Set<GraphNode> allNodes, Set<GraphNode> sourceNodes, Set<GraphNode> targetNodes) {
        boolean isSourceNodeProvided = !sourceNodes.isEmpty();
        boolean isTargetNodeProvided = !targetNodes.isEmpty();

        for (GraphNode node : allNodes) {
            String id = safeLower(node.getId());
            SecurityFacts facts = node.getSecurityFacts();

            if (!isSourceNodeProvided && isPotentialSourceNode(node, id, facts)) {
                boolean isSystemComponent = id.contains(":kube-system:")
                        || id.contains(":kube-public:")
                        || id.contains(":system:")
                        || id.contains(":kubeadm:");
                if (!isSystemComponent) {
                    sourceNodes.add(node);
                }
            }

            if (!isTargetNodeProvided && isPotentialTargetNode(node, id, facts)) {
                targetNodes.add(node);
            }
        }

        log.info("Identified {} potential entry points and {} potential targets.", sourceNodes.size(), targetNodes.size());
        for (GraphNode node : sourceNodes) {
            log.debug("Potential Source Node - ID: {}, Type: {}", node.getId(), node.getType());
        }
        for (GraphNode node : targetNodes) {
            log.debug("Potential Target Node - ID: {}, Type: {}", node.getId(), node.getType());
        }
    }

    private static boolean isPotentialSourceNode(GraphNode node, String id, SecurityFacts facts) {
        String type = node.getType() == null ? "" : node.getType().toLowerCase();

        // Metadata-driven (preferred)
        if (facts != null) {
            if (facts.isPrivilegedContainer()
                    || facts.isAllowPrivilegeEscalation()
                    || facts.isHostPID()
                    || facts.isHostNetwork()
                    || facts.isHostIPC()
                    || facts.isHostPathMounted()
                    || facts.isNodeLevelSurface()
                    || facts.isServiceAccountTokenAutomount()) {
                return true;
            }
        }

        // Backward-compatible fallback heuristics
        return id.startsWith("pod:")
                || id.startsWith("user:")
                || (id.startsWith("group:") && !(id.contains(":kubeadm:") || id.contains(":system:")))
                || (id.startsWith("service:") && (id.contains("loadbalancer") || id.contains("nodeport")))
                || id.startsWith("serviceaccount:")
                || id.startsWith("ingress:")
                || id.contains("system:anonymous")
                || type.equals("node");
    }

    private static boolean isPotentialTargetNode(GraphNode node, String id, SecurityFacts facts) {
        String type = node.getType() == null ? "" : node.getType().toLowerCase();

        // Metadata-driven (preferred)
        if (facts != null) {
            if (facts.isCredentialMaterial()
                    || facts.isRbacWildcardVerb()
                    || facts.isRbacWildcardResource()
                    || facts.isRbacWildcardApiGroup()
                    || facts.isRbacHasEscalate()
                    || facts.isRbacHasBind()
                    || facts.isRbacHasImpersonate()) {
                return true;
            }
        }

        // Backward-compatible fallback heuristics
        return id.startsWith("secret:")
                || id.startsWith("serviceaccount:")
                || id.startsWith("rolebinding:")
                || id.startsWith("clusterrolebinding:")
                || type.equals("clusterrole")
                || type.equals("role")
                || id.contains("cluster-admin")
                || id.contains("system:masters")
                || (id.startsWith("configmap:") && (id.contains("db") || id.contains("auth") || id.contains("key") || id.contains("prod") || id.contains("vault")))
                || (id.startsWith("persistentvolume:") && (id.contains("db") || id.contains("prod") || id.contains("vault") || id.contains("backup")))
                || (id.startsWith("pod:") && (id.contains("db") || id.contains("vault") || id.contains("prod")));
    }
}
