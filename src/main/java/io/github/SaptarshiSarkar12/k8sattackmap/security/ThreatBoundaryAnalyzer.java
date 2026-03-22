package io.github.SaptarshiSarkar12.k8sattackmap.security;

import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Set;

public class ThreatBoundaryAnalyzer {
    private static final Logger log = LoggerFactory.getLogger(ThreatBoundaryAnalyzer.class);

    public static void analyze(Set<GraphNode> allNodes, List<GraphNode> sourceNodes, List<GraphNode> targetNodes) {
        boolean isSourceNodeProvided = !sourceNodes.isEmpty();
        boolean isTargetNodeProvided = !targetNodes.isEmpty();
        for (GraphNode node : allNodes) {
            String id = node.getId().toLowerCase();
            if (!isSourceNodeProvided && isPotentialSourceNode(id)) {
                boolean isSystemComponent = id.contains(":kube-system:") || id.contains(":kube-public:") || id.contains(":system:") || id.contains(":kubeadm:");
                if (!isSystemComponent) {
                    sourceNodes.add(node);
                }
            }
            if (!isTargetNodeProvided && isPotentialTargetNode(id)) {
                targetNodes.add(node);
            }
        }
        log.info("Identified {} potential entry points and {} potential crown jewels.", sourceNodes.size(), targetNodes.size());
        for (GraphNode node : sourceNodes) {
            log.debug("Potential Source Node - ID: {}, Type: {}", node.getId(), node.getType());
        }
        for (GraphNode node : targetNodes) {
            log.debug("Potential Target Node - ID: {}, Type: {}", node.getId(), node.getType());
        }
    }

    private static boolean isPotentialSourceNode(String id) {
        return id.startsWith("pod:")
                || id.startsWith("user:")
                || (id.startsWith("group:") && !(id.contains(":kubeadm:") || id.contains(":system:")))
                || id.startsWith("service:") && (id.contains("loadbalancer") || id.contains("nodeport"))
                || id.startsWith("serviceaccount:")
                || id.startsWith("ingress:")
                || id.contains("system:anonymous");
    }

    private static boolean isPotentialTargetNode(String id) {
        return id.startsWith("secret:")
                || id.startsWith("serviceaccount:")
                || id.startsWith("rolebinding:")
                || id.startsWith("clusterrolebinding:")
                || (id.startsWith("configmap:") && (id.contains("db") || id.contains("auth") || id.contains("key") || id.contains("prod") || id.contains("vault")))
                || (id.startsWith("persistentvolume:") && (id.contains("db") || id.contains("prod") || id.contains("vault") || id.contains("backup")))
                || (id.startsWith("pod:") && (id.contains("db") || id.contains("vault") || id.contains("prod")))
                || id.contains("cluster-admin")
                || id.contains("system:masters");
    }
}
