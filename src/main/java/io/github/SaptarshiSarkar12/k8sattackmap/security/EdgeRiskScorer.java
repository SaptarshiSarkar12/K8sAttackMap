package io.github.SaptarshiSarkar12.k8sattackmap.security;

import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphEdge;
import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphNode;
import org.jgrapht.Graph;

import java.util.HashMap;
import java.util.Map;

public class EdgeRiskScorer {
    public static Map<GraphEdge, Double> calculateEdgeWeights(Graph<GraphNode, GraphEdge> graph) {
        Map<GraphEdge, Double> edgeWeights = new HashMap<>();
        for (GraphEdge edge : graph.edgeSet()) {
            String targetNodeId = edge.getTarget().toLowerCase();
            String edgeRelationship = edge.getRelationship() != null ? edge.getRelationship().toLowerCase() : "";
            double score = getEdgeRiskScore(targetNodeId, edgeRelationship);
            double edgeFriction = 10.0 - score; // Higher risk = lower friction
            double targetNodeFriction = graph.getEdgeTarget(edge).getIntrinsicFriction();
            double finalWeight = edgeFriction + targetNodeFriction;
            edgeWeights.put(edge, finalWeight);
        }
        return edgeWeights;
    }

    private static double getEdgeRiskScore(String targetNodeId, String edgeRelationship) {
        if (edgeRelationship.contains("uses_sa")) {
            if (targetNodeId.contains(":default")) {
                return 7.5; // CIS 5.1.5: Default SA is a High Risk
            } else {
                return 4.0; // CIS 5.1.6: Custom SA is Medium Risk
            }
        } else if (edgeRelationship.contains("bound_to")) {
            if (targetNodeId.contains("cluster-admin") || targetNodeId.contains("system:masters")) {
                return 9.8; // CIS 5.1.1: Critical Risk
            } else if (targetNodeId.contains("admin") || targetNodeId.contains("edit")) {
                return 8.0; // High Risk
            } else if (targetNodeId.contains("view")) {
                return 3.0; // Low Risk (Recon)
            } else {
                return 6.0; // Standard custom role
            }
        } else if (edgeRelationship.contains("can_access")) {
            if (targetNodeId.contains("rolebinding")) {
                return 9.5; // Escaping RBAC boundaries
            } else if (targetNodeId.startsWith("secret:")) {
                return 9.0; // CIS 5.1.2: Critical Credential Theft
            } else if (targetNodeId.startsWith("pod:") || targetNodeId.contains("exec")) {
                return 8.5; // CIS 5.1.4: Container Escape Risk
            } else if (targetNodeId.contains("wildcard") || targetNodeId.contains("*")) {
                return 8.5; // CIS 5.1.3: Overly permissive
            } else if (targetNodeId.startsWith("configmap:") || targetNodeId.startsWith("service:")) {
                return 2.0; // Low Risk Discovery
            } else {
                return 4.0; // Default for other access types
            }
        }
        return 1.0; // Default baseline for non-risky edges
    }
}
