package io.github.SaptarshiSarkar12.k8sattackmap.security;

import io.github.SaptarshiSarkar12.k8sattackmap.model.EdgeType;
import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphEdge;
import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphNode;
import io.github.SaptarshiSarkar12.k8sattackmap.model.SecurityFacts;
import org.jgrapht.Graph;

import java.util.HashMap;
import java.util.Map;

import static io.github.SaptarshiSarkar12.k8sattackmap.model.EdgeType.*;
import static io.github.SaptarshiSarkar12.k8sattackmap.util.AppConstants.*;

public class EdgeRiskScorer {
    private EdgeRiskScorer() {
    }

    public static Map<GraphEdge, Double> calculateEdgeWeights(Graph<GraphNode, GraphEdge> graph) {
        Map<GraphEdge, Double> edgeWeights = new HashMap<>();

        for (GraphEdge edge : graph.edgeSet()) {
            GraphNode source = graph.getEdgeSource(edge);
            GraphNode target = graph.getEdgeTarget(edge);

            double friction = baseFriction(source, target, edge);

            // Lower friction = easier attacker movement (more dangerous path)
            edgeWeights.put(edge, Math.clamp(friction, 0.1, 25.0));
        }

        return edgeWeights;
    }

    private static double baseFriction(GraphNode source, GraphNode target, GraphEdge edge) {
        // Start from intrinsic friction already modeled in node
        double sourceIntrinsic = source.getIntrinsicFriction();
        double targetIntrinsic = target.getIntrinsicFriction();

        // Blend source/target with slight target emphasis
        double friction = (0.45 * sourceIntrinsic) + (0.55 * targetIntrinsic);

        SecurityFacts sourceFacts = source.getSecurityFacts();
        SecurityFacts targetFacts = target.getSecurityFacts();

        // If source has high execution power, reduce friction (attacker moves easier)
        if (sourceFacts != null) {
            if (sourceFacts.isPrivilegedContainer()) friction -= 2.0;
            if (sourceFacts.isAllowPrivilegeEscalation()) friction -= 1.5;
            if (sourceFacts.isHostPID() || sourceFacts.isHostNetwork() || sourceFacts.isHostIPC()) friction -= 1.5;
            if (sourceFacts.isHostPathMounted()) friction -= 1.2;
            if (sourceFacts.isNodeLevelSurface()) friction -= 2.0;
            if (sourceFacts.isServiceAccountTokenAutomount()) friction -= 1.0;
            if (sourceFacts.getAddedCapabilities() != null && !sourceFacts.getAddedCapabilities().isEmpty()) friction -= 0.8;
        }

        // If target is highly sensitive / privilege-enabling, reduce friction
        if (targetFacts != null) {
            if (targetFacts.isCredentialMaterial()) friction -= 1.8;
            if (targetFacts.isRbacWildcardVerb() || targetFacts.isRbacWildcardResource() || targetFacts.isRbacWildcardApiGroup()) friction -= 2.2;
            if (targetFacts.isRbacHasEscalate() || targetFacts.isRbacHasBind() || targetFacts.isRbacHasImpersonate()) friction -= 2.5;
        }

        // Relationship-aware adjustment
        EdgeType rel = edge.getRelationship();
        if (rel != null) {
            switch (rel) {
                case USES_SA, MOUNTS_CONFIGMAP, USES_CONFIGMAP, ENV_FROM_CONFIGMAP, MEMBER_OF -> friction -= 0.5;
                case BOUND_TO, CAN_ACCESS -> friction -= 0.8;
                case MOUNTS_SECRET, USES_SECRET, ENV_FROM_SECRET -> friction -= 2.0; // direct secret access, very easy
                case NODE_ESCAPE, HOST_PATH_ACCESS -> friction -= 3.0; // node escape is trivial once you have it
                case MANAGES -> friction -= 0.3; // workload ownership chain
                case EXEC_INTO -> friction -= 2.5; // exec is near-direct access
            }
        }
        return friction;
    }
}
