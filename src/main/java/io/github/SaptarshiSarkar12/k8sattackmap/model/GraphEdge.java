package io.github.SaptarshiSarkar12.k8sattackmap.model;

import lombok.Getter;
import lombok.Setter;
import org.jgrapht.graph.DefaultWeightedEdge;

/**
 * Represents a directed edge in the Kubernetes attack graph.
 * <p>
 * Edges capture relationships between resources (e.g., Pod uses ServiceAccount, Role grants permissions).
 * The relationship type is defined by {@link EdgeType}. Edge weight (friction) is computed by
 * {@link io.github.SaptarshiSarkar12.k8sattackmap.security.EdgeRiskScorer} based on source/target risk.
 * <p>
 * Lower weight = easier attacker movement = more dangerous edge. Algorithms like Dijkstra find
 * the lowest-friction path (most dangerous attack route).
 */
@Setter
@Getter
public class GraphEdge extends DefaultWeightedEdge {
    private String source;
    private String target;
    private EdgeType relationship; // e.g., "USES_SA" (uses ServiceAccount), "BOUND_TO" (bound to Role/ClusterRole)
}