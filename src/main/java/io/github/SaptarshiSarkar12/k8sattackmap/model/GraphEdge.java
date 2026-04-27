package io.github.SaptarshiSarkar12.k8sattackmap.model;

import lombok.Getter;
import lombok.Setter;
import org.jgrapht.graph.DefaultWeightedEdge;

@Setter
@Getter
public class GraphEdge extends DefaultWeightedEdge {
    private String source;
    private String target;
    private EdgeType relationship; // e.g., "USES_SA" (uses ServiceAccount), "BOUND_TO" (bound to Role/ClusterRole)
}