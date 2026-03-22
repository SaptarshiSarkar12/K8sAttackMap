package io.github.SaptarshiSarkar12.k8sattackmap.model;

import lombok.Getter;
import lombok.Setter;
import org.jgrapht.graph.DefaultWeightedEdge;

@Setter
@Getter
public class GraphEdge extends DefaultWeightedEdge {
    private String source;
    private String target;
    private String relationship; // e.g., "uses_sa" (uses ServiceAccount), "bound_to" (bound to Role/ClusterRole)
}


