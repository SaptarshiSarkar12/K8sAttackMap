package io.github.SaptarshiSarkar12.k8sattackmap.analysis;

import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphEdge;
import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphNode;
import org.jgrapht.Graph;

import java.util.Objects;
import java.util.Set;

public record AnalysisInput(Graph<GraphNode, GraphEdge> clusterGraph, Set<GraphNode> sourceNodes, Set<GraphNode> targetNodes, int maxHops) {
    public AnalysisInput(Graph<GraphNode, GraphEdge> clusterGraph, Set<GraphNode> sourceNodes, Set<GraphNode> targetNodes, int maxHops) {
        this.clusterGraph = Objects.requireNonNull(clusterGraph, "clusterGraph must not be null");
        this.sourceNodes = sourceNodes;
        this.targetNodes = targetNodes;
        this.maxHops = maxHops;
    }
}