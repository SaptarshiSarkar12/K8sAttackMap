package io.github.SaptarshiSarkar12.k8sattackmap.analysis.graph;

import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphEdge;
import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphNode;
import org.jgrapht.GraphPath;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public record PathDiscoveryResult(List<GraphPath<GraphNode, GraphEdge>> allPossiblePaths, List<GraphPath<GraphNode, GraphEdge>> dijkstraPaths, GraphPath<GraphNode, GraphEdge> mostDangerousPath, Map<GraphEdge, Double> edgeRiskScores) {
    public PathDiscoveryResult {
        if (allPossiblePaths == null) {
            allPossiblePaths = new ArrayList<>();
        }
        if (dijkstraPaths == null) {
            dijkstraPaths = new ArrayList<>();
        }
        if (edgeRiskScores == null) {
            edgeRiskScores = Map.of();
        }
    }
}