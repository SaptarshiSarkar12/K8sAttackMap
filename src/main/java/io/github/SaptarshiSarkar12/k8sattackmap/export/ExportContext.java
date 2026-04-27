package io.github.SaptarshiSarkar12.k8sattackmap.export;

import io.github.SaptarshiSarkar12.k8sattackmap.analysis.AnalysisResult;
import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphEdge;
import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphNode;
import org.jgrapht.Graph;

import java.util.List;
import java.util.Map;
import java.util.Set;

public record ExportContext(
    AnalysisResult result,
    Graph<GraphNode, GraphEdge> graph,
    Set<GraphNode> sourceNodes,
    int maxHops,
    Map<String, List<String>> podCVEIds,
    Map<String, GraphNode> nodeLookup,
    Map<GraphEdge, Double> edgeRiskScores,
    String clusterContext
) {
}