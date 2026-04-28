package io.github.SaptarshiSarkar12.k8sattackmap.export;

import io.github.SaptarshiSarkar12.k8sattackmap.analysis.chokepoint.RankedChokePoint;
import io.github.SaptarshiSarkar12.k8sattackmap.analysis.remediation.RemediationPlan;
import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphEdge;
import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphNode;
import org.jgrapht.Graph;
import org.jgrapht.GraphPath;

import java.util.List;
import java.util.Map;
import java.util.Set;

public record PdfReportData(
    String clusterContext,
    int totalPaths,
    int entryPointsCount,
    int loopsCount,
    List<RankedChokePoint> topChokePoints,
    GraphPath<GraphNode, GraphEdge> worstPath,
    Graph<GraphNode, GraphEdge> graph,
    List<List<GraphNode>> escalationLoops,
    Map<GraphEdge, Double> edgeRiskScores,
    Map<String, List<String>> podCVEIds,
    Map<String, GraphNode> nodeLookup,
    Set<GraphNode> nodesOnCriticalPath,
    List<RemediationPlan> remediationPlans
) {}