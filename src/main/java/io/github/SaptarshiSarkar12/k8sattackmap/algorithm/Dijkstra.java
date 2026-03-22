package io.github.SaptarshiSarkar12.k8sattackmap.algorithm;

import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphEdge;
import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphNode;
import org.jgrapht.Graph;
import org.jgrapht.GraphPath;
import org.jgrapht.alg.shortestpath.DijkstraShortestPath;
import org.jgrapht.graph.AsWeightedGraph;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;

public class Dijkstra {
    private static final Logger log = LoggerFactory.getLogger(Dijkstra.class);

    public static GraphPath<GraphNode, GraphEdge> findShortestPath(Graph<GraphNode, GraphEdge> graph, GraphNode source, GraphNode target, Map<GraphEdge, Double> edgeWeights) {
        Graph<GraphNode, GraphEdge> weightedGraph = new AsWeightedGraph<>(graph, edgeWeights);
        DijkstraShortestPath<GraphNode, GraphEdge> dijkstraAlg = new DijkstraShortestPath<>(weightedGraph);
        GraphPath<GraphNode, GraphEdge> path = dijkstraAlg.getPath(source, target);
        if (path != null) {
            log.warn("⚠ WARNING: Attack Path Detected");
            log.warn("Source: {}", source);
            log.warn("Target: {}", target);
            log.warn("Total Hops: {}", path.getLength());
            double rawScore = (10.0 * path.getLength()) - path.getWeight();
            String severity = getPathSeverity(rawScore, path.getLength());
            log.warn("Path Risk Score: {} ({})", String.format("%.1f", rawScore), severity);
            log.warn("Path Details:");
            for (GraphEdge edge : path.getEdgeList()) {
                GraphNode edgeSource = graph.getEdgeSource(edge);
                GraphNode edgeTarget = graph.getEdgeTarget(edge);
                log.warn("   {} --[{}]--> {}", edgeSource.getId(), edge.getRelationship(), edgeTarget.getId());
            }
        }
        return path;
    }

    public static String getPathSeverity(double totalScore, int hops) {
        if (hops == 0) return "UNKNOWN";

        double averageRisk = totalScore / hops;

        if (averageRisk >= 8.0) return "CRITICAL";
        if (averageRisk >= 6.0) return "HIGH";
        if (averageRisk >= 4.0) return "MEDIUM";
        return "LOW";
    }
}
