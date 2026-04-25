package io.github.SaptarshiSarkar12.k8sattackmap.analysis.graph;

import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphEdge;
import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphNode;
import org.jgrapht.Graph;
import org.jgrapht.GraphPath;
import org.jgrapht.alg.shortestpath.DijkstraShortestPath;
import org.jgrapht.graph.AsWeightedGraph;

import java.util.Map;

public class Dijkstra {
    private final Graph<GraphNode, GraphEdge> weightedGraph;

    public Dijkstra(Graph<GraphNode, GraphEdge> graph, Map<GraphEdge, Double> edgeWeights) {
        weightedGraph = new AsWeightedGraph<>(graph, edgeWeights);
    }

    public GraphPath<GraphNode, GraphEdge> findShortestPath(GraphNode source, GraphNode target) {
        DijkstraShortestPath<GraphNode, GraphEdge> dijkstraAlg = new DijkstraShortestPath<>(weightedGraph);
        return dijkstraAlg.getPath(source, target);
    }
}
