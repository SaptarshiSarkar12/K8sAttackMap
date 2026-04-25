package io.github.SaptarshiSarkar12.k8sattackmap.analysis;

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
    public static GraphPath<GraphNode, GraphEdge> findShortestPath(Graph<GraphNode, GraphEdge> graph, GraphNode source, GraphNode target, Map<GraphEdge, Double> edgeWeights) {
        Graph<GraphNode, GraphEdge> weightedGraph = new AsWeightedGraph<>(graph, edgeWeights);
        DijkstraShortestPath<GraphNode, GraphEdge> dijkstraAlg = new DijkstraShortestPath<>(weightedGraph);
        return dijkstraAlg.getPath(source, target);
    }
}
