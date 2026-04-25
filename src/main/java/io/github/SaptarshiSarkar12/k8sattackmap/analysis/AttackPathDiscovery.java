package io.github.SaptarshiSarkar12.k8sattackmap.analysis;

import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphEdge;
import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphNode;
import io.github.SaptarshiSarkar12.k8sattackmap.security.EdgeRiskScorer;
import org.jgrapht.Graph;
import org.jgrapht.GraphPath;
import org.jgrapht.alg.shortestpath.AllDirectedPaths;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class AttackPathDiscovery {
    private AttackPathDiscovery() {
    }

    public static PathDiscoveryResult findAttackPaths(AnalysisInput input) {
        Graph<GraphNode, GraphEdge> graph = input.clusterGraph();
        Set<GraphNode> sourceNodes = input.sourceNodes();
        Set<GraphNode> targetNodes = input.targetNodes();
        Map<GraphEdge, Double> riskScores = EdgeRiskScorer.calculateEdgeWeights(graph);
        AllDirectedPaths<GraphNode, GraphEdge> pathFinder = new AllDirectedPaths<>(graph);
        List<GraphPath<GraphNode, GraphEdge>> allDijkstraPaths = new ArrayList<>();
        List<GraphPath<GraphNode, GraphEdge>> allPossiblePaths = new ArrayList<>();
        GraphPath<GraphNode, GraphEdge> mostDangerousPath = null;
        double lowestFrictionDensity = Double.MAX_VALUE;

        for (GraphNode source : sourceNodes) {
            for (GraphNode target : targetNodes) {
                if (source.equals(target)) continue;
                GraphPath<GraphNode, GraphEdge> path = Dijkstra.findShortestPath(graph, source, target, riskScores);
                if (path != null && path.getLength() > 0) {
                    int baseLen = path.getLength();
                    int maxSearchDepth = baseLen + 2;
                    List<GraphPath<GraphNode, GraphEdge>> paths = pathFinder.getAllPaths(source, target, true, maxSearchDepth);
                    allPossiblePaths.addAll(paths);
                    allDijkstraPaths.add(path);

                    double frictionDensity = path.getWeight() / baseLen;
                    if (frictionDensity < lowestFrictionDensity) {
                        lowestFrictionDensity = frictionDensity;
                        mostDangerousPath = path;
                    }
                }
            }
        }
        return new PathDiscoveryResult(allPossiblePaths, allDijkstraPaths, mostDangerousPath, riskScores);
    }
}