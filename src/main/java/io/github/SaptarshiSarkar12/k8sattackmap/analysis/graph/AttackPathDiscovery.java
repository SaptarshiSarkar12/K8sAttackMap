package io.github.SaptarshiSarkar12.k8sattackmap.analysis.graph;

import io.github.SaptarshiSarkar12.k8sattackmap.analysis.AnalysisInput;
import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphEdge;
import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphNode;
import io.github.SaptarshiSarkar12.k8sattackmap.model.SecurityFacts;
import io.github.SaptarshiSarkar12.k8sattackmap.security.EdgeRiskScorer;
import org.jgrapht.Graph;
import org.jgrapht.GraphPath;
import org.jgrapht.alg.shortestpath.AllDirectedPaths;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

public final class AttackPathDiscovery {
    private AttackPathDiscovery() {
    }

    public static PathDiscoveryResult findAttackPaths(AnalysisInput input) {
        Graph<GraphNode, GraphEdge> graph = input.clusterGraph();
        Set<GraphNode> sources = input.sourceNodes();
        Set<GraphNode> targets = input.targetNodes();

        Map<GraphEdge, Double> riskScores = EdgeRiskScorer.calculateEdgeWeights(graph);
        AllDirectedPaths<GraphNode, GraphEdge> allPathsFinder = new AllDirectedPaths<>(graph);
        List<GraphPath<GraphNode, GraphEdge>> allDijkstraPaths = new ArrayList<>();
        List<GraphPath<GraphNode, GraphEdge>> allPossiblePaths = new ArrayList<>();

        GraphPath<GraphNode, GraphEdge> mostDangerousPath = null;
        double highestDangerScore = Double.NEGATIVE_INFINITY;

        Dijkstra dijkstra = new Dijkstra(graph, riskScores);

        for (GraphNode source : sources) {
            for (GraphNode target : targets) {
                if (source.equals(target)) continue;
                if (!graph.containsVertex(source) || !graph.containsVertex(target)) continue;

                GraphPath<GraphNode, GraphEdge> shortest = dijkstra.findShortestPath(source, target);
                if (shortest == null || shortest.getLength() == 0) continue;

                int baseLen = shortest.getLength();
                int maxSearchDepth = Math.clamp(baseLen + 2, 8, 10);
                List<GraphPath<GraphNode, GraphEdge>> paths = allPathsFinder.getAllPaths(source, target, true, maxSearchDepth);

                allPossiblePaths.addAll(paths);
                allDijkstraPaths.add(shortest);

                double rawScore = (10.0 * baseLen) - shortest.getWeight();
                double dangerScore = rawScore + computeTargetValueBonus(target);

                if (dangerScore > highestDangerScore) {
                    highestDangerScore = dangerScore;
                    mostDangerousPath = shortest;
                }
            }
        }

        return new PathDiscoveryResult(allPossiblePaths, allDijkstraPaths, mostDangerousPath, riskScores);
    }

    /**
     * Computes a bonus score for the target node based on its type and security facts.
     * Secrets and Nodes are high-value targets; RBAC wildcards/escalation verbs increase the bonus.
     * This ensures that multi-hop paths to sensitive assets rank higher than short dead-end paths.
     *
     * @param target the target node
     * @return bonus score (0–10, clamped)
     */
    private static double computeTargetValueBonus(GraphNode target) {
        double bonus = 0.0;
        String type = target.getType() == null ? "" : target.getType();
        SecurityFacts facts = target.getSecurityFacts();

        // Base by node type (higher means more sensitive)
        switch (type) {
            case "Secret" -> bonus += 5.0;
            case "Node" -> bonus += 4.0;
            case "ClusterRole" -> bonus += 3.0;
            case "ClusterRoleBinding", "RoleBinding" -> bonus += 2.5;
            case "Role" -> bonus += 2.0;
        }

        if (facts != null) {
            if (facts.isCredentialMaterial()) bonus += 3.0;
            if (facts.isRbacWildcardVerb()) bonus += 2.0;
            if (facts.isRbacWildcardResource()) bonus += 1.5;
            if (facts.isRbacWildcardApiGroup()) bonus += 1.0;
            if (facts.isRbacHasEscalate() || facts.isRbacHasBind() || facts.isRbacHasImpersonate()) bonus += 3.0;
        }

        return Math.min(bonus, 10.0);
    }
}