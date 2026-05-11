package io.github.SaptarshiSarkar12.k8sattackmap.analysis;

import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphEdge;
import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphNode;
import org.jgrapht.Graph;

import java.util.Objects;
import java.util.Set;

/**
 * Immutable input payload for all security analysis stages.
 * <p>
 * Encapsulates the cluster graph, attack source nodes (entry points), target nodes (crown jewels),
 * and maximum hop depth for multi-stage blast radius analysis.
 * <p>
 * {@code sourceNodes} are typically auto-discovered by {@link io.github.SaptarshiSarkar12.k8sattackmap.security.AttackSurfaceClassifier}
 * or provided by CLI. {@code targetNodes} are high-value assets to protect (Secrets, ClusterRoles, etc.).
 * {@code maxHops} limits lateral movement analysis depth passed to {@link io.github.SaptarshiSarkar12.k8sattackmap.analysis.blast.BlastRadiusAnalyzer}.
 *
 * @param clusterGraph the JGraphT graph of Kubernetes resources (must not be null)
 * @param sourceNodes candidate attack entry points (pods, users, load balancers)
 * @param targetNodes high-value targets to assess impact on (secrets, roles, data)
 * @param maxHops maximum hops for blast radius (lateral movement depth)
 */
public record AnalysisInput(Graph<GraphNode, GraphEdge> clusterGraph, Set<GraphNode> sourceNodes, Set<GraphNode> targetNodes, int maxHops) {
    public AnalysisInput(Graph<GraphNode, GraphEdge> clusterGraph, Set<GraphNode> sourceNodes, Set<GraphNode> targetNodes, int maxHops) {
        this.clusterGraph = Objects.requireNonNull(clusterGraph, "clusterGraph must not be null");
        this.sourceNodes = sourceNodes;
        this.targetNodes = targetNodes;
        this.maxHops = maxHops;
    }
}