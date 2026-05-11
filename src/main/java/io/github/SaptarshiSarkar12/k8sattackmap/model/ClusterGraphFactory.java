package io.github.SaptarshiSarkar12.k8sattackmap.model;

import lombok.extern.slf4j.Slf4j;
import org.jgrapht.Graph;
import org.jgrapht.graph.DirectedWeightedMultigraph;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * Constructs a JGraphT graph from parsed Kubernetes cluster data.
 * <p>
 * Primary entry point: {@link #buildGraph(ClusterGraphData)}, which:
 * <ol>
 *   <li>Creates a {@link org.jgrapht.graph.DirectedWeightedMultigraph} of {@link io.github.SaptarshiSarkar12.k8sattackmap.model.GraphNode}
 *       and {@link io.github.SaptarshiSarkar12.k8sattackmap.model.GraphEdge}</li>
 *   <li>Adds all nodes from {@link io.github.SaptarshiSarkar12.k8sattackmap.model.ClusterGraphData#getNodes()}</li>
 *   <li>Adds all edges, skipping those with missing source or target nodes</li>
 *   <li><strong>Prunes orphan nodes:</strong> Removes non-entry nodes with in-degree 0 (dead-end nodes).
 *       Entry point types (Pod, User, Group, ServiceAccount, Node) are retained even with zero in-degree.</li>
 *   <li>Populates {@link io.github.SaptarshiSarkar12.k8sattackmap.model.ClusterGraphData#getNodeLookup()} for O(1) lookups</li>
 * </ol>
 * <p>
 * The resulting graph is fed to analysis modules via {@link io.github.SaptarshiSarkar12.k8sattackmap.analysis.AnalysisInput}.
 * <p>
 * <strong>Important:</strong> Not every parsed node survives into the final graph due to pruning.
 */
@Slf4j
public class ClusterGraphFactory {
    public static Graph<GraphNode, GraphEdge> buildGraph(ClusterGraphData data) {
        Graph<GraphNode, GraphEdge> clusterGraph = new DirectedWeightedMultigraph<>(GraphEdge.class);
        Map<String, GraphNode> nodeLookup = new HashMap<>();
        log.info("Building graph: Adding nodes...");
        for (GraphNode node : data.getNodes()) {
            clusterGraph.addVertex(node);
            nodeLookup.put(node.getId(), node);
        }
        data.setNodeLookup(nodeLookup);

        log.info("Building graph: Adding edges...");
        for (GraphEdge edge : data.getEdges()) {
            GraphNode source = nodeLookup.get(edge.getSource());
            GraphNode target = nodeLookup.get(edge.getTarget());
            if (source != null && target != null) {
                clusterGraph.addEdge(source, target, edge);
            } else {
                log.debug("Skipping edge with missing node(s): \"{}\" -{}-> \"{}\"", edge.getSource(), edge.getRelationship(), edge.getTarget());
            }
        }

        int removed = 0;
        Set<String> entryPointTypes = Set.of("Pod", "User", "Group", "ServiceAccount", "Node");
        for (GraphNode node : new ArrayList<>(clusterGraph.vertexSet())) {
            if (clusterGraph.inDegreeOf(node) == 0 && !entryPointTypes.contains(node.getType())) {
                clusterGraph.removeVertex(node);
                removed++;
            }
        }

        log.info("Graph constructed with {} nodes and {} edges. Removed {} in-degree zero node(s).", clusterGraph.vertexSet().size(), clusterGraph.edgeSet().size(), removed);
        return clusterGraph;
    }
}
