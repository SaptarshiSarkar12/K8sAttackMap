package io.github.SaptarshiSarkar12.k8sattackmap.model;

import org.jgrapht.Graph;
import org.jgrapht.graph.DirectedWeightedMultigraph;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

public class ClusterGraphFactory {
    private static final Logger log = LoggerFactory.getLogger(ClusterGraphFactory.class);

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
