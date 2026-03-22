package io.github.SaptarshiSarkar12.k8sattackmap.graph;

import io.github.SaptarshiSarkar12.k8sattackmap.model.ClusterGraphData;
import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphEdge;
import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphNode;
import org.jgrapht.Graph;
import org.jgrapht.graph.DirectedWeightedMultigraph;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Map;

public class ClusterGraph {
    private static final Logger log = LoggerFactory.getLogger(ClusterGraph.class);

    public static Graph<GraphNode, GraphEdge> buildGraph(ClusterGraphData data) {
        Graph<GraphNode, GraphEdge> clusterGraph = new DirectedWeightedMultigraph<>(GraphEdge.class);
        Map<String, GraphNode> nodeLookup = new HashMap<>();
        log.info("Building graph: Adding nodes...");
        for (GraphNode node : data.getNodes()) {
            clusterGraph.addVertex(node);
            nodeLookup.put(node.getId(), node);
        }

        log.info("Building graph: Adding edges...");
        int edgeCount = 0;
        for (GraphEdge edge : data.getEdges()) {
            GraphNode source = nodeLookup.get(edge.getSource());
            GraphNode target = nodeLookup.get(edge.getTarget());
            if (source != null && target != null) {
                clusterGraph.addEdge(source, target, edge);
                edgeCount++;
            } else {
                log.debug("Skipping edge with missing node(s): \"{}\" -{}-> \"{}\"", edge.getSource(), edge.getRelationship(), edge.getTarget());
            }
        }
        log.info("Graph constructed with {} nodes and {} edges.", clusterGraph.vertexSet().size(), edgeCount);
        return clusterGraph;
    }
}
