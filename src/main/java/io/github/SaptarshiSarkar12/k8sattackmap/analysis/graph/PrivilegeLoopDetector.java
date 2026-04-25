package io.github.SaptarshiSarkar12.k8sattackmap.analysis.graph;

import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphEdge;
import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphNode;
import org.jgrapht.Graph;
import org.jgrapht.alg.cycle.JohnsonSimpleCycles;
import org.jgrapht.graph.DefaultDirectedGraph;
import org.jgrapht.graph.DefaultEdge;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

public class PrivilegeLoopDetector {
    private static final Logger log = LoggerFactory.getLogger(PrivilegeLoopDetector.class);

    public static List<List<GraphNode>> findEscalationLoops(Graph<GraphNode, GraphEdge> originalGraph) {
        // Flatten to a simple directed graph as Johnson's algorithm crashes on parallel edges
        // (multiple edges between the same two nodes), which our multigraph can have.
        Graph<GraphNode, DefaultEdge> simpleGraph = new DefaultDirectedGraph<>(DefaultEdge.class);

        for (GraphNode node : originalGraph.vertexSet()) {
            simpleGraph.addVertex(node);
        }
        for (GraphEdge edge : originalGraph.edgeSet()) {
            GraphNode source = originalGraph.getEdgeSource(edge);
            GraphNode target = originalGraph.getEdgeTarget(edge);
            if (!simpleGraph.containsEdge(source, target)) {
                simpleGraph.addEdge(source, target);
            }
        }

        int v = simpleGraph.vertexSet().size();
        int e = simpleGraph.edgeSet().size();
        log.debug("Running Johnson's cycle detection on {} vertices, {} edges.", v, e);

        return new JohnsonSimpleCycles<>(simpleGraph).findSimpleCycles();
    }
}