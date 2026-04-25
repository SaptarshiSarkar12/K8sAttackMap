package io.github.SaptarshiSarkar12.k8sattackmap.analysis;

import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphEdge;
import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphNode;
import org.jgrapht.Graph;
import org.jgrapht.alg.cycle.JohnsonSimpleCycles;
import org.jgrapht.alg.cycle.TarjanSimpleCycles;
import org.jgrapht.graph.DefaultDirectedGraph;
import org.jgrapht.graph.DefaultEdge;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

public class PrivilegeLoopDetector {
    private static final Logger log = LoggerFactory.getLogger(PrivilegeLoopDetector.class);

    public static List<List<GraphNode>> findEscalationLoops(Graph<GraphNode, GraphEdge> originalGraph) {
        // Flatten the graph to remove parallel edges
        // Johnson's Algorithm implementation crashes if there are multiple edges between the exact same nodes.
        Graph<GraphNode, DefaultEdge> simpleGraph = new DefaultDirectedGraph<>(DefaultEdge.class);

        for (GraphNode node : originalGraph.vertexSet()) {
            simpleGraph.addVertex(node);
        }

        for (GraphEdge edge : originalGraph.edgeSet()) {
            GraphNode source = originalGraph.getEdgeSource(edge);
            GraphNode target = originalGraph.getEdgeTarget(edge);
            // Only add the edge if one doesn't already exist between these two specific nodes
            if (!simpleGraph.containsEdge(source, target)) {
                simpleGraph.addEdge(source, target);
            }
        }

        int v = simpleGraph.vertexSet().size();
        int e = simpleGraph.edgeSet().size();
        List<List<GraphNode>> cycles;

        double avgDegree = v > 0 ? (double) e / v : 0.0;
        double density = v > 1 ? (double) e / (v * (v - 1)) : 0.0;

        log.debug("Graph has {} vertices and {} edges (average degree: {}).", v, e, avgDegree);
        log.debug("Graph density: {}.", density);

        if (v > 100 && avgDegree > 50.0) {
            log.debug("Switching to Tarjan's algorithm for cycle detection due to graph density.");
            TarjanSimpleCycles<GraphNode, DefaultEdge> tarjan = new TarjanSimpleCycles<>(simpleGraph);
            cycles = tarjan.findSimpleCycles();
        } else {
            log.debug("Proceeding with Johnson's algorithm for cycle detection.");
            JohnsonSimpleCycles<GraphNode, DefaultEdge> johnson = new JohnsonSimpleCycles<>(simpleGraph);
            cycles = johnson.findSimpleCycles();
        }
        return cycles;
    }
}