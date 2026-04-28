package io.github.SaptarshiSarkar12.k8sattackmap.analysis.graph;

import io.github.SaptarshiSarkar12.k8sattackmap.model.EdgeType;
import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphEdge;
import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphNode;
import org.jgrapht.Graph;
import org.jgrapht.alg.cycle.JohnsonSimpleCycles;
import org.jgrapht.graph.DefaultEdge;
import org.jgrapht.graph.SimpleDirectedGraph;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Set;

public class PrivilegeLoopDetector {
    private static final Logger log = LoggerFactory.getLogger(PrivilegeLoopDetector.class);
    private static final Set<EdgeType> RBAC_EDGE_TYPES = Set.of(
            EdgeType.BOUND_TO, EdgeType.CAN_ACCESS, EdgeType.MEMBER_OF
    );

    public static List<List<GraphNode>> findEscalationLoops(Graph<GraphNode, GraphEdge> originalGraph) {
        // Flatten to a simple directed graph as Johnson's algorithm crashes on parallel edges
        // (multiple edges between the same two nodes), which our multigraph can have.
        Graph<GraphNode, DefaultEdge> simpleGraph = new SimpleDirectedGraph<>(DefaultEdge.class);

        for (GraphNode node : originalGraph.vertexSet()) {
            simpleGraph.addVertex(node);
        }
        for (GraphEdge edge : originalGraph.edgeSet()) {
            GraphNode source = originalGraph.getEdgeSource(edge);
            GraphNode target = originalGraph.getEdgeTarget(edge);
            simpleGraph.addEdge(source, target);
        }

        int v = simpleGraph.vertexSet().size();
        int e = simpleGraph.edgeSet().size();
        log.debug("Running Johnson's cycle detection on {} vertices, {} edges.", v, e);
        List<List<GraphNode>> rawCycles = new JohnsonSimpleCycles<>(simpleGraph).findSimpleCycles();
        return rawCycles.stream()
                .filter(cycle -> cycleContainsRbacEdge(cycle, originalGraph))
                .toList();
    }

    private static boolean cycleContainsRbacEdge(List<GraphNode> cycle, Graph<GraphNode, GraphEdge> original) {
        // Check each consecutive pair in the cycle (including wrap-around)
        for (int i = 0; i < cycle.size(); i++) {
            GraphNode from = cycle.get(i);
            GraphNode to = cycle.get((i + 1) % cycle.size());
            Set<GraphEdge> edges = original.getAllEdges(from, to);
            for (GraphEdge e : edges) {
                if (RBAC_EDGE_TYPES.contains(e.getRelationship())) {
                    return true;
                }
            }
        }
        return false;
    }
}