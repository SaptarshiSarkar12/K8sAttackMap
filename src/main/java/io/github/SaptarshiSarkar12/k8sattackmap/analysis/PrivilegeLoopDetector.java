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
        log.info("Finding Escalation Loops...");

        // 1. Flatten the graph to remove parallel edges
        // Johnson's Algorithm crashes if there are multiple edges between the exact same nodes.
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

        // 2. Circuit Breaker: If the graph is insanely dense (average degree > 50),
        // it might be a trap. Fall back to Tarjan's to prevent out-of-memory errors.
        if (v > 100 && (e / v) > 50) {
            log.error("🚨 Graph is too dense for deep cycle analysis. Falling back to Tarjan's algorithm.");
            TarjanSimpleCycles<GraphNode, DefaultEdge> tarjan = new TarjanSimpleCycles<>(simpleGraph);
            cycles = tarjan.findSimpleCycles();
        } else {
            log.info("🔄 Running Johnson's Algorithm (Graph looks sparse enough)...");
            JohnsonSimpleCycles<GraphNode, DefaultEdge> johnson = new JohnsonSimpleCycles<>(simpleGraph);
            cycles = johnson.findSimpleCycles();
        }

        // 3. Log the results
        if (cycles.isEmpty()) {
            log.info("✅ No privilege escalation loops detected in the cluster.");
        } else {
            log.warn("⚠️ CRITICAL: Found {} privilege escalation loops!", cycles.size());

            // Print the first few loops for debugging/logging
            int displayLimit = Math.min(cycles.size(), 5);
            for (int i = 0; i < displayLimit; i++) {
                List<GraphNode> loop = cycles.get(i);
                StringBuilder loopString = new StringBuilder();
                for (GraphNode node : loop) {
                    loopString.append(node.getId()).append(" -> ");
                }
                // Complete the visual loop back to the start
                loopString.append(loop.getFirst().getId());
                log.warn("   Loop {}: {}", (i + 1), loopString);
            }
            if (cycles.size() > displayLimit) {
                log.warn("   ... and {} more loops hidden for brevity.", (cycles.size() - displayLimit));
            }
        }

        return cycles;
    }
}