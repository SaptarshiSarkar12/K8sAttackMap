package io.github.SaptarshiSarkar12.k8sattackmap.algorithm;

import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphEdge;
import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphNode;
import org.jgrapht.Graph;
import org.jgrapht.traverse.BreadthFirstIterator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashSet;
import java.util.Set;

public class BFS {
    private static final Logger log = LoggerFactory.getLogger(BFS.class);

    public static Set<GraphNode> getAffectedNodes(Graph<GraphNode, GraphEdge> graph, GraphNode sourceNode, int maxHops) {
        Set<GraphNode> affectedNodes = new HashSet<>();
        if (!graph.containsVertex(sourceNode)) {
            log.error("Source Node {} does not exist", sourceNode.getId());
            return affectedNodes;
        }
        BreadthFirstIterator<GraphNode, GraphEdge> bfsIterator = new BreadthFirstIterator<>(graph, sourceNode);
        log.debug("Starting BFS from node: {} with max hops: {}", sourceNode.getId(), maxHops);
        while (bfsIterator.hasNext()) {
            GraphNode node = bfsIterator.next();
            int currentDepth = bfsIterator.getDepth(node);
            if (currentDepth > maxHops) {
                break;
            }
            affectedNodes.add(node);
        }
        log.debug("BFS completed. Total affected nodes within {} hops: {}", maxHops, affectedNodes.size());
        log.debug("Affected nodes: {}", affectedNodes);
        return affectedNodes;
    }
}
