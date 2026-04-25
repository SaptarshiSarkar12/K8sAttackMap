package io.github.SaptarshiSarkar12.k8sattackmap.util;

import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashSet;
import java.util.Set;

public class NodeFinder {
    private static final Logger log = LoggerFactory.getLogger(NodeFinder.class);

    public static Set<GraphNode> findNodesById(Set<GraphNode> vertexSet, Set<String> nodeIds) {
        Set<GraphNode> nodes = new HashSet<>();
        for (String nodeId : nodeIds) {
            GraphNode node = findNodeById(vertexSet, nodeId);
            if (node != null) nodes.add(node);
            else log.warn("Specified node not found in graph: {}. Ignoring.", nodeId);
        }
        return nodes;
    }

    public static GraphNode findNodeById(Set<GraphNode> vertexSet, String nodeId) {
        if (nodeId == null) {
            return null;
        }
        return vertexSet.stream()
                .filter(node -> node.getId().equalsIgnoreCase(nodeId))
                .findFirst()
                .orElse(null);
    }
}
