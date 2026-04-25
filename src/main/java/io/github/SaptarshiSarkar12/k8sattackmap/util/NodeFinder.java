package io.github.SaptarshiSarkar12.k8sattackmap.util;

import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class NodeFinder {
    private static final Logger log = LoggerFactory.getLogger(NodeFinder.class);

    public static Set<GraphNode> findNodesById(Map<String, GraphNode> nodeLookup, Set<String> nodeIds) {
        Set<GraphNode> nodes = new HashSet<>();
        for (String nodeId : nodeIds) {
            if (nodeId == null) continue;
            GraphNode node = nodeLookup.get(nodeId);
            if (node == null) {
                node = nodeLookup.values().stream()
                        .filter(n -> n.getId().equalsIgnoreCase(nodeId))
                        .findFirst().orElse(null);
            }
            if (node != null) nodes.add(node);
            else log.warn("Specified node not found in graph: {}. Ignoring.", nodeId);
        }
        return nodes;
    }
}
