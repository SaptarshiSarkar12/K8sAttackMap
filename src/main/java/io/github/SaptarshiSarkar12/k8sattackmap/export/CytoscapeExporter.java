package io.github.SaptarshiSarkar12.k8sattackmap.export;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphEdge;
import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphNode;
import org.jgrapht.Graph;
import org.jgrapht.GraphPath;

import java.util.*;

public class CytoscapeExporter {
    private static final ObjectMapper mapper = new ObjectMapper();

    /**
     * Exports the JGraphT model into a valid Cytoscape.js JSON string.
     */
    public static String exportToJson(Graph<GraphNode, GraphEdge> graph,
                                      List<GraphPath<GraphNode, GraphEdge>> criticalPaths,
                                      GraphNode chokePoint,
                                      List<GraphNode> entryNodes,
                                      int maxBlastHops) throws Exception {

        ObjectNode root = mapper.createObjectNode();
        ArrayNode nodesArray = root.putArray("nodes");
        ArrayNode edgesArray = root.putArray("edges");

        // 1. Identify Critical Elements for highlighting
        Set<GraphNode> criticalNodes = new HashSet<>();
        Set<GraphEdge> criticalEdges = new HashSet<>();
        if (criticalPaths != null) {
            for (GraphPath<GraphNode, GraphEdge> path : criticalPaths) {
                criticalNodes.addAll(path.getVertexList());
                criticalEdges.addAll(path.getEdgeList());
            }
        }

        // 2. Process Nodes
        for (GraphNode node : graph.vertexSet()) {
            ObjectNode nodeObj = nodesArray.addObject();
            ObjectNode data = nodeObj.putObject("data");

            String type = node.getType() != null ? node.getType() : "Unknown";
            String shortName = node.getId().substring(node.getId().lastIndexOf(":") + 1);

            data.put("id", node.getId());
            data.put("label", shortName + "\n(" + type + ")");
            data.put("type", type.toLowerCase());

            List<String> classes = new ArrayList<>();

            // Tag Critical Path
            if (criticalNodes.contains(node)) {
                classes.add("critical-path");
            }
            
            // Tag Choke Point
            if (chokePoint != null && node.equals(chokePoint)) {
                data.put("isChokePoint", true);
                classes.add("choke-point");
            }

            // Tag Entry Nodes & Calculate Blast Radius
            if (entryNodes != null && entryNodes.contains(node)) {
                data.put("isEntry", true);
                classes.add("entry-node");
                
                List<String> blastIds = calculateBlastRadius(graph, node, maxBlastHops);
                ArrayNode blastArray = data.putArray("blastRadiusIds");
                blastIds.forEach(blastArray::add);
            }

            // Apply classes
            if (!classes.isEmpty()) {
                nodeObj.put("classes", String.join(" ", classes));
            }
        }

        // 3. Process Edges
        for (GraphEdge edge : graph.edgeSet()) {
            ObjectNode edgeObj = edgesArray.addObject();
            ObjectNode data = edgeObj.putObject("data");

            data.put("source", graph.getEdgeSource(edge).getId());
            data.put("target", graph.getEdgeTarget(edge).getId());
            data.put("label", edge.getRelationship() != null ? edge.getRelationship() : "connected");

            // Tag Critical Edges
            if (criticalEdges.contains(edge)) {
                edgeObj.put("classes", "critical-path");
            }
        }

        // Return pretty-printed JSON
        return mapper.writerWithDefaultPrettyPrinter().writeValueAsString(root);
    }

    /**
     * Executes a Breadth-First Search (BFS) to find all nodes reachable from the start node within maxHops.
     */
    private static List<String> calculateBlastRadius(Graph<GraphNode, GraphEdge> graph, GraphNode start, int maxHops) {
        List<String> reachable = new ArrayList<>();
        Queue<GraphNode> queue = new LinkedList<>();
        Map<GraphNode, Integer> distances = new HashMap<>();

        queue.add(start);
        distances.put(start, 0);

        while (!queue.isEmpty()) {
            GraphNode current = queue.poll();
            int dist = distances.get(current);

            // Don't add the start node itself to its own blast radius
            if (dist > 0) {
                reachable.add(current.getId());
            }

            if (dist < maxHops) {
                for (GraphEdge edge : graph.outgoingEdgesOf(current)) {
                    GraphNode neighbor = graph.getEdgeTarget(edge);
                    if (!distances.containsKey(neighbor)) {
                        distances.put(neighbor, dist + 1);
                        queue.add(neighbor);
                    }
                }
            }
        }
        return reachable;
    }
}