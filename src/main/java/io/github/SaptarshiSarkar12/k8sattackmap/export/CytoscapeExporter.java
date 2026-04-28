package io.github.SaptarshiSarkar12.k8sattackmap.export;

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.SaptarshiSarkar12.k8sattackmap.analysis.blast.BlastRadiusResult;
import io.github.SaptarshiSarkar12.k8sattackmap.analysis.chokepoint.RankedChokePoint;
import io.github.SaptarshiSarkar12.k8sattackmap.analysis.graph.PathDiscoveryResult;
import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphEdge;
import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphNode;
import io.github.SaptarshiSarkar12.k8sattackmap.util.AppConstants;
import io.github.SaptarshiSarkar12.k8sattackmap.util.TemplateStore;
import org.jgrapht.Graph;
import org.jgrapht.GraphPath;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;

import static io.github.SaptarshiSarkar12.k8sattackmap.util.JacksonConfig.MAPPER;

public class CytoscapeExporter {
    private static final Logger log = LoggerFactory.getLogger(CytoscapeExporter.class);

    public static void exportHtmlReport(Graph<GraphNode, GraphEdge> graph, PathDiscoveryResult pathResult, Set<GraphNode> sourceNodes, RankedChokePoint topChoke, Map<String, List<String>> podCVEIds, Map<GraphNode, BlastRadiusResult> blastBySource, int maxHops) {
        try {
            GraphNode chokePointNode = topChoke == null ? null : topChoke.node();

            String cytoscapeJson = exportToJson(
                    graph,
                    pathResult == null ? List.of() : pathResult.allPossiblePaths(),
                    chokePointNode,
                    sourceNodes == null ? List.of() : sourceNodes.stream().toList(),
                    blastBySource
            );

            String finalHtml = TemplateStore.HTML.replace("/*%GRAPH_DATA%*/", cytoscapeJson)
                    .replace("{{MAX_HOPS_COUNT}}", String.valueOf(maxHops));
            Files.writeString(Paths.get(AppConstants.OUTPUT_HTML_FILENAME), finalHtml);
            log.info("HTML/Cytoscape visualization exported to {}", AppConstants.OUTPUT_HTML_FILENAME);
        } catch (Exception e) {
            log.error("Failed to export Cytoscape HTML report.", e);
        }
    }

    public static String exportToJson(Graph<GraphNode, GraphEdge> graph,
                                      List<GraphPath<GraphNode, GraphEdge>> criticalPaths,
                                      GraphNode chokePoint,
                                      List<GraphNode> entryNodes,
                                      Map<GraphNode, BlastRadiusResult> blastBySource) throws Exception {

        ObjectNode root = MAPPER.createObjectNode();
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
            if (node.equals(chokePoint)) {
                data.put("isChokePoint", true);
                classes.add("choke-point");
            }

            // Tag Entry Nodes & Calculate Blast Radius
            if (entryNodes != null && entryNodes.contains(node)) {
                data.put("isEntry", true);
                classes.add("entry-node");

                // Use pre-computed blast radius instead of re-running BFS
                BlastRadiusResult blast = blastBySource.get(node);
                ArrayNode blastArray = data.putArray("blastRadiusIds");
                if (blast != null) {
                    blast.rankedImpactedAssets().forEach(asset -> blastArray.add(asset.node().getId()));
                }
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
            data.put("label", edge.getRelationship() != null ? edge.getRelationship().getLabel() : "connected");

            // Tag Critical Edges
            if (criticalEdges.contains(edge)) {
                edgeObj.put("classes", "critical-path");
            }
        }

        // Return pretty-printed JSON
        return MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(root);
    }
}