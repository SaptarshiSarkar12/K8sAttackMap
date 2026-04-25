package io.github.SaptarshiSarkar12.k8sattackmap.export;

import io.github.SaptarshiSarkar12.k8sattackmap.analysis.AnalysisResult;
import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphEdge;
import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphNode;
import org.jgrapht.Graph;

import java.util.Set;

public final class ExportService {
    public static void export(AnalysisResult result, Graph<GraphNode, GraphEdge> graph, Set<GraphNode> sourceNodes, int maxHops, Set<String> outputFormats) {
        if (outputFormats.contains("pdf")) {
//            PdfReportEngine.generateReport(result, graph, sourceNodes, maxHops);
        }
        if (outputFormats.contains("cytoscape")) {
//            CytoscapeExporter.exportToCytoscape(result, graph);
        }
    }
}