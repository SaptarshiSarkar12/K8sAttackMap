package io.github.SaptarshiSarkar12.k8sattackmap.export;

import io.github.SaptarshiSarkar12.k8sattackmap.analysis.AnalysisResult;
import io.github.SaptarshiSarkar12.k8sattackmap.analysis.blast.BlastRadiusResult;
import io.github.SaptarshiSarkar12.k8sattackmap.analysis.chokepoint.RankedChokePoint;
import io.github.SaptarshiSarkar12.k8sattackmap.analysis.graph.PathDiscoveryResult;
import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphEdge;
import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphNode;
import org.jgrapht.Graph;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Coordinates export of analysis results to multiple output formats.
 * <p>
 * Primary entry point: {@link #export(ExportContext, Set)} handles:
 * <ul>
 *   <li>{@code "html"} → {@link CytoscapeExporter}: Interactive Cytoscape.js graph visualization
 *       (default filename: {@link io.github.SaptarshiSarkar12.k8sattackmap.util.AppConstants#OUTPUT_HTML_FILENAME})</li>
 *   <li>{@code "pdf"} → {@link PdfReportEngine}: Formatted PDF security report
 *       (default filename: {@link io.github.SaptarshiSarkar12.k8sattackmap.util.AppConstants#OUTPUT_PDF_FILENAME})</li>
 * </ul>
 * <p>
 * Delegates to specialized exporters; this class acts as a facade/router for export logic.
 */
public final class ExportService {
    public static void export(ExportContext ctx, Set<String> outputFormats) {
        AnalysisResult result = ctx.result();
        Graph<GraphNode, GraphEdge> graph = ctx.graph();
        Set<GraphNode> sourceNodes = ctx.sourceNodes();
        Map<String, List<String>> podCVEIds = ctx.podCVEIds();
        Map<GraphEdge, Double> edgeRiskScores = ctx.edgeRiskScores();
        String clusterContext = ctx.clusterContext();
        PathDiscoveryResult pathResult = result.pathDiscoveryResult();
        RankedChokePoint topChoke = getTopChoke(result);

        Map<GraphNode, BlastRadiusResult> blastBySource = result.blastRadiusResults().stream()
                .collect(Collectors.toMap(BlastRadiusResult::source, r -> r));

        if (outputFormats.contains("pdf")) {
            PdfReportEngine.exportPdfReport(result, graph, sourceNodes, clusterContext, edgeRiskScores, podCVEIds, ctx.nodeLookup());
        }
        if (outputFormats.contains("html")) {
            CytoscapeExporter.exportHtmlReport(graph, pathResult, sourceNodes, topChoke, blastBySource, ctx.maxHops());
        }
    }

    private static RankedChokePoint getTopChoke(AnalysisResult result) {
        if (result == null
                || result.chokePointResult() == null
                || result.chokePointResult().rankedChokePoints() == null
                || result.chokePointResult().rankedChokePoints().isEmpty()) {
            return null;
        }
        return result.chokePointResult().rankedChokePoints().getFirst();
    }
}