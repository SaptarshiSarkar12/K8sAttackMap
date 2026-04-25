package io.github.SaptarshiSarkar12.k8sattackmap.export;

import io.github.SaptarshiSarkar12.k8sattackmap.analysis.AnalysisResult;
import io.github.SaptarshiSarkar12.k8sattackmap.analysis.blast.BlastRadiusResult;
import io.github.SaptarshiSarkar12.k8sattackmap.analysis.graph.PathDiscoveryResult;
import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphEdge;
import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphNode;
import io.github.SaptarshiSarkar12.k8sattackmap.analysis.chokepoint.RankedChokePoint;
import org.jgrapht.Graph;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public final class ExportService {
    public static void export(ExportContext ctx, Set<String> outputFormats) {
        AnalysisResult result = ctx.result();
        Graph<GraphNode, GraphEdge> graph = ctx.graph();
        Set<GraphNode> sourceNodes = ctx.sourceNodes();
        Map<String, List<String>> podCVEIds = ctx.podCVEIds();
        String clusterContext = ctx.clusterContext();
        PathDiscoveryResult pathResult = result.pathDiscoveryResult();
        RankedChokePoint topChoke = getTopChoke(result);

        Map<GraphNode, BlastRadiusResult> blastBySource = result.blastRadiusResults().stream()
                .collect(Collectors.toMap(BlastRadiusResult::source, r -> r));

        if (outputFormats.contains("pdf")) {
            PdfReportEngine.exportPdfReport(result, graph, sourceNodes, clusterContext);
        }
        if (outputFormats.contains("html")) {
            CytoscapeExporter.exportHtmlReport(graph, pathResult, sourceNodes, topChoke, podCVEIds, blastBySource);
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