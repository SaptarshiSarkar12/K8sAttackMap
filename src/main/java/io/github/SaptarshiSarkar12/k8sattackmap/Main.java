package io.github.SaptarshiSarkar12.k8sattackmap;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import com.openhtmltopdf.util.XRLog;
import io.github.SaptarshiSarkar12.k8sattackmap.analysis.*;
import io.github.SaptarshiSarkar12.k8sattackmap.cli.CommandParser;
import io.github.SaptarshiSarkar12.k8sattackmap.export.AnalysisSummaryPrinter;
import io.github.SaptarshiSarkar12.k8sattackmap.export.ExportService;
import io.github.SaptarshiSarkar12.k8sattackmap.model.ClusterGraphFactory;
import io.github.SaptarshiSarkar12.k8sattackmap.ingestion.K8sJsonParser;
import io.github.SaptarshiSarkar12.k8sattackmap.ingestion.KubectlExtractor;
import io.github.SaptarshiSarkar12.k8sattackmap.model.ClusterGraphData;
import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphEdge;
import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphNode;
import io.github.SaptarshiSarkar12.k8sattackmap.security.AttackSurfaceClassifier;
import io.github.SaptarshiSarkar12.k8sattackmap.util.AppConstants;
import io.github.SaptarshiSarkar12.k8sattackmap.util.WorkspaceManager;
import org.jgrapht.Graph;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;

import static io.github.SaptarshiSarkar12.k8sattackmap.util.NodeFinder.findNodesById;

public class Main {
    private static final org.slf4j.Logger log = LoggerFactory.getLogger(Main.class);

    static void main(String[] args) {
        System.out.println(AppConstants.HEADER);
        WorkspaceManager.initializeWorkspace();
        CommandParser cli = new CommandParser();
        if (!cli.parse(args)) {
            System.exit(1);
        }

        configureLogging(cli);
        initializeTemplates();

        ClusterGraphData graphData = loadClusterGraph(cli);
        if (graphData == null) {
            System.exit(1);
        }

        Graph<GraphNode, GraphEdge> graph = ClusterGraphFactory.buildGraph(graphData);

        Set<GraphNode> vertexSet = graph.vertexSet();
        Set<String> sourceNodeIds = cli.getSourceNodes();
        Set<String> targetNodeIds = cli.getTargetNodes();

        Set<GraphNode> sourceNodes = findNodesById(vertexSet, sourceNodeIds);
        Set<GraphNode> targetNodes = findNodesById(vertexSet, targetNodeIds);
        if (sourceNodeIds.isEmpty() || targetNodeIds.isEmpty()) {
            log.info("No explicit source/target provided. Running Auto-Discovery Heuristics...");
            AttackSurfaceClassifier.classifySourceAndTargetCandidates(graph.vertexSet(), sourceNodes, targetNodes);
            if (sourceNodes.isEmpty() || targetNodes.isEmpty()) {
                log.info("Auto-discovery found no valid source/target. Use --source and --target.");
                System.exit(1);
            }
        }
        AnalysisInput input = new AnalysisInput(graph, sourceNodes, targetNodes, cli.getMaxHops());
        AnalysisResult result = AnalysisOrchestrator.performAnalysis(input);

        AnalysisSummaryPrinter.print(graph, result, graphData.getPodCVEIds(), log, cli.isVerbose());
        ExportService.export(result, graph, sourceNodes, cli.getMaxHops(), cli.getOutputFormats());
    }

    private static void configureLogging(CommandParser cli) {
        Logger rootLogger = (Logger) LoggerFactory.getLogger(org.slf4j.Logger.ROOT_LOGGER_NAME);
        if (cli.isVerbose()) {
            rootLogger.setLevel(Level.DEBUG);
            log.debug("Verbose logging enabled.");
        } else {
            rootLogger.setLevel(Level.INFO);
        }
        XRLog.setLoggingEnabled(cli.isVerbose()); // Toggles logging for openhtmltopdf used for pdf generation
    }

    private static void initializeTemplates() {
        try {
            AppConstants.TEMPLATE_HTML = Files.readString(Paths.get(Objects.requireNonNull(Main.class.getResource(AppConstants.HTML_TEMPLATE_RESOURCE_PATH)).toURI()));
        } catch (Exception e) {
            log.error("Failed to load template for HTML: {}", e.getMessage(), e);
            System.exit(1);
        }
        try {
            AppConstants.TEMPLATE_PDF = Files.readString(Paths.get(Objects.requireNonNull(Main.class.getResource(AppConstants.PDF_TEMPLATE_RESOURCE_PATH)).toURI()));
        } catch (Exception e) {
            log.error("Failed to load template for PDF: {}", e.getMessage(), e);
            System.exit(1);
        }
    }

    private static ClusterGraphData loadClusterGraph(CommandParser cli) {
        Reader jsonReader = null;
        try {
            jsonReader = getJsonReader(cli);
            if (jsonReader == null) {
                return null;
            }

            ClusterGraphData graphData = K8sJsonParser.parse(jsonReader);
            if (graphData == null) {
                log.error("Failed to parse Kubernetes JSON data. Please ensure the file is in the correct format and contains valid cluster information.");
                return null;
            }

            return graphData;
        } catch (IOException e) {
            log.error("Error reading Kubernetes JSON data: {}", e.getMessage(), e);
            return null;
        } finally {
            closeJsonReader(jsonReader);
        }
    }

    private static Reader getJsonReader(CommandParser cli) throws IOException {
        if (cli.getK8sJsonPath() == null) {
            log.info("No Kubernetes JSON path provided. Using kubectl to extract cluster data...");
            String clusterJson = KubectlExtractor.fetchClusterStateAsJson();
            if (clusterJson == null) {
                log.error("Failed to fetch cluster state using kubectl. Please ensure kubectl is installed, configured correctly, and you have access to the cluster. Alternatively, provide a JSON file with --k8s-json.");
                return null;
            }
            return new StringReader(clusterJson);
        } else {
            log.info("Using provided Kubernetes JSON file: {}", cli.getK8sJsonPath());
            return Files.newBufferedReader(cli.getK8sJsonPath());
        }
    }

    private static void closeJsonReader(Reader jsonReader) {
        if (jsonReader != null) {
            try {
                jsonReader.close();
            } catch (IOException e) {
                log.error("Error closing Kubernetes JSON reader: {}", e.getMessage(), e);
            }
        }
    }
}