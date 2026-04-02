package io.github.SaptarshiSarkar12.k8sattackmap;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import com.openhtmltopdf.util.XRLog;
import io.github.SaptarshiSarkar12.k8sattackmap.algorithm.AttackPathRemediationAdvisor;
import io.github.SaptarshiSarkar12.k8sattackmap.algorithm.BFS;
import io.github.SaptarshiSarkar12.k8sattackmap.algorithm.Dijkstra;
import io.github.SaptarshiSarkar12.k8sattackmap.algorithm.PrivilegeLoopDetector;
import io.github.SaptarshiSarkar12.k8sattackmap.cli.CommandParser;
import io.github.SaptarshiSarkar12.k8sattackmap.export.CytoscapeExporter;
import io.github.SaptarshiSarkar12.k8sattackmap.export.PdfReportEngine;
import io.github.SaptarshiSarkar12.k8sattackmap.graph.ClusterGraph;
import io.github.SaptarshiSarkar12.k8sattackmap.ingestion.K8sJsonParser;
import io.github.SaptarshiSarkar12.k8sattackmap.ingestion.KubectlExtractor;
import io.github.SaptarshiSarkar12.k8sattackmap.model.ClusterGraphData;
import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphEdge;
import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphNode;
import io.github.SaptarshiSarkar12.k8sattackmap.security.EdgeRiskScorer;
import io.github.SaptarshiSarkar12.k8sattackmap.security.ThreatBoundaryAnalyzer;
import io.github.SaptarshiSarkar12.k8sattackmap.util.AppConstants;
import io.github.SaptarshiSarkar12.k8sattackmap.util.WorkspaceManager;
import org.jgrapht.Graph;
import org.jgrapht.GraphPath;
import org.jgrapht.alg.shortestpath.AllDirectedPaths;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;

import static io.github.SaptarshiSarkar12.k8sattackmap.util.ConsoleColors.*;

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

        Graph<GraphNode, GraphEdge> graph = loadClusterGraph(cli);
        if (graph == null) {
            System.exit(1);
        }

        analyzeAttackPaths(cli, graph);
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

    private static Graph<GraphNode, GraphEdge> loadClusterGraph(CommandParser cli) {
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

            return ClusterGraph.buildGraph(graphData);
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

    private static void analyzeAttackPaths(CommandParser cli, Graph<GraphNode, GraphEdge> graph) {
        Map<GraphEdge, Double> riskScores = EdgeRiskScorer.calculateEdgeWeights(graph);
        List<GraphNode> sourceNodes = new ArrayList<>();
        List<GraphNode> targetNodes = new ArrayList<>();

        GraphNode sourceNode = findNodeById(graph, cli.getSourceNode());
        GraphNode targetNode = findNodeById(graph, cli.getTargetNode());

        if (sourceNode != null) {
            sourceNodes.add(sourceNode);
        }
        if (targetNode != null) {
            targetNodes.add(targetNode);
        }

        AllDirectedPaths<GraphNode, GraphEdge> pathFinder = new AllDirectedPaths<>(graph);
        List<GraphPath<GraphNode, GraphEdge>> allPossiblePaths = new ArrayList<>();

        GraphPath<GraphNode, GraphEdge> mostDangerousPath;

        if (sourceNode == null || targetNode == null) {
            mostDangerousPath = analyzeWithAutoDiscovery(graph, sourceNodes, targetNodes, riskScores, pathFinder, allPossiblePaths);
        } else {
            mostDangerousPath = analyzeWithExplicitNodes(graph, sourceNode, targetNode, cli.getSourceNode(), cli.getTargetNode(), riskScores, pathFinder, allPossiblePaths);
        }

        if (mostDangerousPath == null) {
            System.exit(0);
        }

        runBlastRadiusAnalysis(graph, mostDangerousPath, cli.getMaxHops());
        String recommendation = runRecommendationEngine(allPossiblePaths);
        exportResults(graph, recommendation, allPossiblePaths, mostDangerousPath, sourceNodes, cli);
    }

    private static GraphNode findNodeById(Graph<GraphNode, GraphEdge> graph, String nodeId) {
        if (nodeId == null) {
            return null;
        }
        return graph.vertexSet().stream()
                .filter(node -> node.getId().equalsIgnoreCase(nodeId))
                .findFirst()
                .orElse(null);
    }

    private static GraphPath<GraphNode, GraphEdge> analyzeWithAutoDiscovery(
            Graph<GraphNode, GraphEdge> graph,
            List<GraphNode> sourceNodes,
            List<GraphNode> targetNodes,
            Map<GraphEdge, Double> riskScores,
            AllDirectedPaths<GraphNode, GraphEdge> pathFinder,
            List<GraphPath<GraphNode, GraphEdge>> allPossiblePaths) {

        log.info("No explicit source/target provided. Running Auto-Discovery Heuristics...");
        ThreatBoundaryAnalyzer.analyze(graph.vertexSet(), sourceNodes, targetNodes);

        if (sourceNodes.isEmpty() || targetNodes.isEmpty()) {
            log.info("Auto-discovery did not identify any valid source or target nodes. Please provide explicit source and target using --source and --target.");
            return null;
        }

        GraphPath<GraphNode, GraphEdge> mostDangerousPath = getMostDangerousPath(graph, sourceNodes, targetNodes, riskScores, pathFinder, allPossiblePaths);

        if (mostDangerousPath != null) {
            printAttackPath(mostDangerousPath);
        } else {
            log.info(GREEN + "✔ SUCCESS: No attack paths found between identified entry points and crown jewels." + RESET);
            log.info(GREEN + "Cluster may be well-secured, or the auto-discovery heuristics may need adjustment. Please review the identified source and target nodes, and consider providing explicit nodes for analysis." + RESET);
        }

        return mostDangerousPath;
    }

    private static GraphPath<GraphNode, GraphEdge> analyzeWithExplicitNodes(
            Graph<GraphNode, GraphEdge> graph,
            GraphNode sourceNode,
            GraphNode targetNode,
            String sourceNodeId,
            String targetNodeId,
            Map<GraphEdge, Double> riskScores,
            AllDirectedPaths<GraphNode, GraphEdge> pathFinder,
            List<GraphPath<GraphNode, GraphEdge>> allPossiblePaths) {

        log.info("Running attack path analysis for specified source and target...");

        GraphPath<GraphNode, GraphEdge> mostDangerousPath = Dijkstra.findShortestPath(graph, sourceNode, targetNode, riskScores);

        if (mostDangerousPath != null) {
            int baselineLength = mostDangerousPath.getLength();
            int maxSearchDepth = baselineLength + 2;
            List<GraphPath<GraphNode, GraphEdge>> paths = pathFinder.getAllPaths(sourceNode, targetNode, true, maxSearchDepth);
            allPossiblePaths.addAll(paths);
            printAttackPath(mostDangerousPath);
        } else {
            System.out.print(GREEN);
            log.info("✔ SUCCESS: No attack path found between {} and {}.", sourceNodeId, targetNodeId);
            log.info("Cluster may be well-secured, or the specified nodes may not be directly exploitable. Please review the source and target nodes, and consider running without explicit nodes to allow auto-discovery heuristics to identify potential attack paths.");
            System.out.print(RESET);
        }

        return mostDangerousPath;
    }

    private static void exportResults(
            Graph<GraphNode, GraphEdge> graph,
            String recommendation,
            List<GraphPath<GraphNode, GraphEdge>> allPossiblePaths,
            GraphPath<GraphNode, GraphEdge> mostDangerousPath,
            List<GraphNode> sourceNodes,
            CommandParser cli) {

        Set<String> outputFormats = cli.getOutputFormats();
        if (!outputFormats.isEmpty()) {
            GraphNode chokePointNode = extractChokePointNode(graph, recommendation);
            boolean hasSupportedFormat = false;

            if (outputFormats.contains("html")) {
                hasSupportedFormat = true;
                generateHtmlVisualisation(graph, chokePointNode, allPossiblePaths, sourceNodes, cli.getMaxHops());
            }

            if (outputFormats.contains("pdf")) {
                hasSupportedFormat = true;
                try {
                    List<List<GraphNode>> cycles = PrivilegeLoopDetector.findEscalationLoops(graph);
                    int totalLoops = cycles.size();
                    final String count = recommendation.substring(
                            recommendation.lastIndexOf("eliminate") + 10,
                            recommendation.lastIndexOf("attack paths")
                    );
                    int pathsSevered = count.trim().isEmpty() ? 0 : Integer.parseInt(count.trim());

                    PdfReportEngine.generatePdf(
                            AppConstants.OUTPUT_PDF_FILENAME,
                            KubectlExtractor.getClusterContext(),
                            totalLoops,
                            sourceNodes.size(),
                            totalLoops,
                            chokePointNode,
                            pathsSevered,
                            mostDangerousPath,
                            cycles
                    );
                    System.out.print(GREEN);
                    log.info("✔ SUCCESS: Executive PDF Report exported to {}", AppConstants.OUTPUT_PDF_FILENAME);
                    System.out.print(RESET);
                } catch (Exception e) {
                    log.error("Failed to generate PDF Report.", e);
                }
            }

            if (!hasSupportedFormat) {
                log.error("Unsupported output format specified. Supported formats are: html, pdf");
            }
        }
    }

    private static void generateHtmlVisualisation(
            Graph<GraphNode, GraphEdge> graph,
            GraphNode chokePointNode,
            List<GraphPath<GraphNode, GraphEdge>> totalPathsForRemediation,
            List<GraphNode> sources,
            int maxSearchDepth) {

        try {
            String cytoscapeJson = CytoscapeExporter.exportToJson(
                    graph,
                    totalPathsForRemediation,
                    chokePointNode,
                    sources,
                    maxSearchDepth
            );
            String finalHtml = AppConstants.TEMPLATE_HTML.replace("/*%GRAPH_DATA%*/", cytoscapeJson);
            Files.writeString(Paths.get(AppConstants.OUTPUT_HTML_FILENAME), finalHtml);
            System.out.print(GREEN);
            log.info("✔ SUCCESS: Visualization exported to {}", AppConstants.OUTPUT_HTML_FILENAME);
            System.out.print(RESET);
        } catch (Exception e) {
            log.error("Failed to export Cytoscape visualization.", e);
        }
    }

    private static GraphNode extractChokePointNode(Graph<GraphNode, GraphEdge> graph, String recommendation) {
        int startIdx = recommendation.indexOf("[");
        int endIdx = recommendation.indexOf("]");

        if (startIdx == -1 || endIdx == -1) {
            return null;
        }

        String chokeId = recommendation.substring(startIdx + 1, endIdx);
        return findNodeById(graph, chokeId);
    }

    private static String runRecommendationEngine(List<GraphPath<GraphNode, GraphEdge>> allPossiblePaths) {
        log.info("Generating remediation recommendations based on the discovered attack paths...");
        String recommendation = AttackPathRemediationAdvisor.recommendHighestImpactRemediation(allPossiblePaths);
        System.out.print(GREEN);
        log.info(recommendation);
        System.out.print(RESET);
        return recommendation;
    }

    private static void runBlastRadiusAnalysis(Graph<GraphNode, GraphEdge> graph, GraphPath<GraphNode, GraphEdge> path, int maxHops) {
        log.info("Running blast radius analysis for the discovered attack path...");
        Set<GraphNode> blastRadius = BFS.getAffectedNodes(graph, path.getStartVertex(), maxHops);
        log.info("Estimated Blast Radius ({} nodes within {} hops):", blastRadius.size(), maxHops);
        blastRadius.forEach(node -> log.info("   - {}", node.getId()));
    }

    private static GraphPath<GraphNode, GraphEdge> getMostDangerousPath(
            Graph<GraphNode, GraphEdge> graph,
            List<GraphNode> sourceNodes,
            List<GraphNode> targetNodes,
            Map<GraphEdge, Double> riskScores,
            AllDirectedPaths<GraphNode, GraphEdge> pathFinder,
            List<GraphPath<GraphNode, GraphEdge>> allPossiblePaths) {

        GraphPath<GraphNode, GraphEdge> mostDangerousPath = null;
        double lowestFrictionDensity = Double.MAX_VALUE;

        for (GraphNode source : sourceNodes) {
            for (GraphNode target : targetNodes) {
                if (source.equals(target)) {
                    continue;
                }

                GraphPath<GraphNode, GraphEdge> path = Dijkstra.findShortestPath(graph, source, target, riskScores);
                if (path != null) {
                    int baselineLength = path.getLength();
                    int maxSearchDepth = baselineLength + 2; // Allowing for slightly longer paths to be considered in the analysis,
                    // as sometimes the "most dangerous" path may not be the absolute shortest one due to risk score distribution.
                    // This gives us a more comprehensive view of potential attack vectors while still keeping the search space manageable.
                    List<GraphPath<GraphNode, GraphEdge>> paths = pathFinder.getAllPaths(source, target, true, maxSearchDepth);
                    allPossiblePaths.addAll(paths);

                    double pathRisk = path.getWeight();
                    double pathLength = path.getLength();
                    double frictionDensity = pathRisk / pathLength;

                    if (frictionDensity < lowestFrictionDensity) {
                        lowestFrictionDensity = frictionDensity;
                        mostDangerousPath = path;
                    }
                }
            }
        }

        return mostDangerousPath;
    }

    private static void printAttackPath(GraphPath<GraphNode, GraphEdge> path) {
        log.error("Critical Attack Path Detected!");
        System.out.print(BOLD_RED);
        log.info("--------------------------------------------------");
        log.info("Source: {}", path.getStartVertex().getId());
        log.info("Target: {}", path.getEndVertex().getId());
        log.info("Total Hops: {}", path.getLength());
        log.info("Total Attacker Friction: {}", String.format("%.1f", path.getWeight()));

        double rawScore = (10.0 * path.getLength()) - path.getWeight();
        String severity = Dijkstra.getPathSeverity(rawScore, path.getLength());
        log.info("Path Risk Score: {} ({})", String.format("%.1f", rawScore), severity);
        log.info("Execution Steps:");

        int stepNum = 1;
        for (GraphEdge edge : path.getEdgeList()) {
            GraphNode sourceNode = path.getGraph().getEdgeSource(edge);
            GraphNode targetNode = path.getGraph().getEdgeTarget(edge);
            log.info("  Step {}: [{}] --({})--> [{}]", stepNum, sourceNode.getId(), edge.getRelationship(), targetNode.getId());
            stepNum++;
        }

        log.info("--------------------------------------------------");
        System.out.print(RESET);
    }
}