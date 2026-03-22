package io.github.SaptarshiSarkar12.k8sattackmap;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import io.github.SaptarshiSarkar12.k8sattackmap.algorithm.AttackPathRemediationAdvisor;
import io.github.SaptarshiSarkar12.k8sattackmap.algorithm.BFS;
import io.github.SaptarshiSarkar12.k8sattackmap.algorithm.Dijkstra;
import io.github.SaptarshiSarkar12.k8sattackmap.cli.CommandParser;
import io.github.SaptarshiSarkar12.k8sattackmap.graph.ClusterGraph;
import io.github.SaptarshiSarkar12.k8sattackmap.ingestion.K8sJsonParser;
import io.github.SaptarshiSarkar12.k8sattackmap.ingestion.KubectlExtractor;
import io.github.SaptarshiSarkar12.k8sattackmap.model.ClusterGraphData;
import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphEdge;
import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphNode;
import io.github.SaptarshiSarkar12.k8sattackmap.security.EdgeRiskScorer;
import io.github.SaptarshiSarkar12.k8sattackmap.security.ThreatBoundaryAnalyzer;
import io.github.SaptarshiSarkar12.k8sattackmap.util.AppConstants;
import org.jgrapht.Graph;
import org.jgrapht.GraphPath;
import org.jgrapht.alg.shortestpath.AllDirectedPaths;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static io.github.SaptarshiSarkar12.k8sattackmap.util.ConsoleColors.GREEN;
import static io.github.SaptarshiSarkar12.k8sattackmap.util.ConsoleColors.RESET;

public class Main {
    private static final org.slf4j.Logger log = LoggerFactory.getLogger(Main.class);

    static void main(String[] args) {
        System.out.println(AppConstants.HEADER);
        CommandParser cli = new CommandParser();
        // If the user typed invalid commands, exit gracefully.
        if (!cli.parse(args)) System.exit(1);
        Logger rootLogger = (Logger) LoggerFactory.getLogger(org.slf4j.Logger.ROOT_LOGGER_NAME);
        if (cli.isVerbose()) {
            rootLogger.setLevel(Level.DEBUG);
            log.debug("Verbose logging enabled.");
        } else {
            rootLogger.setLevel(Level.INFO);
        }
        Reader jsonReader = null;
        Graph<GraphNode, GraphEdge> graph = null;
        try {
            if (cli.getK8sJsonPath() == null) {
                log.info("No Kubernetes JSON path provided. Using kubectl to extract cluster data...");
                String clusterJson = KubectlExtractor.fetchClusterStateAsJson();
                if (clusterJson == null) {
                    log.error("Failed to fetch cluster state using kubectl. Please ensure kubectl is installed, configured correctly, and you have access to the cluster. Alternatively, provide a JSON file with --k8s-json.");
                    System.exit(1);
                }
                jsonReader = new StringReader(clusterJson);
            } else {
                log.info("Using provided Kubernetes JSON file: {}", cli.getK8sJsonPath());
                jsonReader = Files.newBufferedReader(cli.getK8sJsonPath());
            }
            ClusterGraphData graphData = K8sJsonParser.parse(jsonReader);
            if (graphData == null) {
                log.error("Failed to parse Kubernetes JSON data. Please ensure the file is in the correct format and contains valid cluster information.");
                System.exit(1);
            }
            graph = ClusterGraph.buildGraph(graphData);
        } catch (IOException e) {
            log.error("Error reading Kubernetes JSON data: {}", e.getMessage(), e);
            System.exit(1);
        } finally {
            if (jsonReader != null) {
                try {
                    jsonReader.close();
                } catch (IOException e) {
                    log.error("Error closing Kubernetes JSON reader: {}", e.getMessage(), e);
                }
            }
        }
        Map<GraphEdge, Double> riskScores = EdgeRiskScorer.calculateEdgeWeights(graph);
        List<GraphNode> sourceNodes = new ArrayList<>();
        List<GraphNode> targetNodes = new ArrayList<>();
        String sourceNodeId = cli.getSourceNode();
        String targetNodeId = cli.getTargetNode();
        GraphNode sourceNode = null;
        GraphNode targetNode = null;
        if (sourceNodeId != null) {
            sourceNode = graph.vertexSet().stream()
                    .filter(node -> node.getId().equalsIgnoreCase(sourceNodeId))
                    .findFirst()
                    .orElse(null);
            if (sourceNode == null) {
                log.error("Specified source node '{}' not found in the graph.", sourceNodeId);
                System.exit(1);
            }
            sourceNodes.add(sourceNode);
        }
        if (targetNodeId != null) {
            targetNode = graph.vertexSet().stream()
                    .filter(node -> node.getId().equalsIgnoreCase(targetNodeId))
                    .findFirst()
                    .orElse(null);
            if (targetNode == null) {
                log.error("Specified target node '{}' not found in the graph.", targetNodeId);
                System.exit(1);
            }
            targetNodes.add(targetNode);
        }
        GraphPath<GraphNode, GraphEdge> mostDangerousPath;
        AllDirectedPaths<GraphNode, GraphEdge> pathFinder = new AllDirectedPaths<>(graph);
        List<GraphPath<GraphNode, GraphEdge>> allPossiblePaths = new ArrayList<>();
        if (sourceNode == null || targetNode == null) {
            log.info("No explicit source/target provided. Running Auto-Discovery Heuristics...");
            ThreatBoundaryAnalyzer.analyze(graph.vertexSet(), sourceNodes, targetNodes);
            if (sourceNodes.isEmpty() || targetNodes.isEmpty()) {
                log.info("Auto-discovery did not identify any valid source or target nodes. Please provide explicit source and target using --source and --target.");
                System.exit(1);
            }
            mostDangerousPath = getMostDangerousPath(graph, sourceNodes, targetNodes, riskScores, pathFinder, allPossiblePaths);
            if (mostDangerousPath != null) {
                printAttackPath(mostDangerousPath);
            } else {
                log.info(GREEN + "✔ SUCCESS: No attack paths found between identified entry points and crown jewels." + RESET);
                log.info(GREEN + "Cluster may be well-secured, or the auto-discovery heuristics may need adjustment. Please review the identified source and target nodes, and consider providing explicit nodes for analysis." + RESET);
                System.exit(0);
            }
        } else {
            log.info("Running attack path analysis for specified source and target...");
            mostDangerousPath = Dijkstra.findShortestPath(graph, sourceNode, targetNode, riskScores);
            if (mostDangerousPath != null) {
                int baselineLength = mostDangerousPath.getLength();
                int maxSearchDepth = baselineLength + 2;
                List<GraphPath<GraphNode, GraphEdge>> paths = pathFinder.getAllPaths(sourceNode, targetNode, true, maxSearchDepth);
                allPossiblePaths.addAll(paths);
                printAttackPath(mostDangerousPath);
            } else {
                log.info(GREEN + "✔ SUCCESS: No attack path found between {} and {}." + RESET, sourceNodeId, targetNodeId);
                log.info(GREEN + "Cluster may be well-secured, or the specified nodes may not be directly exploitable. Please review the source and target nodes, and consider running without explicit nodes to allow auto-discovery heuristics to identify potential attack paths." + RESET);
                System.exit(0);
            }
        }
        runBlastRadiusAnalysis(graph, mostDangerousPath, cli.getMaxHops());
        runRecommendationEngine(allPossiblePaths);
    }

    private static void runRecommendationEngine(List<GraphPath<GraphNode, GraphEdge>> allPossiblePaths) {
        log.info("Generating remediation recommendations based on the discovered attack paths...");
        String recommendation = AttackPathRemediationAdvisor.recommendHighestImpactRemediation(allPossiblePaths);
        log.info(recommendation);
    }

    private static void runBlastRadiusAnalysis(Graph<GraphNode, GraphEdge> graph, GraphPath<GraphNode, GraphEdge> path, int maxHops) {
        log.info("Running blast radius analysis for the discovered attack path...");
        Set<GraphNode> blastRadius = BFS.getAffectedNodes(graph, path.getStartVertex(), maxHops);
        log.info("Estimated Blast Radius ({} nodes within {} hops):", blastRadius.size(), maxHops);
        blastRadius.forEach(node -> log.info("   - {}", node.getId()));
    }

    private static GraphPath<GraphNode, GraphEdge> getMostDangerousPath(Graph<GraphNode, GraphEdge> graph, List<GraphNode> sourceNodes, List<GraphNode> targetNodes, Map<GraphEdge, Double> riskScores, AllDirectedPaths<GraphNode, GraphEdge> pathFinder, List<GraphPath<GraphNode, GraphEdge>> allPossiblePaths) {
        GraphPath<GraphNode, GraphEdge> mostDangerousPath = null;
        double lowestFrictionDensity = Double.MAX_VALUE;
        for (GraphNode source : sourceNodes) {
            for (GraphNode target : targetNodes) {
                if (source.equals(target)) {
                    continue; // Skip if source and target are the same node
                }
                GraphPath<GraphNode, GraphEdge> path = Dijkstra.findShortestPath(graph, source, target, riskScores);
                if (path != null) {
                    // To avoid combinatorial explosion, we only explore paths that are close in length to the shortest path.
                    int baselineLength = path.getLength();
                    int maxSearchDepth = baselineLength + 2;
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
    }
}
