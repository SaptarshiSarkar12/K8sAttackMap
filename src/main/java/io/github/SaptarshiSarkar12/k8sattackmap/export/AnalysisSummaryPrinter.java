package io.github.SaptarshiSarkar12.k8sattackmap.export;

import io.github.SaptarshiSarkar12.k8sattackmap.analysis.*;
import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphEdge;
import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphNode;
import io.github.SaptarshiSarkar12.k8sattackmap.model.RankedChokePoint;
import org.jgrapht.Graph;
import org.jgrapht.GraphPath;
import org.slf4j.Logger;

import java.util.*;

import static io.github.SaptarshiSarkar12.k8sattackmap.util.ConsoleColors.*;

public class AnalysisSummaryPrinter {
    public static void print(Graph<GraphNode, GraphEdge> graph, AnalysisResult result, Map<String, List<String>> podCVEIds, Logger log, boolean verbose) {
        printHeader();

        PathDiscoveryResult pathResult = result.pathDiscoveryResult();
        ChokePointResult chokeResult = result.chokePointResult();
        List<BlastRadiusResult> blastResults = result.blastRadiusResults();

        printExecutiveSummary(pathResult, chokeResult, blastResults, log); // CHECKED
        printAttackPathAnalysis(graph, pathResult, log, verbose); // CHECKED
        printChokePointAnalysis(chokeResult, log);
        printBlastRadiusAnalysis(blastResults, log);
        printPodVulnerabilityDetails(podCVEIds, log);
        printRemediationPlans(result.remediationPlans(), log);
        printFooter();
    }

    private static void printHeader() {
        System.out.println(BOLD + "\n" + "=".repeat(80));
        System.out.println(" K8sAttackMap: SECURITY ANALYSIS SUMMARY");
        System.out.println("=".repeat(80) + RESET);
    }

    private static void printExecutiveSummary(PathDiscoveryResult pathResult, ChokePointResult chokeResult, List<BlastRadiusResult> blastResults, Logger log) {
        log.info(CYAN + "--- EXECUTIVE OVERVIEW ---" + RESET);
        log.info("  • Discovered Attack Paths: {}", pathResult.allPossiblePaths().size());
        log.info("  • Critical Choke Points:    {}", chokeResult.rankedChokePoints().size());

        long criticalAssets = blastResults.stream()
                .mapToLong(r -> r.severityCounts().getOrDefault(ImpactSeverity.CRITICAL, 0L))
                .sum();
        log.info("  • Critical Assets At Risk: {}", BOLD_RED + criticalAssets + RESET);
        System.out.println();
    }

    private static void printAttackPathAnalysis(Graph<GraphNode, GraphEdge> graph, PathDiscoveryResult pathResult, Logger log, boolean verbose) {
        log.info(CYAN + "--- ATTACK PATH ANALYSIS ---" + RESET);

        GraphPath<GraphNode, GraphEdge> mostDangerous = pathResult.mostDangerousPath();
        Map<GraphEdge, Double> edgeRiskScores = pathResult.edgeRiskScores();
        if (mostDangerous != null) {
            log.info(BOLD_RED + "[!] MOST DANGEROUS PATH IDENTIFIED:" + RESET);
            log.info("    Path: {} → {}", mostDangerous.getStartVertex().getId(), mostDangerous.getEndVertex().getId());
            double rawScore = (10.0 * mostDangerous.getLength()) - mostDangerous.getWeight();
            String severity = getPathSeverity(rawScore, mostDangerous.getLength());
            log.info("    Risk Score: {} ({})", String.format("%.1f", rawScore), severity);
            log.info("    Hops:        {}", mostDangerous.getLength());
            log.info("    Path Details:");
            for (GraphEdge edge : mostDangerous.getEdgeList()) {
                GraphNode edgeSource = graph.getEdgeSource(edge);
                GraphNode edgeTarget = graph.getEdgeTarget(edge);
                log.info("       {} --[{}]--> {} (Edge Weight: {})",
                        edgeSource.getId(), edge.getRelationship(), edgeTarget.getId(),
                        String.format("%.1f", 10.0 - edgeRiskScores.getOrDefault(edge, 0.0)));
            }
        }

        if (verbose) {
            log.info(YELLOW + "All Discovered Paths (Verbose):" + RESET);
            for (GraphPath<GraphNode, GraphEdge> path : pathResult.allPossiblePaths()) {
                double rawScore = (10.0 * path.getLength()) - path.getWeight();
                String severity = getPathSeverity(rawScore, path.getLength());
                log.info("  Path: {} → {} | Hops: {} | Risk Score: {} ({})",
                        path.getStartVertex().getId(), path.getEndVertex().getId(),
                        path.getLength(), String.format("%.1f", rawScore), severity);
                for (GraphEdge edge : path.getEdgeList()) {
                    GraphNode edgeSource = graph.getEdgeSource(edge);
                    GraphNode edgeTarget = graph.getEdgeTarget(edge);
                    log.info("     {} --[{}]--> {} (Edge Weight: {})",
                            edgeSource.getId(), edge.getRelationship(), edgeTarget.getId(),
                            String.format("%.1f", 10.0 - edgeRiskScores.getOrDefault(edge, 0.0)));
                }
            }
        }
        System.out.println();
    }

    private static void printChokePointAnalysis(ChokePointResult chokeResult, Logger log) {
        List<RankedChokePoint> ranked = chokeResult.rankedChokePoints();
        if (ranked == null || ranked.isEmpty()) {
            return;
        }

        log.info(CYAN + "--- CRITICAL CHOKE POINTS (Top Priority for Fixes) ---" + RESET);
        ranked.stream()
                .limit(5)
                .forEach(cp -> log.info(
                        "  • [{}] type={} -> paths={} weightedScore={}",
                        cp.node().getId(),
                        cp.node().getType(),
                        cp.pathsSevered(),
                        String.format("%.1f", cp.weightedScore())
                ));
        System.out.println();
    }

    private static void printBlastRadiusAnalysis(List<BlastRadiusResult> blastResults, Logger log) {
        if (blastResults.isEmpty()) return;

        log.info(CYAN + "--- BLAST RADIUS HIGHLIGHTS ---" + RESET);
        for (BlastRadiusResult br : blastResults) {
            GraphNode source = br.source();
            String nodeId = source.getId();
            String nodeType = source.getType();

            if (nodeType.equals("Pod")) {
                log.info("Source: [{}] type={} (Radius: {} hops, CVSS={})",
                        nodeId,
                        nodeType,
                        br.radius(),
                        String.format("%.1f", source.getRiskScore()));
            } else {
                log.info("Source: [{}] type={} (Radius: {} hops)", nodeId, nodeType, br.radius());
            }

            br.rankedImpactedAssets().stream()
                    .limit(3)
                    .forEach(asset -> {
                        GraphNode node = asset.node();
                        String assetId = node.getId();
                        String assetType = node.getType();
                        if (assetType.equals("Pod")) {
                            log.info("  {} [{}] severity={} (Hops: {}, CVSS={})",
                                    BOLD_RED + "!!" + RESET, assetId, asset.severity(), asset.hopsFromSource(),
                                    node.getRiskScore());
                        } else {
                            log.info("  {} [{}] severity={} (Hops: {})",
                                    BOLD_RED + "!!" + RESET, assetId, asset.severity(), asset.hopsFromSource());
                        }
                        log.info("     Reason: {}", String.join(", ", asset.riskReasons()));
                        log.info("     Action: {}", ImpactRemediationAdvisor.recommendAction(asset));
                    });
        }
        System.out.println();
    }

    private static void printPodVulnerabilityDetails(Map<String, List<String>> podCVEIds, Logger log) {
        if (podCVEIds == null || podCVEIds.isEmpty()) {
            return;
        }

        // Keep only pods with at least one CVE
        List<Map.Entry<String, List<String>>> vulnerablePods = podCVEIds.entrySet().stream()
                .filter(e -> e.getValue() != null && !e.getValue().isEmpty())
                .toList();

        if (vulnerablePods.isEmpty()) {
            return;
        }

        // Sort: CVSS desc (from pod id/name hints if unavailable -> 0), then CVE count desc, then pod id
        vulnerablePods = new ArrayList<>(vulnerablePods);
        vulnerablePods.sort(
                Comparator.<Map.Entry<String, List<String>>>comparingInt(e -> e.getValue().size()).reversed()
                        .thenComparing(Map.Entry::getKey, String.CASE_INSENSITIVE_ORDER)
        );

        log.info(CYAN + "--- POD VULNERABILITY DETAILS ---" + RESET);

        final int maxCvesToPrint = 12;
        for (Map.Entry<String, List<String>> entry : vulnerablePods) {
            String podId = entry.getKey();
            List<String> cves = entry.getValue();

            log.info("  • [{}] CVE_COUNT={}", podId, cves.size());

            if (cves.size() <= maxCvesToPrint) {
                log.info("     CVEs: {}", String.join(", ", cves));
            } else {
                log.info("     CVEs: {} ... (+{} more)",
                        String.join(", ", cves.subList(0, maxCvesToPrint)),
                        cves.size() - maxCvesToPrint);
            }
        }

        System.out.println();
    }

    private static void printRemediationPlans(List<RemediationPlan> plans, Logger log) {
        if (plans.isEmpty()) return;

        log.info(CYAN + "--- PROPOSED REMEDIATION ACTIONS ---" + RESET);
        for (RemediationPlan plan : plans) {
            log.info(GREEN + "Fix for Choke Point: " + RESET + "[{}]", plan.nodeId());
            log.info("  Rationale: {}", plan.rationale());

            if (!plan.enforceCommands().isEmpty()) {
                log.info("  " + BOLD + "Enforcement Command:" + RESET);
                log.info("    " + YELLOW + "{}" + RESET, plan.enforceCommands().getFirst());
            }

            if (plan.containsDestructiveAction()) {
                log.warn(BOLD_RED + "  [!] WARNING: Plan contains destructive actions." + RESET);
            }
        }
        System.out.println();
    }

    private static String getPathSeverity(double totalScore, int hops) {
        if (hops == 0) return "UNKNOWN";

        double averageRisk = totalScore / hops;

        if (averageRisk >= 8.0) return "CRITICAL";
        if (averageRisk >= 6.0) return "HIGH";
        if (averageRisk >= 4.0) return "MEDIUM";
        return "LOW";
    }

    private static void printFooter() {
        System.out.println(BOLD + "=".repeat(80));
        System.out.println(" End of Analysis Summary");
        System.out.println("=".repeat(80) + RESET + "\n");
    }
}