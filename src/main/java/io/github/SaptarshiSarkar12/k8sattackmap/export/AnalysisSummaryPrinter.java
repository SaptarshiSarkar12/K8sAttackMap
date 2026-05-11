package io.github.SaptarshiSarkar12.k8sattackmap.export;

import io.github.SaptarshiSarkar12.k8sattackmap.analysis.AnalysisResult;
import io.github.SaptarshiSarkar12.k8sattackmap.analysis.blast.BlastRadiusResult;
import io.github.SaptarshiSarkar12.k8sattackmap.analysis.blast.ImpactSeverity;
import io.github.SaptarshiSarkar12.k8sattackmap.analysis.chokepoint.ChokePointResult;
import io.github.SaptarshiSarkar12.k8sattackmap.analysis.chokepoint.RankedChokePoint;
import io.github.SaptarshiSarkar12.k8sattackmap.analysis.graph.PathDiscoveryResult;
import io.github.SaptarshiSarkar12.k8sattackmap.analysis.remediation.ImpactRemediationAdvisor;
import io.github.SaptarshiSarkar12.k8sattackmap.analysis.remediation.RemediationPlan;
import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphEdge;
import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphNode;
import io.github.SaptarshiSarkar12.k8sattackmap.util.RiskConfig;
import lombok.extern.slf4j.Slf4j;
import org.jgrapht.Graph;
import org.jgrapht.GraphPath;

import java.util.*;
import java.util.stream.Collectors;

import static io.github.SaptarshiSarkar12.k8sattackmap.util.ConsoleColors.*;
import static io.github.SaptarshiSarkar12.k8sattackmap.util.StringUtils.safeLower;

/**
 * Prints a comprehensive console summary of security analysis results.
 * <p>
 * Primary entry point: {@link #print(Graph, AnalysisResult, Map, boolean, boolean)}, which outputs:
 * <ul>
 *   <li><strong>Executive Summary:</strong> High-level counts of paths, choke points, privilege loops</li>
 *   <li><strong>Attack Paths:</strong> Discovered routes from entry points to crown jewels</li>
 *   <li><strong>Choke Points:</strong> Critical resources for defense (bottlenecks in attack flows)</li>
 *   <li><strong>Privilege Loops:</strong> Cycles enabling escalation</li>
 *   <li><strong>Blast Radius:</strong> Cascading impact of resource compromises</li>
 *   <li><strong>Pod Vulnerabilities:</strong> Scanned CVE counts per Pod</li>
 *   <li><strong>Remediation Plans:</strong> Specific mitigation strategies</li>
 * </ul>
 * <p>
 * Uses {@link io.github.SaptarshiSarkar12.k8sattackmap.util.ConsoleColors} for ANSI-colored output
 * when supported. <strong>This is the primary user-facing output; use System.out here (not SLF4J).</strong>
 */
@Slf4j
public class AnalysisSummaryPrinter {
    public static void print(Graph<GraphNode, GraphEdge> graph, AnalysisResult result, Map<String, List<String>> podCVEIds, boolean showAllPaths, boolean hasExports) {
        printHeader();
        PathDiscoveryResult pathResult = result.pathDiscoveryResult();
        ChokePointResult chokeResult = result.chokePointResult();
        List<BlastRadiusResult> blastResults = result.blastRadiusResults();
        List<List<GraphNode>> privilegeLoops = result.privilegeLoops();

        printExecutiveSummary(pathResult, chokeResult, privilegeLoops, blastResults);
        printAttackPathAnalysis(graph, pathResult, showAllPaths);
        printChokePointAnalysis(chokeResult);
        printPrivilegeLoopAnalysis(privilegeLoops);
        printBlastRadiusAnalysis(blastResults);
        printPodVulnerabilityDetails(podCVEIds);
        printRemediationPlans(result.remediationPlans());
        printFooter(hasExports);
    }

    private static void printHeader() {
        System.out.println(BOLD + "\n" + "=".repeat(80));
        System.out.println(" K8sAttackMap: SECURITY ANALYSIS SUMMARY");
        System.out.println("=".repeat(80) + RESET);
    }

    private static void printExecutiveSummary(PathDiscoveryResult pathResult, ChokePointResult chokeResult, List<List<GraphNode>> privilegeLoops, List<BlastRadiusResult> blastResults) {
        log.info("{}--- EXECUTIVE OVERVIEW ---{}", CYAN, RESET);
        log.info("  • Discovered Attack Paths: {}", pathResult.allPossiblePaths().size());
        log.info("  • Critical Choke Points: {}", chokeResult.rankedChokePoints().size());
        log.info("  • Privilege Escalation Loops: {}", privilegeLoops.size());

        long criticalAssets = blastResults.stream()
                .mapToLong(r -> r.severityCounts().getOrDefault(ImpactSeverity.CRITICAL, 0L))
                .sum();
        log.info("  • Critical Assets At Risk: {}", BOLD_RED + criticalAssets + RESET);
        System.out.println();
    }

    private static void printAttackPathAnalysis(Graph<GraphNode, GraphEdge> graph, PathDiscoveryResult pathResult, boolean showAllPaths) {
        log.info("{}--- ATTACK PATH ANALYSIS ---{}", CYAN, RESET);

        GraphPath<GraphNode, GraphEdge> mostDangerous = pathResult.mostDangerousPath();
        Map<GraphEdge, Double> edgeRiskScores = pathResult.edgeRiskScores();

        if (mostDangerous == null) {
            log.info("  No attack paths discovered.");
            System.out.println();
            return;
        }

        // Always show the most dangerous path
        log.info("{}[!] MOST DANGEROUS PATH IDENTIFIED:{}", BOLD_RED, RESET);
        printSinglePath(graph, mostDangerous, edgeRiskScores, true, true);

        if (!showAllPaths) {
            log.info("  (Use --show-all-paths to display all discovered paths grouped by source → target)");
            System.out.println();
            return;
        }

        // Group allPossiblePaths by (source id, target id) pair
        // and within each group keep the Dijkstra path tagged as shortest
        Map<String, GraphPath<GraphNode, GraphEdge>> shortestByPair = pathResult.dijkstraPaths().stream()
                .collect(Collectors.toMap(
                        AnalysisSummaryPrinter::pairKey,
                        p -> p,
                        (a, _) -> a
                        // if duplicate key, keep first (shouldn't happen since dijkstraPaths should have unique source-target pairs)
                ));

        // Group all paths by pair key, preserving insertion order for readability
        Map<String, List<GraphPath<GraphNode, GraphEdge>>> grouped = new LinkedHashMap<>();
        for (GraphPath<GraphNode, GraphEdge> path : pathResult.allPossiblePaths()) {
            grouped.computeIfAbsent(pairKey(path), _ -> new ArrayList<>()).add(path);
        }

        if (grouped.isEmpty()) {
            System.out.println();
            return;
        }

        log.info("{}All Discovered Paths:{}", YELLOW, RESET);
        int pairIndex = 1;
        for (Map.Entry<String, List<GraphPath<GraphNode, GraphEdge>>> entry : grouped.entrySet()) {
            List<GraphPath<GraphNode, GraphEdge>> paths = entry.getValue();
            GraphPath<GraphNode, GraphEdge> representative = paths.getFirst();
            String sourceId = representative.getStartVertex().getId();
            String targetId = representative.getEndVertex().getId();

            log.info("  [{}/{}] {} → {}  ({} path(s))", pairIndex++, grouped.size(), sourceId, targetId, paths.size());

            // Sort paths within each group: shortest (fewest hops) first, then by risk score desc
            paths.sort(Comparator
                    .comparingInt(GraphPath<GraphNode, GraphEdge>::getLength)
                    .thenComparingDouble(p -> -((10.0 * p.getLength()) - p.getWeight())));

            GraphPath<GraphNode, GraphEdge> dijkstraPath = shortestByPair.get(entry.getKey());

            for (GraphPath<GraphNode, GraphEdge> path : paths) {
                boolean isShortest = path.equals(dijkstraPath);
                printSinglePath(graph, path, edgeRiskScores, isShortest, false);
            }
        }

        System.out.println();
    }

    private static void printSinglePath(Graph<GraphNode, GraphEdge> graph, GraphPath<GraphNode, GraphEdge> path, Map<GraphEdge, Double> edgeRiskScores, boolean markAsShortest, boolean markAsMostDangerous) {
        double rawScore = (10.0 * path.getLength()) - path.getWeight();
        String severity = getPathSeverity(rawScore, path.getLength());
        String tag = markAsMostDangerous ? RED + " [MOST DANGEROUS]" + RESET :
                (markAsShortest ? GREEN + " [SHORTEST]" + RESET : "");

        log.info("     Hops: {} | Risk: {} ({}){}",
                path.getLength(),
                String.format("%.1f", rawScore),
                severity,
                tag);

        for (GraphEdge edge : path.getEdgeList()) {
            GraphNode src = graph.getEdgeSource(edge);
            GraphNode tgt = graph.getEdgeTarget(edge);
            log.info("       {} --[{}]--> {}  (weight: {})",
                    src.getId(),
                    edge.getRelationship(),
                    tgt.getId(),
                    String.format("%.1f", 10.0 - edgeRiskScores.getOrDefault(edge, 0.0)));
        }
    }

    private static String pairKey(GraphPath<GraphNode, GraphEdge> path) {
        return path.getStartVertex().getId() + " → " + path.getEndVertex().getId();
    }

    private static void printChokePointAnalysis(ChokePointResult chokeResult) {
        List<RankedChokePoint> ranked = chokeResult.rankedChokePoints();
        if (ranked == null || ranked.isEmpty()) {
            return;
        }

        log.info("{}--- CRITICAL CHOKE POINTS (Top Priority for Fixes) ---{}", CYAN, RESET);
        ranked.stream()
                .limit(5)
                .forEach(cp -> log.info(
                        "  • [{}] type={} -> paths={}, weighted score={}",
                        cp.node().getId(),
                        cp.node().getType(),
                        cp.pathsSevered(),
                        String.format("%.1f", cp.weightedScore())
                ));
        System.out.println();
    }

    private static void printPrivilegeLoopAnalysis(List<List<GraphNode>> privilegeLoops) {
        log.info("{}--- PRIVILEGE ESCALATION LOOPS ---{}", CYAN, RESET);

        if (privilegeLoops == null || privilegeLoops.isEmpty()) {
            log.info("  • No privilege escalation loops detected.");
            System.out.println();
            return;
        }

        log.info("  • Total loops detected: {}", privilegeLoops.size());

        int loopIndex = 1;
        for (List<GraphNode> loop : privilegeLoops) {
            if (loop == null || loop.isEmpty()) {
                continue;
            }

            List<String> nodeIds = loop.stream().map(GraphNode::getId).toList();

            String loopPath = String.join(" -> ", nodeIds);
            if (nodeIds.size() > 1) {
                loopPath += " -> " + nodeIds.getFirst();
            }

            String severityHint = classifyLoopSeverity(loop);

            if (privilegeLoops.size() > 1) {
                log.info("  {}. Severity={} | Nodes={}", loopIndex++, severityHint, loop.size());
            } else {
                log.info("     Severity={} | Nodes={}", severityHint, loop.size());
            }
            log.info("     Path: {}", loopPath);
        }

        log.info("  • Recommended action: break at least one binding edge per loop to prevent cyclic privilege escalation.");
        System.out.println();
    }

    public static String classifyLoopSeverity(List<GraphNode> loop) {
        boolean hasBinding = false;
        boolean hasRole = false;
        boolean hasSA = false;

        for (GraphNode node : loop) {
            String type = node.getType();
            String lowerType = safeLower(type);

            if (!hasBinding && lowerType.contains("rolebinding")) {
                hasBinding = true;
            }
            if (!hasRole && ("role".equals(lowerType) || "clusterrole".equals(lowerType))) {
                hasRole = true;
            }
            if (!hasSA && "serviceaccount".equalsIgnoreCase(type)) {
                hasSA = true;
            }

            if (hasBinding && hasRole && hasSA) {
                return "HIGH";
            }
        }

        if (hasBinding && hasRole) {
            return "MEDIUM";
        }
        return "LOW";
    }

    private static void printBlastRadiusAnalysis(List<BlastRadiusResult> blastResults) {
        if (blastResults.isEmpty()) return;

        log.info("{}--- BLAST RADIUS HIGHLIGHTS ---{}", CYAN, RESET);
        for (BlastRadiusResult br : blastResults) {
            if (br.totalImpacted() == 0) continue;
            GraphNode source = br.source();
            String nodeId = source.getId();
            String nodeType = source.getType();

            if ("Pod".equals(nodeType)) {
                log.info("Source: [{}] type={} (Radius: {} hops, CVSS={})",
                        nodeId,
                        nodeType,
                        br.radius(),
                        String.format("%.1f", source.getRiskScore()));
            } else {
                log.info("Source: [{}] type={} (Radius: {} hops)", nodeId, nodeType, br.radius());
            }

            br.rankedImpactedAssets().forEach(asset -> {
                GraphNode node = asset.node();
                String assetId = node.getId();
                String assetType = node.getType();
                if ("Pod".equals(assetType)) {
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

    private static void printPodVulnerabilityDetails(Map<String, List<String>> podCVEIds) {
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

        // Sort CVSS desc (from pod id/name hints if unavailable -> 0), then CVE count desc, then pod id
        vulnerablePods = new ArrayList<>(vulnerablePods);
        vulnerablePods.sort(
                Comparator.<Map.Entry<String, List<String>>>comparingInt(e -> e.getValue().size()).reversed()
                        .thenComparing(Map.Entry::getKey, String.CASE_INSENSITIVE_ORDER)
        );

        log.info("{}--- POD VULNERABILITY DETAILS ---{}", CYAN, RESET);

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

    private static void printRemediationPlans(List<RemediationPlan> plans) {
        if (plans.isEmpty()) return;
        log.info("{}--- PROPOSED REMEDIATION ACTIONS ---{}", CYAN, RESET);
        for (RemediationPlan plan : plans) {
            log.info("{}Fix for Choke Point: {}[{}]", GREEN, RESET, plan.nodeId());
            log.info("  Rationale: {}", plan.rationale());

            if (!plan.auditCommands().isEmpty()) {
                log.info("  {}Audit first:{}", BOLD, RESET);
                plan.auditCommands().forEach(cmd -> log.info("     {}", cmd));
            }
            if (!plan.enforceCommands().isEmpty()) {
                log.info("  {}Then enforce:{}", BOLD, RESET);
                plan.enforceCommands().forEach(cmd -> log.info("{}     {}{}", YELLOW, cmd, RESET));
            }
            if (plan.containsDestructiveAction()) {
                log.warn("{}  [!] WARNING: Plan contains destructive actions.{}", BOLD_RED, RESET);
            }
        }
        System.out.println();
    }

    private static String getPathSeverity(double totalScore, int hops) {
        if (hops == 0) return "UNKNOWN";
        double averageRisk = totalScore / hops;
        if (averageRisk >= RiskConfig.PATH_RISK_CRITICAL) return "CRITICAL";
        if (averageRisk >= RiskConfig.PATH_RISK_HIGH) return "HIGH";
        if (averageRisk >= RiskConfig.PATH_RISK_MEDIUM) return "MEDIUM";
        return "LOW";
    }

    private static void printFooter(boolean hasExports) {
        log.info("{}{}{}", BOLD, "=".repeat(80), RESET);
        log.info(" End of Analysis Summary");
        log.info("{}{}{}", BOLD, "=".repeat(80), RESET);

        if (!hasExports) {
            System.out.println();
            log.info("{}{}╔ NEXT STEPS ╗{}", CYAN, BOLD, RESET);
            log.info("{}├─ Visualization:{}  {} {}", BOLD, RESET, GREEN + "add -o html" + RESET, "(visual graph)");
            log.info("{}├─ Documentation:{} {} {}", BOLD, RESET, GREEN + "add -o pdf" + RESET, "(PDF report)");
            log.info("{}├─ Analysis:{}      {} {}", BOLD, RESET, GREEN + "add --show-all-paths" + RESET, "(all attack paths)");
            log.info("{}└─ Scope:{}         {} {}", BOLD, RESET, GREEN + "add --max-hops <N>" + RESET, "(default: 3)");
            log.info("{}{}{}\n", BOLD, "=".repeat(80), RESET);
        }
    }
}