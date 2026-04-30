package io.github.SaptarshiSarkar12.k8sattackmap.export;

import com.itextpdf.html2pdf.HtmlConverter;
import io.github.SaptarshiSarkar12.k8sattackmap.analysis.AnalysisResult;
import io.github.SaptarshiSarkar12.k8sattackmap.analysis.chokepoint.ChokePointResult;
import io.github.SaptarshiSarkar12.k8sattackmap.analysis.chokepoint.RankedChokePoint;
import io.github.SaptarshiSarkar12.k8sattackmap.analysis.graph.PathDiscoveryResult;
import io.github.SaptarshiSarkar12.k8sattackmap.analysis.remediation.RemediationPlan;
import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphEdge;
import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphNode;
import io.github.SaptarshiSarkar12.k8sattackmap.util.AppConstants;
import io.github.SaptarshiSarkar12.k8sattackmap.util.RiskConfig;
import io.github.SaptarshiSarkar12.k8sattackmap.util.TemplateStore;
import org.jgrapht.Graph;
import org.jgrapht.GraphPath;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileOutputStream;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.stream.Collectors;

public class PdfReportEngine {
    private static final Logger log = LoggerFactory.getLogger(PdfReportEngine.class);

    public static void exportPdfReport(AnalysisResult result, Graph<GraphNode, GraphEdge> graph, Set<GraphNode> sourceNodes, String clusterContext, Map<GraphEdge, Double> edgeRiskScores, Map<String, List<String>> podCVEIds, Map<String, GraphNode> nodeLookup) {
        try {
            PathDiscoveryResult pathResult = result.pathDiscoveryResult();
            ChokePointResult chokeResult = result.chokePointResult();

            List<List<GraphNode>> loops = result.privilegeLoops() == null ? List.of() : result.privilegeLoops();

            int totalPaths = pathResult == null || pathResult.allPossiblePaths() == null
                    ? 0
                    : pathResult.allPossiblePaths().size();
            GraphPath<GraphNode, GraphEdge> mostDangerousPath = pathResult == null ? null : pathResult.mostDangerousPath();
            Set<GraphNode> nodesOnCriticalPath = mostDangerousPath == null ? Set.of() : new HashSet<>(mostDangerousPath.getVertexList());

            List<RankedChokePoint> chokePoints = chokeResult == null || chokeResult.rankedChokePoints() == null
                    ? List.of()
                    : chokeResult.rankedChokePoints();
            List<RankedChokePoint> topChokePoints = chokePoints.stream().limit(5).toList();
            PdfReportData data = new PdfReportData(clusterContext, totalPaths, sourceNodes.size(), loops.size(), topChokePoints, mostDangerousPath, graph, loops, edgeRiskScores, podCVEIds, nodeLookup, nodesOnCriticalPath, result.remediationPlans());
            generatePdf(AppConstants.OUTPUT_PDF_FILENAME, data);

            log.info("PDF report exported to {}", AppConstants.OUTPUT_PDF_FILENAME);
        } catch (Exception e) {
            log.error("Failed to export PDF report.", e);
        }
    }

    public static void generatePdf(String outputPath, PdfReportData data) throws Exception {
        int totalPaths = data.totalPaths();

        List<RankedChokePoint> topChokePoints = data.topChokePoints();
        GraphNode topChokePoint = topChokePoints.isEmpty() ? null : topChokePoints.getFirst().node();
        int pathsSeveredByTopChoke = topChokePoints.isEmpty() ? 0 : topChokePoints.getFirst().pathsSevered();
        if (topChokePoint != null && (topChokePoint.getNamespace() == null || topChokePoint.getNamespace().isEmpty())) {
            topChokePoint.setNamespace("—");
        }

        // Calculate Dynamic Metrics
        String dateStr = new SimpleDateFormat("MMMM dd, yyyy - HH:mm z").format(new Date());
        String riskGrade = totalPaths > RiskConfig.PDF_GRADE_CRITICAL_PATHS ? "CRITICAL (F)" : (totalPaths > 0 ? "HIGH (D)" : "SAFE (A)");
        int impactPercentage = totalPaths == 0 ? 0 : (int) (((double) pathsSeveredByTopChoke / totalPaths) * 100);

        String chokeRows = buildChokePointRows(topChokePoints);
        String attackPathRows = buildAttackPathRows(data.worstPath(), data.edgeRiskScores(), data.graph());
        String remediationPlanCards = buildRemediationCards(data.remediationPlans());
        String loopRows = buildPrivilegeEscalationLoopRows(data.escalationLoops());
        String vulnerablePodsRows = buildVulnerablePodsRows(data.podCVEIds(), data.nodeLookup(), data.nodesOnCriticalPath());

        String riskGradeClass = switch (riskGrade) {
            case "CRITICAL (F)" -> "critical";
            case "HIGH (D)" -> "high";
            default -> "safe";
        };
        String pathsCardClass = totalPaths > RiskConfig.PDF_GRADE_CRITICAL_PATHS ? "danger" : totalPaths > 0 ? "warning" : "safe";
        String pathsValClass = totalPaths > RiskConfig.PDF_GRADE_CRITICAL_PATHS ? "red" : totalPaths > 0 ? "orange" : "green";
        String loopsCardClass = data.loopsCount() > 0 ? "danger" : "safe";
        String loopsValClass = data.loopsCount() > 0 ? "red" : "green";

        // Inject Data into HTML Placeholders
        String html = TemplateStore.PDF.replace("{{REPORT_DATE}}", dateStr)
                .replace("{{CLUSTER_CONTEXT}}", data.clusterContext())
                .replace("{{TOOL_VERSION}}", AppConstants.APP_VERSION)
                .replace("{{RISK_GRADE_COLOR_CLASS}}", riskGradeClass)
                .replace("{{PATHS_CARD_CLASS}}", pathsCardClass)
                .replace("{{PATHS_VAL_CLASS}}", pathsValClass)
                .replace("{{LOOPS_CARD_CLASS}}", loopsCardClass)
                .replace("{{LOOPS_VAL_CLASS}}", loopsValClass)
                .replace("{{RISK_GRADE}}", riskGrade)
                .replace("{{TOTAL_PATHS}}", String.valueOf(totalPaths))
                .replace("{{ENTRY_POINTS_COUNT}}", String.valueOf(data.entryPointsCount()))
                .replace("{{LOOPS_COUNT}}", String.valueOf(data.loopsCount()))
                .replace("{{CHOKE_POINT_IMPACT}}", String.valueOf(impactPercentage))
                .replace("{{CHOKE_POINT_ID}}", topChokePoint != null ? topChokePoint.getId() : "N/A")
                .replace("{{CHOKE_POINT_NAMESPACE}}", topChokePoint != null ? topChokePoint.getNamespace() : "N/A")
                .replace("{{CHOKE_POINT_TYPE}}", topChokePoint != null ? topChokePoint.getType() : "N/A")
                .replace("{{VULNERABLE_POD_COUNT}}", String.valueOf(data.podCVEIds().size()))
                .replace("{{CHOKE_POINT_TABLE_ROWS}}", chokeRows)
                .replace("{{ATTACK_PATH_TABLE_ROWS}}", attackPathRows)
                .replace("{{REMEDIATION_PLAN_CARDS}}", remediationPlanCards)
                .replace("{{ESCALATION_LOOPS_ROWS}}", loopRows)
                .replace("{{VULNERABLE_PODS_ROWS}}", vulnerablePodsRows);

        // Render HTML to PDF
        try (FileOutputStream os = new FileOutputStream(outputPath)) {
            HtmlConverter.convertToPdf(html, os);
        }
    }

    private static String buildChokePointRows(List<RankedChokePoint> chokePoints) {
        if (chokePoints.isEmpty()) {
            return "<tr><td colspan='4' class='text-center text-green'>No critical choke points identified.</td></tr>";
        }
        StringBuilder sb = new StringBuilder();
        int rank = 1;
        for (RankedChokePoint cp : chokePoints) {
            GraphNode node = cp.node();
            sb.append("<tr>")
                    .append("<td>#").append(rank++).append("</td>")
                    .append("<td>").append(node.getId()).append("</td>")
                    .append("<td>").append(node.getType() != null ? node.getType() : "Unknown").append("</td>")
                    .append("<td>").append(node.getNamespace() != null ? node.getNamespace() : "—").append("</td>")
                    .append("<td>").append(cp.pathsSevered()).append("</td>")
                    .append("<td>").append(String.format("%.1f", cp.weightedScore())).append("</td>")
                    .append("</tr>");
        }
        return sb.toString();
    }

    private static String buildAttackPathRows(GraphPath<GraphNode, GraphEdge> worstPath, Map<GraphEdge, Double> edgeRiskScores, Graph<GraphNode, GraphEdge> graph) {
        if (worstPath == null || worstPath.getVertexList() == null || worstPath.getVertexList().isEmpty()) {
            return "<tr><td colspan='4' class='text-center text-green'>No attack paths discovered.</td></tr>";
        }
        StringBuilder sb = new StringBuilder();
        int hop = 1;
        for (GraphEdge edge : worstPath.getEdgeList()) {
            GraphNode source = graph.getEdgeSource(edge);
            GraphNode target = graph.getEdgeTarget(edge);
            double riskScore = 10.0 - edgeRiskScores.getOrDefault(edge, 0.0);
            String colorClass = riskScore >= 7.0 ? "text-red-600 font-bold" : riskScore >= 4.0 ? "text-yellow-600 font-semibold" : "text-gray-600";

            sb.append("<tr>")
                    .append("<td>").append(hop++).append("</td>")
                    .append("<td>").append(source.getId()).append("</td>")
                    .append("<td>").append(edge.getRelationship()).append("</td>")
                    .append("<td>").append(target.getId()).append("</td>")
                    .append("<td class='").append(colorClass).append("'>").append(String.format("%.1f", riskScore)).append("</td>")
                    .append("</tr>");
        }
        return sb.toString();
    }

    private static String buildPrivilegeEscalationLoopRows(List<List<GraphNode>> loops) {
        if (loops.isEmpty()) {
            return "<tr><td colspan='4' class='text-center text-green'>No privilege escalation loops detected.</td></tr>";
        }
        StringBuilder sb = new StringBuilder();
        int loopId = 1;
        for (List<GraphNode> cycle : loops) {
            StringBuilder pathBuilder = new StringBuilder();
            for (GraphNode graphNode : cycle) {
                pathBuilder.append("<span style='color:#e53e3e; font-weight:bold;'>")
                        .append(graphNode.getId())
                        .append("</span>");
                String cssArrow = " <span style='display:inline-block; width:12px; height:2px; background-color:#e53e3e; margin-bottom:4px;'></span>" +
                        "<span style='display:inline-block; width:0; height:0; border-top:4px solid transparent; border-bottom:4px solid transparent; border-left:6px solid #e53e3e; margin-bottom:1px; margin-right:4px;'></span> ";

                pathBuilder.append(cssArrow);
            }
            // Visually close the loop back to the first node
            pathBuilder.append("<span style='color:#e53e3e; font-weight:bold;'>")
                    .append(cycle.getFirst().getId())
                    .append("</span>");
            String severity = AnalysisSummaryPrinter.classifyLoopSeverity(cycle);
            sb.append("<tr>")
                    .append("<td>#").append(loopId++).append("</td>")
                    .append("<td class='").append(privilegeEscalationSeverityClass(severity)).append("'>").append(severity).append("</td>")
                    .append("<td>").append(cycle.size()).append("</td>")
                    .append("<td>").append(pathBuilder).append("</td>")
                    .append("</tr>");
        }
        return sb.toString();
    }

    private static String privilegeEscalationSeverityClass(String severity) {
        return switch (severity) {
            case "CRITICAL" -> "text-red-600 font-bold";
            case "HIGH" -> "text-yellow-600 font-semibold";
            case "MEDIUM" -> "text-orange-600";
            default -> "text-gray-600 italic";
        };
    }

    private static String buildRemediationCards(List<RemediationPlan> plans) {
        if (plans.isEmpty()) {
            return "<p style='color:#555; font-style:italic;'>No remediation plans generated.</p>";
        }
        StringBuilder sb = new StringBuilder();
        int i = 1;
        for (RemediationPlan plan : plans) {
            String cardClass = plan.containsDestructiveAction() ? "remed-card destructive" : "remed-card";
            sb.append("<div class='").append(cardClass).append(" no-break'>");
            sb.append("<h3>").append(i++).append(". ").append(escHtml(plan.nodeId())).append("</h3>");
            sb.append("<div class='remed-rationale'>").append(escHtml(plan.rationale())).append("</div>");

            if (!plan.auditCommands().isEmpty()) {
                sb.append("<div class='remed-section-label'>Audit first (safe on live cluster)</div>");
                sb.append("<div class='cmd-block'>");
                for (String cmd : plan.auditCommands()) {
                    String cls = cmd.startsWith("#") ? "cmd-comment" : "";
                    if (cls.isEmpty()) sb.append(escHtml(cmd)).append("\n");
                    else sb.append("<span class='cmd-comment'>").append(escHtml(cmd)).append("</span>\n");
                }
                sb.append("</div>");
            }

            if (!plan.enforceCommands().isEmpty()) {
                sb.append("<div class='remed-section-label'>Then enforce</div>");
                sb.append("<div class='cmd-block'>");
                for (String cmd : plan.enforceCommands()) {
                    if (cmd.startsWith("#")) {
                        sb.append("<span class='cmd-comment'>").append(escHtml(cmd)).append("</span>\n");
                    } else {
                        sb.append(escHtml(cmd)).append("\n");
                    }
                }
                sb.append("</div>");
            }

            if (plan.containsDestructiveAction()) {
                sb.append("<div class='destructive-warn'>&#x26A0; Plan contains destructive actions — review before executing.</div>");
            }
            sb.append("</div>");
        }
        return sb.toString();
    }

    private static String buildVulnerablePodsRows(Map<String, List<String>> podCVEIds, Map<String, GraphNode> nodeLookup, Set<GraphNode> nodesOnCriticalPath) {
        return podCVEIds.entrySet().stream()
                .filter(e -> e.getValue() != null && !e.getValue().isEmpty())
                .sorted(Comparator.<Map.Entry<String, List<String>>>comparingInt(e -> e.getValue().size()).reversed())
                .limit(15)
                .map(e -> {
                    GraphNode node = nodeLookup.get(e.getKey());
                    String podName = node != null ? node.getId() : e.getKey();
                    String podNs = node != null ? node.getNamespace() : "—";
                    int count = e.getValue().size();
                    String countClass = count > 100 ? "cve-count-high" : count > 20 ? "cve-count-med" : "cve-count-low";

                    String cvss = node != null ? String.format("%.1f", node.getRiskScore()) : "—";
                    boolean onPath = node != null && nodesOnCriticalPath.contains(node);
                    String onPathCell = onPath ? "<span style='color:#e94560;font-weight:bold;'>[!] YES</span>" : "No";

                    return "<tr><td class='node-id'>" + podName + "</td>"
                            + "<td>" + podNs + "</td>"
                            + "<td class='" + countClass + "'>" + count + "</td>"
                            + "<td>" + cvss + "</td>"
                            + "<td>" + onPathCell + "</td></tr>";
                })
                .collect(Collectors.joining());
    }

    private static String escHtml(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;")
                .replace(">", "&gt;").replace("\"", "&quot;");
    }
}