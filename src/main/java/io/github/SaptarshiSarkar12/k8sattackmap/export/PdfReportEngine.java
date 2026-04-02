package io.github.SaptarshiSarkar12.k8sattackmap.export;

import com.openhtmltopdf.pdfboxout.PdfRendererBuilder;
import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphEdge;
import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphNode;
import io.github.SaptarshiSarkar12.k8sattackmap.util.AppConstants;
import org.jgrapht.GraphPath;

import java.io.FileOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;

public class PdfReportEngine {

    public static void generatePdf(
            String outputPath,
            String clusterContext,
            int totalPaths,
            int entryPoints,
            int loops,
            GraphNode chokePoint,
            int pathsSevered,
            GraphPath<GraphNode, GraphEdge> absoluteWorstPath,
            List<List<GraphNode>> escalationLoops) throws Exception {

        // 1. Load HTML Template from Classpath
        InputStream templateStream = PdfReportEngine.class.getResourceAsStream(AppConstants.PDF_TEMPLATE_RESOURCE_PATH);
        if (templateStream == null) {
            throw new RuntimeException("Could not find report-template.html in resources.");
        }
        String html = new String(templateStream.readAllBytes(), StandardCharsets.UTF_8);

        // 2. Calculate Dynamic Metrics
        String dateStr = new SimpleDateFormat("MMMM dd, yyyy - HH:mm z").format(new Date());
        String riskGrade = totalPaths > 10 ? "CRITICAL (F)" : (totalPaths > 0 ? "HIGH (D)" : "SAFE (A)");
        int impactPercentage = totalPaths == 0 ? 0 : (int) (((double) pathsSevered / totalPaths) * 100);

        // 3. Format the Choke Point Command
        String chokeType = "resource";
        String chokeName = "unknown";
        String chokeNamespace = "default";
        if (chokePoint != null) {
            String[] parts = chokePoint.getId().split(":");
            if (parts.length >= 3) {
                chokeType = parts[0].toLowerCase();
                chokeNamespace = parts[1];
                chokeName = parts[2];
            }
        }

        // 4. Build Attack Path Table Rows
        StringBuilder rows = new StringBuilder();
        if (absoluteWorstPath != null) {
            int hop = 1;
            for (GraphEdge edge : absoluteWorstPath.getEdgeList()) {
                GraphNode source = absoluteWorstPath.getGraph().getEdgeSource(edge);
                GraphNode target = absoluteWorstPath.getGraph().getEdgeTarget(edge);
                rows.append("<tr>")
                    .append("<td>").append(hop++).append("</td>")
                    .append("<td>").append(source.getId()).append("</td>")
                    .append("<td style='color:#e53e3e; font-weight:bold;'>").append(edge.getRelationship()).append("</td>")
                    .append("<td>").append(target.getId()).append("</td>")
                    .append("</tr>");
            }
        } else {
            rows.append("<tr><td colspan='4' class='text-center'>No critical paths detected.</td></tr>");
        }

        StringBuilder loopRows = new StringBuilder();
        if (escalationLoops != null && !escalationLoops.isEmpty()) {
            int loopId = 1;
            for (List<GraphNode> cycle : escalationLoops) {
                StringBuilder pathBuilder = new StringBuilder();
                for (int i = 0; i < cycle.size(); i++) {
                    pathBuilder.append("<span style='color:#e53e3e; font-weight:bold;'>")
                            .append(cycle.get(i).getId())
                            .append("</span>");
                    String cssArrow = " <span style='display:inline-block; width:12px; height:2px; background-color:#e53e3e; margin-bottom:4px;'></span>" +
                            "<span style='display:inline-block; width:0; height:0; border-top:4px solid transparent; border-bottom:4px solid transparent; border-left:6px solid #e53e3e; margin-bottom:1px; margin-right:4px;'></span> ";

                    pathBuilder.append(cssArrow);
                }
                // Visually close the loop back to the first node
                pathBuilder.append("<span style='color:#e53e3e; font-weight:bold;'>")
                        .append(cycle.getFirst().getId())
                        .append("</span>");

                loopRows.append("<tr>")
                        .append("<td>#").append(loopId++).append("</td>")
                        .append("<td>").append(pathBuilder).append("</td>")
                        .append("</tr>");
            }
        } else {
            loopRows.append("<tr><td colspan='2' class='text-center text-green'>No privilege escalation loops detected.</td></tr>");
        }

        // 5. Inject Data into HTML Placeholders
        html = html.replace("{{REPORT_DATE}}", dateStr)
                   .replace("{{CLUSTER_CONTEXT}}", clusterContext)
                   .replace("{{RISK_GRADE}}", riskGrade)
                   .replace("{{TOTAL_PATHS}}", String.valueOf(totalPaths))
                   .replace("{{ENTRY_POINTS_COUNT}}", String.valueOf(entryPoints))
                   .replace("{{LOOP_COUNT}}", String.valueOf(loops))
                   .replace("{{CHOKE_POINT_IMPACT}}", String.valueOf(impactPercentage))
                   .replace("{{CHOKE_POINT_ID}}", chokePoint != null ? chokePoint.getId() : "None")
                   .replace("{{REMEDIATION_ACTION}}", "Sever this connection to restrict lateral movement.")
                   .replace("{{CHOKE_POINT_TYPE}}", chokeType)
                   .replace("{{CHOKE_POINT_NAME}}", chokeName)
                   .replace("{{CHOKE_POINT_NAMESPACE}}", chokeNamespace)
                   .replace("{{ATTACK_PATH_ROWS}}", rows.toString())
                   .replace("{{ESCALATION_LOOPS_ROWS}}", loopRows.toString());

        // 6. Render HTML to PDF
        try (FileOutputStream os = new FileOutputStream(outputPath)) {
            PdfRendererBuilder builder = new PdfRendererBuilder();
            builder.useFastMode();
            builder.withHtmlContent(html, null);
            builder.toStream(os);
            builder.run();
        }
    }
}