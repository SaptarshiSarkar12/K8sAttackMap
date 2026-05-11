package io.github.SaptarshiSarkar12.k8sattackmap.analysis;

import io.github.SaptarshiSarkar12.k8sattackmap.analysis.blast.BlastRadiusResult;
import io.github.SaptarshiSarkar12.k8sattackmap.analysis.chokepoint.ChokePointResult;
import io.github.SaptarshiSarkar12.k8sattackmap.analysis.graph.PathDiscoveryResult;
import io.github.SaptarshiSarkar12.k8sattackmap.analysis.remediation.RemediationPlan;
import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphNode;

import java.util.List;

/**
 * Immutable result payload aggregating all security analysis outcomes.
 * <p>
 * Produced by {@link AnalysisOrchestrator#performAnalysis(AnalysisInput)} and consumed by
 * {@link io.github.SaptarshiSarkar12.k8sattackmap.export.AnalysisSummaryPrinter},
 * {@link io.github.SaptarshiSarkar12.k8sattackmap.export.ExportService}, and test harnesses.
 *
 * @param pathDiscoveryResult discovered attack paths from sources to targets (Dijkstra results)
 * @param blastRadiusResults impact analysis showing affected resources downstream from compromises
 * @param chokePointResult detected choke points (resources that block or filter multiple paths)
 * @param privilegeLoops detected cycles enabling privilege escalation loops
 * @param remediationPlans actionable remediation strategies for blocking paths or hardening resources
 */
public record AnalysisResult(
        PathDiscoveryResult pathDiscoveryResult,
        List<BlastRadiusResult> blastRadiusResults,
        ChokePointResult chokePointResult,
        List<List<GraphNode>> privilegeLoops,
        List<RemediationPlan> remediationPlans
) {
}