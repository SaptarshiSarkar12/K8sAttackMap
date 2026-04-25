package io.github.SaptarshiSarkar12.k8sattackmap.analysis;

import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphNode;

import java.util.List;

public record AnalysisResult(
        PathDiscoveryResult pathDiscoveryResult,
        List<BlastRadiusResult> blastRadiusResults,
        ChokePointResult chokePointResult,
        List<List<GraphNode>> privilegeLoops,
        List<RemediationPlan> remediationPlans
) {

}