package io.github.SaptarshiSarkar12.k8sattackmap.analysis;

import java.util.List;

public record AnalysisResult(PathDiscoveryResult pathDiscoveryResult, List<BlastRadiusResult> blastRadiusResults, ChokePointResult chokePointResult, List<RemediationPlan> remediationPlans) {
}