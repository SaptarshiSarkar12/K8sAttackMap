package io.github.SaptarshiSarkar12.k8sattackmap.analysis;

import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphNode;

import java.util.List;
import java.util.Map;

public record BlastRadiusResult(
        GraphNode source,
        int radius,
        int totalImpacted,
        Map<ImpactSeverity, Long> severityCounts,
        List<ImpactedAsset> rankedImpactedAssets
) {
}