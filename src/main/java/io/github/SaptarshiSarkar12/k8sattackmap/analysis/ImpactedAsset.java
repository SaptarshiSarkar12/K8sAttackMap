package io.github.SaptarshiSarkar12.k8sattackmap.analysis;

import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphNode;

import java.util.List;

public record ImpactedAsset(
        GraphNode node,
        int hopsFromSource,
        double impactScore,
        ImpactSeverity severity,
        List<String> riskReasons
) {
}