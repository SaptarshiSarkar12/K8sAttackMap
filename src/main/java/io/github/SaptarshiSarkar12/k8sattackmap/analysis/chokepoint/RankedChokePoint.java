package io.github.SaptarshiSarkar12.k8sattackmap.analysis.chokepoint;

import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphNode;

public record RankedChokePoint(
        GraphNode node,
        int pathsSevered,
        double weightedScore
) {
}