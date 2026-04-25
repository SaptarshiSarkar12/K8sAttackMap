package io.github.SaptarshiSarkar12.k8sattackmap.model;

public record RankedChokePoint(
        GraphNode node,
        int pathsSevered,
        double weightedScore
) {
}