package io.github.SaptarshiSarkar12.k8sattackmap.analysis;

import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphNode;
import io.github.SaptarshiSarkar12.k8sattackmap.model.RankedChokePoint;

import java.util.List;
import java.util.Map;

public record ChokePointResult(List<RankedChokePoint> rankedChokePoints, Map<GraphNode, Integer> chokePointFrequencies, Map<GraphNode, Double> chokePointWeightedScores) {
    public ChokePointResult {
        if (rankedChokePoints == null) {
            rankedChokePoints = List.of();
        }
        if (chokePointFrequencies == null) {
            chokePointFrequencies = Map.of();
        }
        if (chokePointWeightedScores == null) {
            chokePointWeightedScores = Map.of();
        }
    }
}
