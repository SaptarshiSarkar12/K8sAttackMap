package io.github.SaptarshiSarkar12.k8sattackmap.analysis;

import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphEdge;
import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphNode;
import io.github.SaptarshiSarkar12.k8sattackmap.model.RankedChokePoint;
import org.jgrapht.GraphPath;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.DoubleAdder;
import java.util.concurrent.atomic.LongAdder;

public class ChokePointIdentifier {
    private static final double FREQUENCY_WEIGHT = 1.0;
    private static final double RISK_WEIGHT = 0.5;

    public static ChokePointResult identifyChokePoints(List<GraphPath<GraphNode, GraphEdge>> allPossiblePaths) {
        if (allPossiblePaths == null || allPossiblePaths.isEmpty()) {
            return new ChokePointResult(List.of(), Map.of(), Map.of());
        }

        Map<GraphNode, Integer> frequencyCounts = countNodeOccurrences(allPossiblePaths);
        Map<GraphNode, Double> weightedScores = computeWeightedScores(allPossiblePaths);
        List<RankedChokePoint> ranked = buildRankedChokePoints(frequencyCounts, weightedScores);
        return new ChokePointResult(ranked, frequencyCounts, weightedScores);
    }

    private static List<RankedChokePoint> buildRankedChokePoints(Map<GraphNode, Integer> frequencyCounts, Map<GraphNode, Double> weightedScores) {
        List<GraphNode> candidates = new ArrayList<>(frequencyCounts.keySet());

        candidates.sort(
                Comparator.<GraphNode>comparingDouble(node -> compositeScore(node, frequencyCounts, weightedScores))
                        .reversed()
                        .thenComparing(node -> frequencyCounts.getOrDefault(node, 0), Comparator.reverseOrder())
                        .thenComparing(GraphNode::getId, String.CASE_INSENSITIVE_ORDER)
        );

        List<RankedChokePoint> ranked = new ArrayList<>(candidates.size());
        for (GraphNode node : candidates) {
            ranked.add(new RankedChokePoint(
                    node,
                    frequencyCounts.getOrDefault(node, 0),
                    weightedScores.getOrDefault(node, 0.0)
            ));
        }
        return ranked;
    }

    private static double compositeScore(GraphNode node, Map<GraphNode, Integer> frequencyCounts, Map<GraphNode, Double> weightedScores) {
        double frequencyPart = frequencyCounts.getOrDefault(node, 0) * FREQUENCY_WEIGHT;
        double riskPart = weightedScores.getOrDefault(node, 0.0) * RISK_WEIGHT;
        return frequencyPart + riskPart;
    }

    private static Map<GraphNode, Integer> countNodeOccurrences(List<GraphPath<GraphNode, GraphEdge>> allPaths) {
        Map<GraphNode, LongAdder> counts = new ConcurrentHashMap<>(Math.max(16, allPaths.size() / 2));

        allPaths.parallelStream().forEach(path -> {
            List<GraphNode> nodes = path.getVertexList();
            if (nodes == null || nodes.size() < 3) {
                return;
            }
            for (int i = 1; i < nodes.size() - 1; i++) {
                counts.computeIfAbsent(nodes.get(i), k -> new LongAdder()).increment();
            }
        });

        Map<GraphNode, Integer> result = new HashMap<>(counts.size());
        counts.forEach((node, adder) -> result.put(node, adder.intValue()));
        return result;
    }

    private static Map<GraphNode, Double> computeWeightedScores(List<GraphPath<GraphNode, GraphEdge>> allPaths) {
        Map<GraphNode, DoubleAdder> weighted = new ConcurrentHashMap<>(Math.max(16, allPaths.size() / 2));

        allPaths.parallelStream().forEach(path -> {
            List<GraphNode> nodes = path.getVertexList();
            if (nodes == null || nodes.size() < 3) {
                return;
            }

            double pathWeight = normalizedPathRisk(path);

            for (int i = 1; i < nodes.size() - 1; i++) {
                weighted.computeIfAbsent(nodes.get(i), k -> new DoubleAdder()).add(pathWeight);
            }
        });

        Map<GraphNode, Double> result = new HashMap<>(weighted.size());
        weighted.forEach((node, adder) -> result.put(node, adder.doubleValue()));
        return result;
    }

    private static double normalizedPathRisk(GraphPath<GraphNode, GraphEdge> path) {
        int length = Math.max(1, path.getLength());
        double raw = (10.0 * length) - path.getWeight();
        double normalized = raw / length;
        return Math.max(0.1, normalized);
    }
}