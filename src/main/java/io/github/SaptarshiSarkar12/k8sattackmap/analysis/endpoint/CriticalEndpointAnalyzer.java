/*
 * Copyright 2026 Ivo Rosa
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.github.SaptarshiSarkar12.k8sattackmap.analysis.endpoint;

import io.github.SaptarshiSarkar12.k8sattackmap.analysis.graph.Dijkstra;
import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphEdge;
import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphNode;
import org.jgrapht.Graph;
import org.jgrapht.GraphPath;

import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Measures how exposed explicitly selected endpoints are from discovered entry points.
 */
public final class CriticalEndpointAnalyzer {
    private CriticalEndpointAnalyzer() {
    }

    public static List<CriticalEndpointExposure> analyze(
            Graph<GraphNode, GraphEdge> graph,
            Set<GraphNode> sourceNodes,
            Set<String> endpointIds,
            List<GraphPath<GraphNode, GraphEdge>> discoveredPaths,
            Map<GraphEdge, Double> edgeRiskScores) {
        Dijkstra dijkstra = new Dijkstra(graph, edgeRiskScores);
        Map<String, GraphNode> nodesById = graph.vertexSet().stream()
                .collect(java.util.stream.Collectors.toMap(node -> node.getId().toLowerCase(Locale.ROOT),
                        node -> node, (first, _) -> first));

        return endpointIds.stream()
                .sorted()
                .map(endpointId -> assessEndpoint(endpointId, nodesById, sourceNodes, discoveredPaths, dijkstra))
                .sorted(Comparator.comparingDouble(CriticalEndpointExposure::patchPriorityScore).reversed()
                        .thenComparing(CriticalEndpointExposure::endpointId))
                .toList();
    }

    private static CriticalEndpointExposure assessEndpoint(
            String endpointId,
            Map<String, GraphNode> nodesById,
            Set<GraphNode> sourceNodes,
            List<GraphPath<GraphNode, GraphEdge>> discoveredPaths,
            Dijkstra dijkstra) {
        GraphNode endpoint = nodesById.get(endpointId.toLowerCase(Locale.ROOT));
        if (endpoint == null) {
            return new CriticalEndpointExposure(endpointId, null, CriticalEndpointStatus.NOT_FOUND,
                    -1, Double.POSITIVE_INFINITY, 0, List.of(), 0);
        }

        GraphPath<GraphNode, GraphEdge> shortest = sourceNodes.stream()
                .filter(dijkstraGraphNode -> dijkstraGraphNode != null)
                .map(source -> dijkstra.findShortestPath(source, endpoint))
                .filter(path -> path != null)
                .min(Comparator.comparingDouble(GraphPath::getWeight))
                .orElse(null);

        long alternativePaths = discoveredPaths.stream()
                .filter(path -> endpoint.equals(path.getEndVertex()))
                .count();

        if (shortest == null) {
            return new CriticalEndpointExposure(endpointId, endpoint, CriticalEndpointStatus.UNREACHABLE,
                    -1, Double.POSITIVE_INFINITY, alternativePaths, List.of(), 0);
        }

        double priority = (100.0 / (1.0 + shortest.getWeight())) + (alternativePaths * 10.0);
        return new CriticalEndpointExposure(endpointId, endpoint, CriticalEndpointStatus.REACHABLE,
                shortest.getLength(), shortest.getWeight(), alternativePaths, shortest.getVertexList(), priority);
    }
}
