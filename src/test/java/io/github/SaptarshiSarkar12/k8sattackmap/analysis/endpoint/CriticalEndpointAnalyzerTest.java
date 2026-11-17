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

import io.github.SaptarshiSarkar12.k8sattackmap.analysis.graph.AttackPathDiscovery;
import io.github.SaptarshiSarkar12.k8sattackmap.analysis.AnalysisInput;
import io.github.SaptarshiSarkar12.k8sattackmap.helper.TestGraphHelper;
import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphEdge;
import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphNode;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.jgrapht.Graph;

import java.util.List;
import java.util.Set;

class CriticalEndpointAnalyzerTest {
    @Test
    void reportsReachableEndpointDepthAndPath() {
        Graph<GraphNode, GraphEdge> graph = TestGraphHelper.buildLinearGraph(3);
        GraphNode source = graph.vertexSet().stream()
                .filter(node -> node.getId().endsWith("pod-0")).findFirst().orElseThrow();
        String endpointId = "Pod:default:pod-3";
        AnalysisInput input = new AnalysisInput(graph, Set.of(source), Set.of(graph.vertexSet().stream()
                .filter(node -> node.getId().equals(endpointId)).findFirst().orElseThrow()), 3, Set.of(endpointId));

        var paths = AttackPathDiscovery.findAttackPaths(input);
        List<CriticalEndpointExposure> results = CriticalEndpointAnalyzer.analyze(
                graph, Set.of(source), Set.of(endpointId), paths.allPossiblePaths(), paths.edgeRiskScores());

        CriticalEndpointExposure result = results.getFirst();
        Assertions.assertEquals(CriticalEndpointStatus.REACHABLE, result.status());
        Assertions.assertEquals(3, result.depth());
        Assertions.assertEquals(endpointId, result.endpointId());
        Assertions.assertFalse(result.contributingNodes().isEmpty());
        Assertions.assertTrue(result.patchPriorityScore() > 0);
    }

    @Test
    void distinguishesMissingAndDisconnectedEndpoints() {
        GraphNode source = TestGraphHelper.makeNode("Pod:default:source", "Pod");
        GraphNode disconnected = TestGraphHelper.makeNode("Pod:default:disconnected", "Pod");
        Graph<GraphNode, GraphEdge> graph = TestGraphHelper.buildGraph(List.of(source, disconnected), List.of());
        String disconnectedId = disconnected.getId();
        var paths = AttackPathDiscovery.findAttackPaths(
                new AnalysisInput(graph, Set.of(source), Set.of(), 3));

        List<CriticalEndpointExposure> results = CriticalEndpointAnalyzer.analyze(
                graph, Set.of(source), Set.of("Pod:default:absent", disconnectedId),
                paths.allPossiblePaths(), paths.edgeRiskScores());

        Assertions.assertEquals(CriticalEndpointStatus.NOT_FOUND, results.get(0).status());
        Assertions.assertEquals(CriticalEndpointStatus.UNREACHABLE, results.get(1).status());
    }
}
