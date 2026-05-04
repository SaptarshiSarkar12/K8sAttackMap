package io.github.SaptarshiSarkar12.k8sattackmap.analysis.graph;

import io.github.SaptarshiSarkar12.k8sattackmap.analysis.AnalysisInput;
import io.github.SaptarshiSarkar12.k8sattackmap.helper.TestGraphHelper;
import io.github.SaptarshiSarkar12.k8sattackmap.model.EdgeType;
import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphEdge;
import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphNode;
import org.jgrapht.Graph;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("AttackPathDiscovery identifies attack paths between source and target nodes")
class AttackPathDiscoveryTest {
    @Test
    @DisplayName("returns empty result when source set is empty")
    void shouldReturnEmptyResultForEmptySources() {
        Graph<GraphNode, GraphEdge> graph = TestGraphHelper.buildLinearGraph(2);
        GraphNode target = graph.vertexSet().stream().filter(n -> n.getId().endsWith("pod-2")).findFirst().orElseThrow();

        AnalysisInput input = new AnalysisInput(graph, Set.of(), Set.of(target), 3);
        PathDiscoveryResult result = AttackPathDiscovery.findAttackPaths(input);

        assertTrue(result.allPossiblePaths().isEmpty());
        assertTrue(result.dijkstraPaths().isEmpty());
        assertNull(result.mostDangerousPath());
    }

    @Test
    @DisplayName("returns empty result when target set is empty")
    void shouldReturnEmptyResultForEmptyTargets() {
        Graph<GraphNode, GraphEdge> graph = TestGraphHelper.buildLinearGraph(2);
        GraphNode source = graph.vertexSet().stream().filter(n -> n.getId().endsWith("pod-0")).findFirst().orElseThrow();

        AnalysisInput input = new AnalysisInput(graph, Set.of(source), Set.of(), 3);
        PathDiscoveryResult result = AttackPathDiscovery.findAttackPaths(input);

        assertTrue(result.allPossiblePaths().isEmpty());
        assertNull(result.mostDangerousPath());
    }

    @Test
    @DisplayName("skips source-target pair when source and target are the same node")
    void shouldSkipWhenSourceEqualsTarget() {
        Graph<GraphNode, GraphEdge> graph = TestGraphHelper.buildLinearGraph(1);
        GraphNode node = graph.vertexSet().stream().filter(n -> n.getId().endsWith("pod-0")).findFirst().orElseThrow();

        AnalysisInput input = new AnalysisInput(graph, Set.of(node), Set.of(node), 3);
        PathDiscoveryResult result = AttackPathDiscovery.findAttackPaths(input);

        assertNull(result.mostDangerousPath());
    }

    @Test
    @DisplayName("finds a path between connected source and target nodes")
    void shouldFindPathBetweenConnectedSourceAndTarget() {
        Graph<GraphNode, GraphEdge> graph = TestGraphHelper.buildLinearGraph(2);
        GraphNode source = graph.vertexSet().stream().filter(n -> n.getId().endsWith("pod-0")).findFirst().orElseThrow();
        GraphNode target = graph.vertexSet().stream().filter(n -> n.getId().endsWith("pod-2")).findFirst().orElseThrow();

        AnalysisInput input = new AnalysisInput(graph, Set.of(source), Set.of(target), 5);
        PathDiscoveryResult result = AttackPathDiscovery.findAttackPaths(input);

        assertNotNull(result.mostDangerousPath());
        assertEquals(source, result.mostDangerousPath().getStartVertex());
        assertEquals(target, result.mostDangerousPath().getEndVertex());
    }

    @Test
    @DisplayName("returns null mostDangerousPath when source and target are not connected")
    void shouldReturnNullMostDangerousPathForDisconnectedNodes() {
        GraphNode source = TestGraphHelper.makeNode("Pod:default:src", "Pod");
        GraphNode target = TestGraphHelper.makeNode("Secret:default:tgt", "Secret");
        Graph<GraphNode, GraphEdge> graph = TestGraphHelper.buildGraph(List.of(source, target), List.of());

        AnalysisInput input = new AnalysisInput(graph, Set.of(source), Set.of(target), 3);
        PathDiscoveryResult result = AttackPathDiscovery.findAttackPaths(input);

        assertNull(result.mostDangerousPath());
    }

    @Test
    @DisplayName("populates edge risk scores for all edges in the graph")
    void shouldPopulateEdgeRiskScores() {
        Graph<GraphNode, GraphEdge> graph = TestGraphHelper.buildLinearGraph(2);
        GraphNode source = graph.vertexSet().stream().filter(n -> n.getId().endsWith("pod-0")).findFirst().orElseThrow();
        GraphNode target = graph.vertexSet().stream().filter(n -> n.getId().endsWith("pod-2")).findFirst().orElseThrow();

        AnalysisInput input = new AnalysisInput(graph, Set.of(source), Set.of(target), 5);
        PathDiscoveryResult result = AttackPathDiscovery.findAttackPaths(input);

        assertFalse(result.edgeRiskScores().isEmpty());
        assertEquals(graph.edgeSet().size(), result.edgeRiskScores().size());
    }

    @Test
    @DisplayName("most dangerous path has the lowest friction density among all discovered paths")
    void mostDangerousPathHasLowestFrictionDensity() {
        // Build: src --MANAGES--> mid --MANAGES--> target (2 hops)
        // Also:  src --MOUNTS_SECRET--> target (1 hop, lower friction)
        GraphNode src = TestGraphHelper.makeNode("Pod:default:src", "Pod");
        GraphNode mid = TestGraphHelper.makeNode("Pod:default:mid", "Pod");
        GraphNode target = TestGraphHelper.makeNode("Secret:default:tgt", "Secret");

        Graph<GraphNode, GraphEdge> graph = TestGraphHelper.buildGraph(
                List.of(src, mid, target),
                List.of(
                        TestGraphHelper.makeEdge(src.getId(), mid.getId(), EdgeType.MANAGES),
                        TestGraphHelper.makeEdge(mid.getId(), target.getId(), EdgeType.MANAGES),
                        TestGraphHelper.makeEdge(src.getId(), target.getId(), EdgeType.MOUNTS_SECRET)
                )
        );

        AnalysisInput input = new AnalysisInput(graph, Set.of(src), Set.of(target), 5);
        PathDiscoveryResult result = AttackPathDiscovery.findAttackPaths(input);

        assertNotNull(result.mostDangerousPath());
        assertEquals(src, result.mostDangerousPath().getStartVertex());
        assertEquals(target, result.mostDangerousPath().getEndVertex());
        // The direct MOUNTS_SECRET edge has lower friction per hop than two MANAGES hops
        assertEquals(1, result.mostDangerousPath().getLength());
    }
}