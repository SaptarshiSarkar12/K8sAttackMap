package io.github.SaptarshiSarkar12.k8sattackmap.analysis.chokepoint;

import org.junit.jupiter.api.Assertions;
import io.github.SaptarshiSarkar12.k8sattackmap.helper.TestGraphHelper;
import io.github.SaptarshiSarkar12.k8sattackmap.model.EdgeType;
import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphEdge;
import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphNode;
import org.jgrapht.Graph;
import org.jgrapht.GraphPath;
import org.jgrapht.alg.shortestpath.AllDirectedPaths;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

@DisplayName("ChokePointIdentifier identifies nodes that appear most frequently on attack paths")
class ChokePointIdentifierTest {
    @Test
    @DisplayName("returns empty result for null input")
    void shouldReturnEmptyResultForNullInput() {
        ChokePointResult result = ChokePointIdentifier.identifyChokePoints(null);
        Assertions.assertTrue(result.rankedChokePoints().isEmpty());
    }

    @Test
    @DisplayName("returns empty result for empty path list")
    void shouldReturnEmptyResultForEmptyPaths() {
        ChokePointResult result = ChokePointIdentifier.identifyChokePoints(List.of());
        Assertions.assertTrue(result.rankedChokePoints().isEmpty());
    }

    @Test
    @DisplayName("does not identify choke points in a 2-node path (no intermediate nodes)")
    void shouldNotFindChokePointsInTwoNodePath() {
        Graph<GraphNode, GraphEdge> graph = TestGraphHelper.buildLinearGraph(1);
        GraphNode src = graph.vertexSet().stream().filter(n -> n.getId().endsWith("pod-0")).findFirst().orElseThrow();
        GraphNode tgt = graph.vertexSet().stream().filter(n -> n.getId().endsWith("pod-1")).findFirst().orElseThrow();

        List<GraphPath<GraphNode, GraphEdge>> paths = new AllDirectedPaths<>(graph).getAllPaths(src, tgt, true, 5);
        ChokePointResult result = ChokePointIdentifier.identifyChokePoints(paths);

        Assertions.assertTrue(result.rankedChokePoints().isEmpty(),
                "A path with only source and target has no intermediate choke point");
    }

    @Test
    @DisplayName("identifies a shared intermediate node as the top-ranked choke point")
    void shouldRankSharedIntermediateNodeFirst() {
        // Two paths both pass through "mid": src1 -> mid -> tgt and src2 -> mid -> tgt
        GraphNode src1 = TestGraphHelper.makeNode("Pod:default:src1", "Pod");
        GraphNode src2 = TestGraphHelper.makeNode("Pod:default:src2", "Pod");
        GraphNode mid  = TestGraphHelper.makeNode("ServiceAccount:default:mid", "ServiceAccount");
        GraphNode tgt  = TestGraphHelper.makeNode("Secret:default:tgt", "Secret");

        Graph<GraphNode, GraphEdge> graph = TestGraphHelper.buildGraph(
                List.of(src1, src2, mid, tgt),
                List.of(
                        TestGraphHelper.makeEdge(src1.getId(), mid.getId(), EdgeType.USES_SA),
                        TestGraphHelper.makeEdge(src2.getId(), mid.getId(), EdgeType.USES_SA),
                        TestGraphHelper.makeEdge(mid.getId(),  tgt.getId(), EdgeType.USES_SECRET)
                )
        );

        AllDirectedPaths<GraphNode, GraphEdge> allPaths = new AllDirectedPaths<>(graph);
        List<GraphPath<GraphNode, GraphEdge>> paths = new ArrayList<>();
        paths.addAll(allPaths.getAllPaths(src1, tgt, true, 5));
        paths.addAll(allPaths.getAllPaths(src2, tgt, true, 5));

        ChokePointResult result = ChokePointIdentifier.identifyChokePoints(paths);

        Assertions.assertFalse(result.rankedChokePoints().isEmpty());
        Assertions.assertEquals(mid, result.rankedChokePoints().getFirst().node(),
                "The shared intermediate node should be the top-ranked choke point");
    }

    @Test
    @DisplayName("frequency count reflects how many paths pass through each intermediate node")
    void shouldCountIntermediateNodeFrequencyCorrectly() {
        GraphNode src = TestGraphHelper.makeNode("Pod:default:src", "Pod");
        GraphNode mid = TestGraphHelper.makeNode("ServiceAccount:default:mid", "ServiceAccount");
        GraphNode tgt = TestGraphHelper.makeNode("Secret:default:tgt", "Secret");

        Graph<GraphNode, GraphEdge> graph = TestGraphHelper.buildGraph(
                List.of(src, mid, tgt),
                List.of(
                        TestGraphHelper.makeEdge(src.getId(), mid.getId(), EdgeType.USES_SA),
                        TestGraphHelper.makeEdge(mid.getId(), tgt.getId(), EdgeType.USES_SECRET)
                )
        );

        List<GraphPath<GraphNode, GraphEdge>> paths =
                new AllDirectedPaths<>(graph).getAllPaths(src, tgt, true, 5);
        ChokePointResult result = ChokePointIdentifier.identifyChokePoints(paths);

        Assertions.assertEquals(1, result.chokePointFrequencies().get(mid), "mid should appear in exactly 1 path");
    }
}