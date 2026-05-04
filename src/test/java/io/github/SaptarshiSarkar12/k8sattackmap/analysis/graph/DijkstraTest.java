package io.github.SaptarshiSarkar12.k8sattackmap.analysis.graph;

import io.github.SaptarshiSarkar12.k8sattackmap.helper.TestGraphHelper;
import io.github.SaptarshiSarkar12.k8sattackmap.model.EdgeType;
import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphEdge;
import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphNode;
import org.jgrapht.Graph;
import org.jgrapht.GraphPath;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Dijkstra finds shortest weighted paths in a directed graph")
class DijkstraTest {
    private Dijkstra dijkstraWithUniformWeights(Graph<GraphNode, GraphEdge> graph) {
        Map<GraphEdge, Double> weights = new HashMap<>();
        for (GraphEdge e : graph.edgeSet()) {
            weights.put(e, 1.0);
        }
        return new Dijkstra(graph, weights);
    }

    @Test
    @DisplayName("returns a path between two directly connected nodes")
    void shouldFindPathBetweenConnectedNodes() {
        Graph<GraphNode, GraphEdge> graph = TestGraphHelper.buildLinearGraph(1);
        List<GraphNode> nodes = List.copyOf(graph.vertexSet());
        GraphNode source = nodes.stream().filter(n -> n.getId().endsWith("pod-0")).findFirst().orElseThrow();
        GraphNode target = nodes.stream().filter(n -> n.getId().endsWith("pod-1")).findFirst().orElseThrow();

        Dijkstra dijkstra = dijkstraWithUniformWeights(graph);
        GraphPath<GraphNode, GraphEdge> path = dijkstra.findShortestPath(source, target);

        assertNotNull(path);
        assertEquals(source, path.getStartVertex());
        assertEquals(target, path.getEndVertex());
    }

    @Test
    @DisplayName("returns null when source and target are not connected")
    void shouldReturnNullForDisconnectedNodes() {
        GraphNode a = TestGraphHelper.makeNode("Pod:default:pod-a", "Pod");
        GraphNode b = TestGraphHelper.makeNode("Pod:default:pod-b", "Pod");
        Graph<GraphNode, GraphEdge> graph = TestGraphHelper.buildGraph(List.of(a, b), List.of());

        Dijkstra dijkstra = dijkstraWithUniformWeights(graph);

        assertNull(dijkstra.findShortestPath(a, b));
    }

    @Test
    @DisplayName("chooses the path with lower total weight when two routes exist")
    void shouldChooseLowerWeightPath() {
        GraphNode src = TestGraphHelper.makeNode("Pod:default:src", "Pod");
        GraphNode mid = TestGraphHelper.makeNode("Pod:default:mid", "Pod");
        GraphNode target = TestGraphHelper.makeNode("Pod:default:tgt", "Pod");

        GraphEdge directEdge = TestGraphHelper.makeEdge(src.getId(), target.getId(), EdgeType.CAN_ACCESS);
        GraphEdge hopEdge1 = TestGraphHelper.makeEdge(src.getId(), mid.getId(), EdgeType.CAN_ACCESS);
        GraphEdge hopEdge2 = TestGraphHelper.makeEdge(mid.getId(), target.getId(), EdgeType.CAN_ACCESS);

        Graph<GraphNode, GraphEdge> graph = TestGraphHelper.buildGraph(
                List.of(src, mid, target),
                List.of(directEdge, hopEdge1, hopEdge2)
        );

        // Direct edge weight = 10.0; two-hop route weight = 1.0 + 1.0 = 2.0
        Map<GraphEdge, Double> weights = Map.of(directEdge, 10.0, hopEdge1, 1.0, hopEdge2, 1.0);
        Dijkstra dijkstra = new Dijkstra(graph, weights);

        GraphPath<GraphNode, GraphEdge> path = dijkstra.findShortestPath(src, target);

        assertNotNull(path);
        assertEquals(2, path.getLength(), "Should take the 2-hop route, not the direct high-weight edge");
    }

    @Test
    @DisplayName("returns path of length 1 for directly adjacent nodes")
    void shouldReturnSingleHopPathForAdjacentNodes() {
        Graph<GraphNode, GraphEdge> graph = TestGraphHelper.buildLinearGraph(3);
        GraphNode source = graph.vertexSet().stream().filter(n -> n.getId().endsWith("pod-0")).findFirst().orElseThrow();
        GraphNode next = graph.vertexSet().stream().filter(n -> n.getId().endsWith("pod-1")).findFirst().orElseThrow();

        Dijkstra dijkstra = dijkstraWithUniformWeights(graph);

        assertEquals(1, dijkstra.findShortestPath(source, next).getLength());
    }
}