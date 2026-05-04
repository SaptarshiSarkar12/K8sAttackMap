package io.github.SaptarshiSarkar12.k8sattackmap.analysis.graph;

import io.github.SaptarshiSarkar12.k8sattackmap.helper.TestGraphHelper;
import io.github.SaptarshiSarkar12.k8sattackmap.model.EdgeType;
import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphEdge;
import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphNode;
import org.jgrapht.Graph;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("PrivilegeLoopDetector finds RBAC escalation cycles")
class PrivilegeLoopDetectorTest {
    @Test
    @DisplayName("returns empty list for an acyclic graph")
    void shouldReturnEmptyForAcyclicGraph() {
        Graph<GraphNode, GraphEdge> graph = TestGraphHelper.buildLinearGraph(3);
        List<List<GraphNode>> loops = PrivilegeLoopDetector.findEscalationLoops(graph);
        assertTrue(loops.isEmpty());
    }

    @Test
    @DisplayName("detects a cycle containing RBAC edge types")
    void shouldDetectRbacCycle() {
        Graph<GraphNode, GraphEdge> graph = TestGraphHelper.buildRbacLoopGraph();
        List<List<GraphNode>> loops = PrivilegeLoopDetector.findEscalationLoops(graph);
        assertFalse(loops.isEmpty());
    }

    @Test
    @DisplayName("does not report a cycle composed entirely of non-RBAC edges")
    void shouldIgnoreNonRbacCycle() {
        GraphNode a = TestGraphHelper.makeNode("Pod:default:pod-a", "Pod");
        GraphNode b = TestGraphHelper.makeNode("Pod:default:pod-b", "Pod");
        GraphNode c = TestGraphHelper.makeNode("Pod:default:pod-c", "Pod");

        Graph<GraphNode, GraphEdge> graph = TestGraphHelper.buildGraph(
                List.of(a, b, c),
                List.of(
                        TestGraphHelper.makeEdge(a.getId(), b.getId(), EdgeType.MANAGES),
                        TestGraphHelper.makeEdge(b.getId(), c.getId(), EdgeType.MANAGES),
                        TestGraphHelper.makeEdge(c.getId(), a.getId(), EdgeType.MANAGES)
                )
        );

        List<List<GraphNode>> loops = PrivilegeLoopDetector.findEscalationLoops(graph);
        assertTrue(loops.isEmpty());
    }

    @Test
    @DisplayName("returns empty list for a graph with a single node and no edges")
    void shouldReturnEmptyForSingleNodeGraph() {
        GraphNode node = TestGraphHelper.makeNode("ServiceAccount:default:sa", "ServiceAccount");
        Graph<GraphNode, GraphEdge> graph = TestGraphHelper.buildGraph(List.of(node), List.of());
        assertTrue(PrivilegeLoopDetector.findEscalationLoops(graph).isEmpty());
    }

    @Test
    @DisplayName("each detected loop contains only nodes from the original graph")
    void detectedLoopNodesAreInOriginalGraph() {
        Graph<GraphNode, GraphEdge> graph = TestGraphHelper.buildRbacLoopGraph();
        List<List<GraphNode>> loops = PrivilegeLoopDetector.findEscalationLoops(graph);

        for (List<GraphNode> loop : loops) {
            for (GraphNode node : loop) {
                assertTrue(graph.containsVertex(node),
                        "Loop node " + node.getId() + " must exist in the original graph");
            }
        }
    }
}