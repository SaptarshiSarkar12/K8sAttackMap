package io.github.SaptarshiSarkar12.k8sattackmap.model;

import org.junit.jupiter.api.Assertions;
import io.github.SaptarshiSarkar12.k8sattackmap.helper.TestGraphHelper;
import org.jgrapht.Graph;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

@DisplayName("ClusterGraphFactory builds a graph")
class ClusterGraphFactoryTest {

    @Test
    @DisplayName("retains entry-point nodes and prunes non-entry nodes without incoming edges")
    void retainsEntryPointsAndPrunesIsolatedNonEntryNodes() {
        GraphNode pod = TestGraphHelper.makeNode("Pod:default:web", "Pod");
        GraphNode serviceAccount = TestGraphHelper.makeNode("ServiceAccount:default:app", "ServiceAccount");
        GraphNode role = TestGraphHelper.makeNode("Role:default:reader", "Role");

        ClusterGraphData data = new ClusterGraphData();
        data.setNodes(List.of(pod, serviceAccount, role));
        data.setEdges(List.of());

        Graph<GraphNode, GraphEdge> graph = ClusterGraphFactory.buildGraph(data);

        Assertions.assertEquals(Set.of(pod, serviceAccount), graph.vertexSet());
    }

    @Test
    @DisplayName("adds an edge when both endpoints exist")
    void addsEdgeWhenBothEndpointsExist() {
        GraphNode pod = TestGraphHelper.makeNode("Pod:default:web", "Pod");
        GraphNode serviceAccount = TestGraphHelper.makeNode("ServiceAccount:default:app", "ServiceAccount");

        GraphEdge edge = TestGraphHelper.makeEdge(EdgeType.USES_SA);
        edge.setSource(pod.getId());
        edge.setTarget(serviceAccount.getId());

        ClusterGraphData data = new ClusterGraphData();
        data.setNodes(List.of(pod, serviceAccount));
        data.setEdges(List.of(edge));

        Graph<GraphNode, GraphEdge> graph = ClusterGraphFactory.buildGraph(data);

        Assertions.assertEquals(1, graph.edgeSet().size());
        GraphEdge addedEdge = graph.edgeSet().iterator().next();
        Assertions.assertEquals(EdgeType.USES_SA, addedEdge.getRelationship());
    }

    @Test
    @DisplayName("populates node lookup on ClusterGraphData")
    void populatesNodeLookup() {
        GraphNode pod = TestGraphHelper.makeNode("Pod:default:web", "Pod");

        ClusterGraphData data = new ClusterGraphData();
        data.setNodes(List.of(pod));
        data.setEdges(List.of());

        ClusterGraphFactory.buildGraph(data);

        Assertions.assertNotNull(data.getNodeLookup());
        Assertions.assertEquals(pod, data.getNodeLookup().get(pod.getId()));
    }

    @Test
    @DisplayName("returns an empty graph for empty input")
    void emptyDataReturnsEmptyGraph() {
        ClusterGraphData data = new ClusterGraphData();
        data.setNodes(List.of());
        data.setEdges(List.of());

        Graph<GraphNode, GraphEdge> graph = ClusterGraphFactory.buildGraph(data);

        Assertions.assertTrue(graph.vertexSet().isEmpty());
        Assertions.assertTrue(graph.edgeSet().isEmpty());
    }
}