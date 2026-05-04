package io.github.SaptarshiSarkar12.k8sattackmap.model;

import io.github.SaptarshiSarkar12.k8sattackmap.helper.TestGraphHelper;
import org.jgrapht.Graph;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("ClusterGraphFactory builds a graph that")
class ClusterGraphFactoryTest {

    @Test
    @DisplayName("keeps entry-point nodes and prunes non-entry-point nodes without incoming edges")
    void buildGraph_keepsEntryPointsAndPrunesOthers() {
        GraphNode pod = TestGraphHelper.makeNode("Pod:default:web", "Pod");
        GraphNode serviceAccount = TestGraphHelper.makeNode("ServiceAccount:default:app", "ServiceAccount");
        GraphNode role = TestGraphHelper.makeNode("Role:default:reader", "Role");

        ClusterGraphData data = new ClusterGraphData();
        data.setNodes(List.of(pod, serviceAccount, role));
        data.setEdges(List.of());

        Graph<GraphNode, GraphEdge> graph = ClusterGraphFactory.buildGraph(data);

        assertEquals(Set.of(pod, serviceAccount), graph.vertexSet());
    }

    @Test
    @DisplayName("adds an edge when both endpoints exist")
    void buildGraph_addsEdge() {
        GraphNode pod = TestGraphHelper.makeNode("Pod:default:web", "Pod");
        GraphNode serviceAccount = TestGraphHelper.makeNode("ServiceAccount:default:app", "ServiceAccount");

        GraphEdge edge = TestGraphHelper.makeEdge(EdgeType.USES_SA);
        edge.setSource(pod.getId());
        edge.setTarget(serviceAccount.getId());

        ClusterGraphData data = new ClusterGraphData();
        data.setNodes(List.of(pod, serviceAccount));
        data.setEdges(List.of(edge));

        Graph<GraphNode, GraphEdge> graph = ClusterGraphFactory.buildGraph(data);

        assertEquals(1, graph.edgeSet().size());
        GraphEdge addedEdge = graph.edgeSet().iterator().next();
        assertEquals(EdgeType.USES_SA, addedEdge.getRelationship());
    }

    @Test
    @DisplayName("skips edges when either endpoint is missing")
    void buildGraph_skipsEdgesWithMissingEndpoints() {
        GraphNode pod = TestGraphHelper.makeNode("Pod:default:web", "Pod");
        GraphNode serviceAccount = TestGraphHelper.makeNode("ServiceAccount:default:app", "ServiceAccount");

        GraphEdge missingTarget = TestGraphHelper.makeEdge(EdgeType.USES_SA);
        missingTarget.setSource(pod.getId());
        missingTarget.setTarget("ServiceAccount:default:ghost");

        GraphEdge missingSource = TestGraphHelper.makeEdge(EdgeType.USES_SA);
        missingSource.setSource("Pod:default:ghost");
        missingSource.setTarget(serviceAccount.getId());

        ClusterGraphData data = new ClusterGraphData();
        data.setNodes(List.of(pod, serviceAccount));
        data.setEdges(List.of(missingTarget, missingSource));

        Graph<GraphNode, GraphEdge> graph = ClusterGraphFactory.buildGraph(data);

        assertTrue(graph.edgeSet().isEmpty());
    }

    @Test
    @DisplayName("populates nodeLookup on ClusterGraphData")
    void buildGraph_populatesNodeLookup() {
        GraphNode pod = TestGraphHelper.makeNode("Pod:default:web", "Pod");

        ClusterGraphData data = new ClusterGraphData();
        data.setNodes(List.of(pod));
        data.setEdges(List.of());

        ClusterGraphFactory.buildGraph(data);

        assertNotNull(data.getNodeLookup());
        assertEquals(pod, data.getNodeLookup().get(pod.getId()));
    }

    @Test
    @DisplayName("returns an empty graph for empty input")
    void buildGraph_emptyData_returnsEmptyGraph() {
        ClusterGraphData data = new ClusterGraphData();
        data.setNodes(List.of());
        data.setEdges(List.of());

        Graph<GraphNode, GraphEdge> graph = ClusterGraphFactory.buildGraph(data);

        assertTrue(graph.vertexSet().isEmpty());
        assertTrue(graph.edgeSet().isEmpty());
    }
}