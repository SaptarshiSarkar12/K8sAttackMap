package io.github.SaptarshiSarkar12.k8sattackmap.helper;

import io.github.SaptarshiSarkar12.k8sattackmap.model.ClusterGraphData;
import io.github.SaptarshiSarkar12.k8sattackmap.model.ClusterGraphFactory;
import io.github.SaptarshiSarkar12.k8sattackmap.model.EdgeType;
import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphEdge;
import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphNode;
import io.github.SaptarshiSarkar12.k8sattackmap.model.SecurityFacts;
import org.jgrapht.Graph;

import java.util.List;

/**
 * Factory helpers for building {@link GraphNode}, {@link GraphEdge}, and
 * {@link Graph} instances in tests without boilerplate.
 */
public final class TestGraphHelper {
    private TestGraphHelper() {
    }

    /** Creates a node with the given ID and type and a risk score of 0.0. */
    public static GraphNode makeNode(String id, String type) {
        return makeNode(id, type, 0.0);
    }

    /** Creates a node with the given ID, type, and risk score. */
    public static GraphNode makeNode(String id, String type, double riskScore) {
        GraphNode node = new GraphNode();
        node.setId(id);
        node.setType(type);
        node.setRiskScore(riskScore);
        // derive namespace and name from the id (format: type:namespace:name)
        String[] parts = id.split(":", 3);
        if (parts.length >= 2) node.setNamespace(parts[1]);
        if (parts.length >= 3) node.setName(parts[2]);
        node.setSecurityFacts(new SecurityFacts());
        return node;
    }

    /**
     * Creates a node with a fully populated {@link SecurityFacts} supplied by
     * the caller — useful when a test needs specific security flags.
     */
    public static GraphNode makeNodeWithFacts(String id, String type, double riskScore, SecurityFacts facts) {
        GraphNode node = makeNode(id, type, riskScore);
        node.setSecurityFacts(facts);
        return node;
    }

    /**
     * Creates an edge with no source/target pre-set; caller assigns them afterwards.
     * Useful when the test only cares about the relationship type.
     */
    public static GraphEdge makeEdge(EdgeType relationship) {
        GraphEdge edge = new GraphEdge();
        edge.setRelationship(relationship);
        return edge;
    }

    /** Creates a directed edge between two node IDs with the given relationship. */
    public static GraphEdge makeEdge(String sourceId, String targetId, EdgeType relationship) {
        GraphEdge edge = new GraphEdge();
        edge.setSource(sourceId);
        edge.setTarget(targetId);
        edge.setRelationship(relationship);
        return edge;
    }

    /**
     * Builds a JGraphT {@link Graph} from the provided nodes and edges via
     * {@link ClusterGraphFactory}. Nodes with in-degree zero and a non-entrypoint
     * type will be pruned (matching production behaviour).
     */
    public static Graph<GraphNode, GraphEdge> buildGraph(List<GraphNode> nodes, List<GraphEdge> edges) {
        ClusterGraphData data = new ClusterGraphData();
        data.setNodes(nodes);
        data.setEdges(edges);
        return ClusterGraphFactory.buildGraph(data);
    }

    /**
     * Builds a straight-line graph of {@code length} hops:
     * {@code Pod:default:pod-0 → Pod:default:pod-1 → … → Pod:default:pod-N}
     * connected by {@link EdgeType#CAN_ACCESS} edges, where N = length. All nodes have a risk score of 5.0
     */
    public static Graph<GraphNode, GraphEdge> buildLinearGraph(int length) {
        List<GraphNode> nodes = new java.util.ArrayList<>();
        List<GraphEdge> edges = new java.util.ArrayList<>();

        for (int i = 0; i <= length; i++) {
            nodes.add(makeNode("Pod:default:pod-" + i, "Pod", 5.0));
        }
        for (int i = 0; i < length; i++) {
            edges.add(makeEdge(nodes.get(i).getId(), nodes.get(i + 1).getId(), EdgeType.CAN_ACCESS));
        }
        return buildGraph(nodes, edges);
    }

    /**
     * Builds a three-node RBAC loop:
     * {@code ServiceAccount → RoleBinding → ClusterRole → ServiceAccount}
     * using {@link EdgeType#BOUND_TO} edges (an RBAC edge type that satisfies
     * {@link io.github.SaptarshiSarkar12.k8sattackmap.analysis.graph.PrivilegeLoopDetector}).
     */
    public static Graph<GraphNode, GraphEdge> buildRbacLoopGraph() {
        GraphNode sa = makeNode("ServiceAccount:default:loop-sa", "ServiceAccount");
        GraphNode rb = makeNode("RoleBinding:default:loop-rb", "RoleBinding");
        GraphNode role = makeNode("ClusterRole:cluster-scoped:loop-role", "ClusterRole");

        List<GraphEdge> edges = List.of(
                makeEdge(sa.getId(), rb.getId(), EdgeType.BOUND_TO),
                makeEdge(rb.getId(), role.getId(), EdgeType.BOUND_TO),
                makeEdge(role.getId(), sa.getId(), EdgeType.CAN_ACCESS)
        );
        return buildGraph(List.of(sa, rb, role), edges);
    }
}