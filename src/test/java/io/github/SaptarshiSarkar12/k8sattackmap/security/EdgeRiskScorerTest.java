package io.github.SaptarshiSarkar12.k8sattackmap.security;

import io.github.SaptarshiSarkar12.k8sattackmap.helper.TestGraphHelper;
import io.github.SaptarshiSarkar12.k8sattackmap.model.EdgeType;
import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphEdge;
import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphNode;
import io.github.SaptarshiSarkar12.k8sattackmap.model.SecurityFacts;
import org.jgrapht.Graph;
import org.jgrapht.graph.DirectedWeightedMultigraph;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("EdgeRiskScorer Tests")
class EdgeRiskScorerTest {
    private double calculateEdgeWeight(GraphNode source, GraphNode target, EdgeType edgeType) {
        GraphEdge edge = TestGraphHelper.makeEdge(edgeType);
        edge.setSource(source.getId());
        edge.setTarget(target.getId());

        List<GraphNode> nodes = List.of(source, target);
        List<GraphEdge> edges = List.of(edge);
        Graph<GraphNode, GraphEdge> graph = TestGraphHelper.buildGraph(nodes, edges);

        Map<GraphEdge, Double> weights = EdgeRiskScorer.calculateEdgeWeights(graph);
        return weights.get(edge);
    }

    @Test
    @DisplayName("Should clamp all edge weights between 0.1 and 25.0")
    void testEdgeWeightsClamped() {
        GraphNode pod = TestGraphHelper.makeNode("Pod:default:web", "Pod", 0.0);
        GraphNode secret = TestGraphHelper.makeNode("Secret:default:db-creds", "Secret", 0.0);

        Graph<GraphNode, GraphEdge> graph = new DirectedWeightedMultigraph<>(GraphEdge.class);
        graph.addVertex(pod);
        graph.addVertex(secret);

        GraphEdge e1 = TestGraphHelper.makeEdge(EdgeType.MOUNTS_SECRET);
        e1.setSource(pod.getId());
        e1.setTarget(secret.getId());
        graph.addEdge(pod, secret, e1);

        GraphEdge e2 = TestGraphHelper.makeEdge(EdgeType.MANAGES);
        e2.setSource(pod.getId());
        e2.setTarget(secret.getId());
        graph.addEdge(pod, secret, e2);

        Map<GraphEdge, Double> weights = EdgeRiskScorer.calculateEdgeWeights(graph);
        for (double weight : weights.values()) {
            assertTrue(weight >= 0.1 && weight <= 25.0,
                    String.format("Weight %.2f must be between 0.1 and 25.0", weight));
        }
    }

    @Test
    @DisplayName("Should assign lower weight to MOUNTS_SECRET than MANAGES")
    void testMountsSecretLowerFrictionThanManages() {
        GraphNode pod = TestGraphHelper.makeNode("Pod:default:web", "Pod");
        GraphNode secret = TestGraphHelper.makeNode("Secret:default:db-creds", "Secret");

        double mountsSecret = calculateEdgeWeight(pod, secret, EdgeType.MOUNTS_SECRET);
        double manages = calculateEdgeWeight(pod, secret, EdgeType.MANAGES);

        assertTrue(mountsSecret < manages);
    }

    @Test
    @DisplayName("Should assign lower weight to NODE_ESCAPE than USES_SA")
    void testNodeEscapeLowerFrictionThanUsesSa() {
        GraphNode pod = TestGraphHelper.makeNode("Pod:default:web", "Pod");
        GraphNode sa = TestGraphHelper.makeNode("ServiceAccount:default:app", "ServiceAccount");

        double nodeEscape = calculateEdgeWeight(pod, sa, EdgeType.NODE_ESCAPE);
        double usesSa = calculateEdgeWeight(pod, sa, EdgeType.USES_SA);

        assertTrue(nodeEscape < usesSa);
    }

    @Test
    @DisplayName("Should assign lower weight to HOST_PATH_ACCESS than USES_CONFIGMAP")
    void testHostPathAccessLowerFrictionThanUsesConfigmap() {
        GraphNode pod = TestGraphHelper.makeNode("Pod:default:web", "Pod");
        GraphNode configMap = TestGraphHelper.makeNode("ConfigMap:default:cfg", "ConfigMap");

        double hostPath = calculateEdgeWeight(pod, configMap, EdgeType.HOST_PATH_ACCESS);
        double configmap = calculateEdgeWeight(pod, configMap, EdgeType.USES_CONFIGMAP);

        assertTrue(hostPath < configmap);
    }

    @Test
    @DisplayName("Should reduce weight when source is a privileged container")
    void testPrivilegedSourceReducesFriction() {
        SecurityFacts privilegedFacts = new SecurityFacts();
        privilegedFacts.setPrivilegedContainer(true);

        GraphNode privPod = TestGraphHelper.makeNodeWithFacts("Pod:default:priv", "Pod", 5.0, privilegedFacts);
        GraphNode normalPod = TestGraphHelper.makeNode("Pod:default:normal", "Pod", 5.0);
        GraphNode secret = TestGraphHelper.makeNode("Secret:default:s", "Secret");

        double frictionPriv = calculateEdgeWeight(privPod, secret, EdgeType.USES_SECRET);
        double frictionNormal = calculateEdgeWeight(normalPod, secret, EdgeType.USES_SECRET);

        assertTrue(frictionPriv < frictionNormal);
    }

    @Test
    @DisplayName("Should reduce weight when source has node-level surface exposure")
    void testNodeLevelSurfaceReducesFriction() {
        SecurityFacts nodeFacts = new SecurityFacts();
        nodeFacts.setNodeLevelSurface(true);

        GraphNode nodeSource = TestGraphHelper.makeNodeWithFacts("Node:cluster-scoped:worker-1", "Node", 0.0, nodeFacts);
        GraphNode normalSource = TestGraphHelper.makeNode("Pod:default:web", "Pod", 0.0);
        GraphNode secret = TestGraphHelper.makeNode("Secret:default:s", "Secret");

        double nodeWeight = calculateEdgeWeight(nodeSource, secret, EdgeType.CAN_ACCESS);
        double normalWeight = calculateEdgeWeight(normalSource, secret, EdgeType.CAN_ACCESS);

        assertTrue(nodeWeight < normalWeight);
    }

    @Test
    @DisplayName("Should reduce weight when target contains credential material")
    void testCredentialMaterialTargetReducesFriction() {
        SecurityFacts credentialFacts = new SecurityFacts();
        credentialFacts.setCredentialMaterial(true);

        GraphNode pod = TestGraphHelper.makeNode("Pod:default:web", "Pod");
        GraphNode credentialSecret = TestGraphHelper.makeNodeWithFacts("Secret:default:cred", "Secret", 0.0, credentialFacts);
        GraphNode plainSecret = TestGraphHelper.makeNode("Secret:default:plain", "Secret");

        double frictionCred = calculateEdgeWeight(pod, credentialSecret, EdgeType.USES_SECRET);
        double frictionPlain = calculateEdgeWeight(pod, plainSecret, EdgeType.USES_SECRET);

        assertTrue(frictionCred < frictionPlain);
    }

    @Test
    @DisplayName("Should reduce weight when target has wildcard RBAC permissions")
    void testWildcardRbacTargetReducesFriction() {
        SecurityFacts wildcardFacts = new SecurityFacts();
        wildcardFacts.setRbacWildcardVerb(true);

        SecurityFacts normalFacts = new SecurityFacts();

        GraphNode sa = TestGraphHelper.makeNode("ServiceAccount:default:app", "ServiceAccount");
        GraphNode wildcardRole = TestGraphHelper.makeNodeWithFacts("ClusterRole:cluster-scoped:wildcard", "ClusterRole", 0.0, wildcardFacts);
        GraphNode normalRole = TestGraphHelper.makeNodeWithFacts("ClusterRole:cluster-scoped:normal", "ClusterRole", 0.0, normalFacts);

        double frictionWildcard = calculateEdgeWeight(sa, wildcardRole, EdgeType.BOUND_TO);
        double frictionNormal = calculateEdgeWeight(sa, normalRole, EdgeType.BOUND_TO);

        assertTrue(frictionWildcard < frictionNormal);
    }

    @Test
    @DisplayName("Should return empty weights map for empty graph")
    void testEmptyGraphReturnsEmptyWeights() {
        Graph<GraphNode, GraphEdge> graph = TestGraphHelper.buildGraph(new ArrayList<>(), new ArrayList<>());
        Map<GraphEdge, Double> weights = EdgeRiskScorer.calculateEdgeWeights(graph);
        assertTrue(weights.isEmpty());
    }
}