package io.github.SaptarshiSarkar12.k8sattackmap.util;

import org.junit.jupiter.api.Assertions;
import io.github.SaptarshiSarkar12.k8sattackmap.helper.TestGraphHelper;
import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphNode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;

@DisplayName("NodeFinder finds nodes by ID with various matching scenarios")
class NodeFinderTest {
    private GraphNode podNode;
    private GraphNode secretNode;
    private Map<String, GraphNode> lookup;

    @BeforeEach
    void setUp() {
        podNode = TestGraphHelper.makeNode("Pod:default:web", "Pod");
        secretNode = TestGraphHelper.makeNode("Secret:default:db-creds", "Secret");
        GraphNode saNode = TestGraphHelper.makeNode("ServiceAccount:default:app", "ServiceAccount");

        lookup = Map.of(
                podNode.getId(), podNode,
                secretNode.getId(), secretNode,
                saNode.getId(), saNode
        );
    }

    @Test
    @DisplayName("finds node by exact ID")
    void shouldReturnNodeWhenExactId() {
        Set<GraphNode> result = NodeFinder.findNodesById(lookup, Set.of("Pod:default:web"));
        Assertions.assertEquals(1, result.size());
        Assertions.assertTrue(result.contains(podNode));
    }

    @Test
    @DisplayName("finds multiple nodes by their IDs")
    void shouldResolveAllProvidedIds() {
        Set<GraphNode> result = NodeFinder.findNodesById(lookup, Set.of("Pod:default:web", "Secret:default:db-creds"));
        Assertions.assertEquals(2, result.size());
        Assertions.assertTrue(result.contains(podNode) && result.contains(secretNode));
    }

    @Test
    @DisplayName("finds node with case-insensitive ID matching")
    void shouldFallbackToCaseInsensitiveMatch() {
        Set<GraphNode> result = NodeFinder.findNodesById(lookup, Set.of("pod:default:web"));
        Assertions.assertEquals(1, result.size());
        Assertions.assertTrue(result.contains(podNode));
    }

    @Test
    @DisplayName("returns empty set for non-existent ID")
    void shouldSkipMissingIdGracefully() {
        Set<GraphNode> result = NodeFinder.findNodesById(lookup, Set.of("Node:default:worker-1"));
        Assertions.assertTrue(result.isEmpty());
    }

    @Test
    @DisplayName("skips null IDs without throwing exception")
    void shouldSkipNullIds() {
        Set<String> ids = new HashSet<>();
        ids.add(null);
        ids.add("Pod:default:web");
        Set<GraphNode> result = NodeFinder.findNodesById(lookup, ids);
        Assertions.assertEquals(1, result.size());
        Assertions.assertTrue(result.contains(podNode));
    }

    @Test
    @DisplayName("returns empty set for empty ID input")
    void shouldReturnEmptyForEmptyIds() {
        Set<GraphNode> result = NodeFinder.findNodesById(lookup, Set.of());
        Assertions.assertTrue(result.isEmpty());
    }

    @Test
    @DisplayName("returns only matched nodes when mixed valid and invalid IDs provided")
    void shouldReturnOnlyFoundForMixedIds() {
        Set<GraphNode> result = NodeFinder.findNodesById(lookup, Set.of("Pod:default:web", "NonExistent:default:ghost"));
        Assertions.assertEquals(1, result.size());
        Assertions.assertTrue(result.contains(podNode));
    }
}