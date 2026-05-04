package io.github.SaptarshiSarkar12.k8sattackmap.model;

import io.github.SaptarshiSarkar12.k8sattackmap.helper.TestGraphHelper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("GraphNode calculates intrinsic friction and equality correctly")
class GraphNodeTest {
    @DisplayName("Passive resource types have zero intrinsic friction")
    @ParameterizedTest(name = "{0} should return 0.0")
    @ValueSource(strings = {
            "Secret", "ConfigMap",
            "ServiceAccount",
            "Service", "Ingress", "NetworkPolicy"
    })
    void testPassiveTypeReturnsZeroFriction(String type) {
        GraphNode node = TestGraphHelper.makeNode("Resource:default:x", type, 0.0);
        assertEquals(0.0, node.getIntrinsicFriction(), 1e-9);
    }

    @DisplayName("RBAC resource types have moderate intrinsic friction")
    @ParameterizedTest(name = "{0} should return 3.0")
    @ValueSource(strings = {
            "Role", "ClusterRole",
            "RoleBinding", "ClusterRoleBinding"
    })
    void testRbacTypeReturnsModerateFriction(String type) {
        GraphNode node = TestGraphHelper.makeNode("Resource:default:x", type, 0.0);
        assertEquals(3.0, node.getIntrinsicFriction(), 1e-9);
    }

    @DisplayName("Workload friction is calculated as 10.0 minus risk score")
    @ParameterizedTest(name = "risk {0} should give friction {1}")
    @CsvSource({
            "0.0, 10.0",
            "5.0, 5.0",
            "10.0, 0.0"
    })
    void testWorkloadFrictionCalculation(double riskScore, double expectedFriction) {
        GraphNode node = TestGraphHelper.makeNode("Pod:default:web", "Pod", riskScore);
        assertEquals(expectedFriction, node.getIntrinsicFriction(), 1e-9);
    }

    @DisplayName("Equality uses the id field")
    @Test
    void testEqualsSameId() {
        GraphNode a = TestGraphHelper.makeNode("Pod:default:web", "Pod", 0.0);
        GraphNode b = TestGraphHelper.makeNode("Pod:default:web", "Pod", 9.9);
        assertEquals(a, b);
    }

    @DisplayName("Different ids are not equal")
    @Test
    void testNotEqualsDifferentId() {
        GraphNode a = TestGraphHelper.makeNode("Pod:default:web", "Pod");
        GraphNode b = TestGraphHelper.makeNode("Pod:default:api", "Pod");
        assertNotEquals(a, b);
    }
}