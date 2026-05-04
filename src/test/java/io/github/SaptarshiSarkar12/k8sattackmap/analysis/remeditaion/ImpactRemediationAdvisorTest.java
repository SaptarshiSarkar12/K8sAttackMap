package io.github.SaptarshiSarkar12.k8sattackmap.analysis.remeditaion;

import io.github.SaptarshiSarkar12.k8sattackmap.analysis.blast.ImpactSeverity;
import io.github.SaptarshiSarkar12.k8sattackmap.analysis.blast.ImpactedAsset;
import io.github.SaptarshiSarkar12.k8sattackmap.analysis.remediation.ImpactRemediationAdvisor;
import io.github.SaptarshiSarkar12.k8sattackmap.helper.TestGraphHelper;
import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphNode;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("ImpactRemediationAdvisor recommends remediation actions based on node type")
class ImpactRemediationAdvisorTest {
    private static ImpactedAsset asset(GraphNode node) {
        return new ImpactedAsset(node, 1, 50.0, ImpactSeverity.HIGH, List.of());
    }

    @Test
    @DisplayName("recommends secret rotation for a Secret node")
    void shouldRecommendSecretRotationForSecret() {
        GraphNode secret = TestGraphHelper.makeNode("Secret:default:db-pass", "Secret");
        String action = ImpactRemediationAdvisor.recommendAction(asset(secret));
        assertTrue(action.toLowerCase().contains("rotat"), "Expected rotation advice for a Secret");
    }

    @Test
    @DisplayName("recommends RBAC least-privilege advice for a ClusterRoleBinding node")
    void shouldRecommendRbacAdviceForClusterRoleBinding() {
        GraphNode crb = TestGraphHelper.makeNode("ClusterRoleBinding:cluster-scoped:admin-crb", "ClusterRoleBinding");
        String action = ImpactRemediationAdvisor.recommendAction(asset(crb));
        assertTrue(action.toLowerCase().contains("rbac") || action.toLowerCase().contains("privilege"),
                "Expected RBAC advice for a ClusterRoleBinding");
    }

    @Test
    @DisplayName("recommends RBAC least-privilege advice for a RoleBinding node")
    void shouldRecommendRbacAdviceForRoleBinding() {
        GraphNode rb = TestGraphHelper.makeNode("RoleBinding:default:dev-rb", "RoleBinding");
        String action = ImpactRemediationAdvisor.recommendAction(asset(rb));
        assertTrue(action.toLowerCase().contains("rbac") || action.toLowerCase().contains("privilege"));
    }

    @Test
    @DisplayName("recommends scoping service account permissions for a ServiceAccount node")
    void shouldRecommendScopeAdviceForServiceAccount() {
        GraphNode sa = TestGraphHelper.makeNode("ServiceAccount:default:app-sa", "ServiceAccount");
        String action = ImpactRemediationAdvisor.recommendAction(asset(sa));
        assertTrue(action.toLowerCase().contains("scope") || action.toLowerCase().contains("service account"));
    }

    @Test
    @DisplayName("recommends tightening permissions for a Role node")
    void shouldRecommendTightenAdviceForRole() {
        GraphNode role = TestGraphHelper.makeNode("Role:default:reader", "Role");
        String action = ImpactRemediationAdvisor.recommendAction(asset(role));
        assertTrue(action.toLowerCase().contains("role") || action.toLowerCase().contains("tighten")
                || action.toLowerCase().contains("review"));
    }

    @Test
    @DisplayName("recommends tightening permissions for a ClusterRole node")
    void shouldRecommendTightenAdviceForClusterRole() {
        GraphNode cr = TestGraphHelper.makeNode("ClusterRole:cluster-scoped:view", "ClusterRole");
        String action = ImpactRemediationAdvisor.recommendAction(asset(cr));
        assertTrue(action.toLowerCase().contains("role") || action.toLowerCase().contains("tighten")
                || action.toLowerCase().contains("review"));
    }

    @Test
    @DisplayName("recommends network policy restrictions for an Ingress node")
    void shouldRecommendNetworkAdviceForIngress() {
        GraphNode ingress = TestGraphHelper.makeNode("ingress:default:public-ingress", "Ingress");
        String action = ImpactRemediationAdvisor.recommendAction(asset(ingress));
        assertTrue(action.toLowerCase().contains("network") || action.toLowerCase().contains("restrict"));
    }

    @Test
    @DisplayName("recommends hardening for a critical pod (id contains 'db')")
    void shouldRecommendHardenAdviceForCriticalPod() {
        GraphNode pod = TestGraphHelper.makeNode("Pod:default:db-server", "Pod");
        String action = ImpactRemediationAdvisor.recommendAction(asset(pod));
        assertTrue(action.toLowerCase().contains("harden") || action.toLowerCase().contains("segment"));
    }

    @Test
    @DisplayName("recommends general pod hardening for a non-critical pod")
    void shouldRecommendGeneralHardenAdviceForGenericPod() {
        GraphNode pod = TestGraphHelper.makeNode("Pod:default:worker", "Pod");
        String action = ImpactRemediationAdvisor.recommendAction(asset(pod));
        assertTrue(action.toLowerCase().contains("harden") || action.toLowerCase().contains("security"));
    }

    @Test
    @DisplayName("recommends access control hardening for a ConfigMap node")
    void shouldRecommendAccessControlAdviceForConfigMap() {
        GraphNode cm = TestGraphHelper.makeNode("ConfigMap:default:app-config", "ConfigMap");
        String action = ImpactRemediationAdvisor.recommendAction(asset(cm));
        assertTrue(action.toLowerCase().contains("access") || action.toLowerCase().contains("harden"));
    }
}