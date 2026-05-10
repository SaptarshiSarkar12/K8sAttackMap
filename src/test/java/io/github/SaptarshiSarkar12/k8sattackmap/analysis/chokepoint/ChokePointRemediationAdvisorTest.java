package io.github.SaptarshiSarkar12.k8sattackmap.analysis.chokepoint;

import org.junit.jupiter.api.Assertions;
import io.github.SaptarshiSarkar12.k8sattackmap.analysis.remediation.RemediationPlan;
import io.github.SaptarshiSarkar12.k8sattackmap.helper.TestGraphHelper;
import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphNode;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

@DisplayName("ChokePointRemediationAdvisor builds remediation plans for ranked choke points")
class ChokePointRemediationAdvisorTest {
    private static ChokePointResult singleNodeResult(GraphNode node) {
        List<RankedChokePoint> ranked = List.of(new RankedChokePoint(node, 3, 5.0));
        return new ChokePointResult(ranked, Map.of(node, 3), Map.of(node, 5.0));
    }

    @Test
    @DisplayName("returns empty list for null ChokePointResult")
    void shouldReturnEmptyForNullResult() {
        List<RemediationPlan> plans = ChokePointRemediationAdvisor.buildPlans(null, 5);
        Assertions.assertTrue(plans.isEmpty());
    }

    @Test
    @DisplayName("returns empty list when ranked choke points list is empty")
    void shouldReturnEmptyForEmptyRankedList() {
        ChokePointResult emptyResult = new ChokePointResult(List.of(), Map.of(), Map.of());
        List<RemediationPlan> plans = ChokePointRemediationAdvisor.buildPlans(emptyResult, 5);
        Assertions.assertTrue(plans.isEmpty());
    }

    @Test
    @DisplayName("limits plans to topK even when more choke points are ranked")
    void shouldLimitPlansToTopK() {
        GraphNode sa = TestGraphHelper.makeNode("ServiceAccount:default:app-sa", "ServiceAccount");
        GraphNode rb = TestGraphHelper.makeNode("RoleBinding:default:dev-rb", "RoleBinding");
        GraphNode crb = TestGraphHelper.makeNode("ClusterRoleBinding:cluster-scoped:admin", "ClusterRoleBinding");
        GraphNode secret = TestGraphHelper.makeNode("Secret:default:db-pass", "Secret");
        GraphNode pod = TestGraphHelper.makeNode("Pod:default:web", "Pod");

        List<RankedChokePoint> ranked = List.of(
                new RankedChokePoint(sa, 5, 9.0),
                new RankedChokePoint(rb, 4, 8.0),
                new RankedChokePoint(crb, 3, 7.0),
                new RankedChokePoint(secret, 2, 6.0),
                new RankedChokePoint(pod, 1, 5.0)
        );
        ChokePointResult result = new ChokePointResult(ranked, Map.of(), Map.of());

        List<RemediationPlan> plans = ChokePointRemediationAdvisor.buildPlans(result, 2);

        Assertions.assertEquals(2, plans.size());
    }

    @Test
    @DisplayName("ServiceAccount plan includes kubectl get serviceaccount in audit commands")
    void serviceAccountPlanHasKubectlGetAuditCommand() {
        GraphNode sa = TestGraphHelper.makeNode("ServiceAccount:default:app-sa", "ServiceAccount");
        List<RemediationPlan> plans = ChokePointRemediationAdvisor.buildPlans(singleNodeResult(sa), 1);

        RemediationPlan plan = plans.getFirst();
        boolean hasGetCommand = plan.auditCommands().stream()
                .anyMatch(cmd -> cmd.contains("kubectl get serviceaccount"));
        Assertions.assertTrue(hasGetCommand, "ServiceAccount plan should include kubectl get serviceaccount");
    }

    @Test
    @DisplayName("Secret plan includes a kubectl create secret command in enforce commands")
    void secretPlanHasRotateEnforceCommand() {
        GraphNode secret = TestGraphHelper.makeNode("Secret:default:db-pass", "Secret");
        List<RemediationPlan> plans = ChokePointRemediationAdvisor.buildPlans(singleNodeResult(secret), 1);

        RemediationPlan plan = plans.getFirst();
        boolean hasRotateCommand = plan.enforceCommands().stream()
                .anyMatch(cmd -> cmd.contains("kubectl create secret"));
        Assertions.assertTrue(hasRotateCommand, "Secret plan should include a kubectl create secret rotation command");
    }

    @Test
    @DisplayName("RoleBinding plan is marked as containing a destructive action")
    void roleBindingPlanIsMarkedDestructive() {
        GraphNode rb = TestGraphHelper.makeNode("RoleBinding:default:dev-rb", "RoleBinding");
        List<RemediationPlan> plans = ChokePointRemediationAdvisor.buildPlans(singleNodeResult(rb), 1);

        Assertions.assertTrue(plans.getFirst().containsDestructiveAction());
    }

    @Test
    @DisplayName("ClusterRoleBinding plan includes kubectl get clusterrolebinding in audit commands")
    void clusterRoleBindingPlanHasAuditCommand() {
        GraphNode crb = TestGraphHelper.makeNode("ClusterRoleBinding:cluster-scoped:admin", "ClusterRoleBinding");
        List<RemediationPlan> plans = ChokePointRemediationAdvisor.buildPlans(singleNodeResult(crb), 1);

        RemediationPlan plan = plans.getFirst();
        boolean hasAuditCmd = plan.auditCommands().stream()
                .anyMatch(cmd -> cmd.contains("kubectl get clusterrolebinding"));
        Assertions.assertTrue(hasAuditCmd);
    }

    @Test
    @DisplayName("plan node ID matches the choke point node ID")
    void planNodeIdMatchesChokePointId() {
        GraphNode sa = TestGraphHelper.makeNode("ServiceAccount:default:app-sa", "ServiceAccount");
        List<RemediationPlan> plans = ChokePointRemediationAdvisor.buildPlans(singleNodeResult(sa), 1);

        Assertions.assertEquals(sa.getId(), plans.getFirst().nodeId());
    }
}