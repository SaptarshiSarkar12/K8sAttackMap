package io.github.SaptarshiSarkar12.k8sattackmap.security;

import io.github.SaptarshiSarkar12.k8sattackmap.helper.TestGraphHelper;
import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphNode;
import io.github.SaptarshiSarkar12.k8sattackmap.model.SecurityFacts;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("AttackSurfaceClassifier")
class AttackSurfaceClassifierTest {
    private static void classify(GraphNode node, Set<GraphNode> sourceNodes, Set<GraphNode> targetNodes) {
        AttackSurfaceClassifier.classifySourceAndTargetCandidates(Set.of(node), sourceNodes, targetNodes);
    }

    @Nested
    @DisplayName("Source node detection")
    class SourceDetection {
        @Test
        @DisplayName("privileged Pod is classified as a source")
        void privilegedPodIsSource() {
            SecurityFacts facts = new SecurityFacts();
            facts.setPrivilegedContainer(true);
            GraphNode pod = TestGraphHelper.makeNodeWithFacts("Pod:default:evil-pod", "Pod", 0.0, facts);

            Set<GraphNode> sources = new HashSet<>();
            Set<GraphNode> targets = new HashSet<>();
            classify(pod, sources, targets);

            assertTrue(sources.contains(pod));
        }

        @Test
        @DisplayName("Pod with privilege escalation is classified as a source")
        void privilegeEscalationPodIsSource() {
            SecurityFacts facts = new SecurityFacts();
            facts.setAllowPrivilegeEscalation(true);
            GraphNode pod = TestGraphHelper.makeNodeWithFacts("Pod:default:escalate-pod", "Pod", 0.0, facts);

            Set<GraphNode> sources = new HashSet<>();
            Set<GraphNode> targets = new HashSet<>();
            classify(pod, sources, targets);

            assertTrue(sources.contains(pod));
        }

        @Test
        @DisplayName("Pod with host network access is classified as a source")
        void hostNetworkPodIsSource() {
            SecurityFacts facts = new SecurityFacts();
            facts.setHostNetwork(true);
            GraphNode pod = TestGraphHelper.makeNodeWithFacts("Pod:default:hostnet-pod", "Pod", 0.0, facts);

            Set<GraphNode> sources = new HashSet<>();
            Set<GraphNode> targets = new HashSet<>();
            classify(pod, sources, targets);

            assertTrue(sources.contains(pod));
        }

        @Test
        @DisplayName("Pod id heuristic classifies Pod as a source")
        void podIdHeuristicIsSource() {
            GraphNode pod = TestGraphHelper.makeNode("pod:default:web", "Pod");

            Set<GraphNode> sources = new HashSet<>();
            Set<GraphNode> targets = new HashSet<>();
            classify(pod, sources, targets);

            assertTrue(sources.contains(pod));
        }

        @Test
        @DisplayName("ServiceAccount id heuristic classifies ServiceAccount as a source")
        void serviceAccountIdIsSource() {
            GraphNode serviceAccount = TestGraphHelper.makeNode("serviceaccount:default:app", "ServiceAccount");

            Set<GraphNode> sources = new HashSet<>();
            Set<GraphNode> targets = new HashSet<>();
            classify(serviceAccount, sources, targets);

            assertTrue(sources.contains(serviceAccount));
        }

        @Test
        @DisplayName("Pod in kube-system namespace is not classified as a source")
        void kubeSystemPodIsExcluded() {
            GraphNode pod = TestGraphHelper.makeNode("Pod:kube-system:coredns", "Pod");

            Set<GraphNode> sources = new HashSet<>();
            Set<GraphNode> targets = new HashSet<>();
            classify(pod, sources, targets);

            assertFalse(sources.contains(pod));
        }

        @Test
        @DisplayName("Pod with system path is not classified as a source")
        void systemPodIsExcluded() {
            GraphNode pod = TestGraphHelper.makeNode("pod:kube-system:system:etcd", "Pod");

            Set<GraphNode> sources = new HashSet<>();
            Set<GraphNode> targets = new HashSet<>();
            classify(pod, sources, targets);

            assertFalse(sources.contains(pod));
        }

        @Test
        @DisplayName("existing source entries are preserved")
        void prePopulatedSourceSetIsPreserved() {
            GraphNode existing = TestGraphHelper.makeNode("Pod:default:existing", "Pod");
            GraphNode newPod = TestGraphHelper.makeNode("pod:default:new-pod", "Pod");

            Set<GraphNode> sources = new HashSet<>(Set.of(existing));
            Set<GraphNode> targets = new HashSet<>();
            AttackSurfaceClassifier.classifySourceAndTargetCandidates(Set.of(existing, newPod), sources, targets);

            assertEquals(1, sources.size());
            assertTrue(sources.contains(existing));
            assertFalse(sources.contains(newPod));
        }
    }

    @Nested
    @DisplayName("Target node detection")
    class TargetDetection {
        @Test
        @DisplayName("secret material is classified as a target")
        void credentialSecretIsTarget() {
            SecurityFacts facts = new SecurityFacts();
            facts.setCredentialMaterial(true);
            GraphNode secret = TestGraphHelper.makeNodeWithFacts("Secret:default:db-pass", "Secret", 0.0, facts);

            Set<GraphNode> sources = new HashSet<>();
            Set<GraphNode> targets = new HashSet<>();
            classify(secret, sources, targets);

            assertTrue(targets.contains(secret));
        }

        @Test
        @DisplayName("RBAC wildcard verb role is classified as a target")
        void wildcardVerbRoleIsTarget() {
            SecurityFacts facts = new SecurityFacts();
            facts.setRbacWildcardVerb(true);
            GraphNode role = TestGraphHelper.makeNodeWithFacts("Role:default:admin-role", "Role", 0.0, facts);

            Set<GraphNode> sources = new HashSet<>();
            Set<GraphNode> targets = new HashSet<>();
            classify(role, sources, targets);

            assertTrue(targets.contains(role));
        }

        @Test
        @DisplayName("ClusterRole with escalate permission is classified as a target")
        void escalateClusterRoleIsTarget() {
            SecurityFacts facts = new SecurityFacts();
            facts.setRbacHasEscalate(true);
            GraphNode clusterRole = TestGraphHelper.makeNodeWithFacts("ClusterRole:cluster-scoped:escalator", "ClusterRole", 0.0, facts);

            Set<GraphNode> sources = new HashSet<>();
            Set<GraphNode> targets = new HashSet<>();
            classify(clusterRole, sources, targets);

            assertTrue(targets.contains(clusterRole));
        }

        @Test
        @DisplayName("secret id heuristic classifies Secret as a target")
        void secretIdHeuristicIsTarget() {
            GraphNode secret = TestGraphHelper.makeNode("secret:default:api-key", "Secret");

            Set<GraphNode> sources = new HashSet<>();
            Set<GraphNode> targets = new HashSet<>();
            classify(secret, sources, targets);

            assertTrue(targets.contains(secret));
        }

        @Test
        @DisplayName("cluster-admin id heuristic classifies binding as a target")
        void clusterAdminIdIsTarget() {
            GraphNode clusterRoleBinding = TestGraphHelper.makeNode("clusterrolebinding:cluster-scoped:cluster-admin-binding", "ClusterRoleBinding");

            Set<GraphNode> sources = new HashSet<>();
            Set<GraphNode> targets = new HashSet<>();
            classify(clusterRoleBinding, sources, targets);

            assertTrue(targets.contains(clusterRoleBinding));
        }

        @Test
        @DisplayName("ClusterRole type is classified as a target")
        void clusterRoleTypeIsTarget() {
            GraphNode clusterRole = TestGraphHelper.makeNode("ClusterRole:cluster-scoped:view", "ClusterRole");

            Set<GraphNode> sources = new HashSet<>();
            Set<GraphNode> targets = new HashSet<>();
            classify(clusterRole, sources, targets);

            assertTrue(targets.contains(clusterRole));
        }

        @Test
        @DisplayName("existing target entries are preserved")
        void prePopulatedTargetSetIsPreserved() {
            GraphNode existing = TestGraphHelper.makeNode("secret:default:existing", "Secret");
            GraphNode newSecret = TestGraphHelper.makeNode("secret:default:new", "Secret");

            Set<GraphNode> sources = new HashSet<>();
            Set<GraphNode> targets = new HashSet<>(Set.of(existing));
            AttackSurfaceClassifier.classifySourceAndTargetCandidates(Set.of(existing, newSecret), sources, targets);

            assertEquals(1, targets.size());
            assertTrue(targets.contains(existing));
            assertFalse(targets.contains(newSecret));
        }
    }
}