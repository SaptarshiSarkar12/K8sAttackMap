package io.github.SaptarshiSarkar12.k8sattackmap.ingestion;

import org.junit.jupiter.api.Assertions;
import io.github.SaptarshiSarkar12.k8sattackmap.model.ClusterGraphData;
import io.github.SaptarshiSarkar12.k8sattackmap.model.EdgeType;
import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphEdge;
import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphNode;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.StringReader;
import java.util.List;

@DisplayName("K8sJsonParser tests")
class K8sJsonParserTest {
    private static ClusterGraphData parse(String json) {
        return K8sJsonParser.parse(new StringReader(json));
    }

    private static String items(String... itemJson) {
        return "{\"items\":[" + String.join(",", itemJson) + "]}";
    }

    private static String pod(String name, String extraSpec) {
        return """
               {
                 "kind":"Pod",
                 "metadata":{"name":"%s","namespace":"%s"},
                 "spec":{%s},
                 "status":{}
               }
               """.formatted(name, "default", extraSpec);
    }

    private static String secret(String namespace, String name, String type, boolean hasData) {
        String data = hasData ? ",\"data\":{\"key\":\"dmFsdWU=\"}" : "";
        return """
               {
                 "kind":"Secret",
                 "metadata":{"name":"%s","namespace":"%s"},
                 "type":"%s"%s
               }
               """.formatted(name, namespace, type, data);
    }

    private static String serviceAccount(String namespace, String name, Boolean automount) {
        String automountField = automount == null ? "" : ",\"automountServiceAccountToken\":" + automount;
        return """
               {
                 "kind":"ServiceAccount",
                 "metadata":{"name":"%s","namespace":"%s"}%s
               }
               """.formatted(name, namespace, automountField);
    }

    private static String role(String kind, String namespace, String name, String rulesJson) {
        String nsField = "ClusterRole".equals(kind) ? "" : "\"namespace\":\"%s\",".formatted(namespace);
        return """
               {
                 "kind":"%s",
                 "metadata":{%s"name":"%s"},
                 "rules":%s
               }
               """.formatted(kind, nsField, name, rulesJson);
    }

    private static String roleBinding(String kind, String namespace, String name,
                                      String roleRefKind, String roleRefName,
                                      String subjectsJson) {
        return """
               {
                 "kind":"%s",
                 "metadata":{"name":"%s","namespace":"%s"},
                 "roleRef":{"kind":"%s","name":"%s"},
                 "subjects":%s
               }
               """.formatted(kind, name, namespace, roleRefKind, roleRefName, subjectsJson);
    }

    private static GraphNode requireNode(ClusterGraphData data, String id) {
        return data.getNodes().stream()
                .filter(n -> n.getId().equals(id))
                .findFirst()
                .orElseThrow();
    }

    private static boolean hasEdge(ClusterGraphData data, String source, String target, EdgeType relationship) {
        return data.getEdges().stream().anyMatch(e ->
                e.getSource().equals(source)
                        && e.getTarget().equals(target)
                        && e.getRelationship() == relationship);
    }

    @Test
    @DisplayName("returns null for malformed JSON")
    void returnsNullForMalformedJson() {
        Assertions.assertNull(parse("{this is not json"));
    }

    @Test
    @DisplayName("returns null when items field is missing")
    void returnsNullWhenItemsFieldIsMissing() {
        Assertions.assertNull(parse("{\"notItems\":[]}"));
    }

    @Test
    @DisplayName("returns empty nodes and edges for empty items")
    void returnsEmptyDataForEmptyItems() {
        ClusterGraphData data = parse(items());
        Assertions.assertNotNull(data);
        Assertions.assertTrue(data.getNodes().isEmpty());
        Assertions.assertTrue(data.getEdges().isEmpty());
    }

    @Test
    @DisplayName("creates node id as type:namespace:name")
    void createsNodeWithExpectedId() {
        ClusterGraphData data = parse(items(pod("web", "")));
        Assertions.assertNotNull(data);
        GraphNode node = requireNode(data, "Pod:default:web");
        Assertions.assertEquals("Pod", node.getType());
        Assertions.assertEquals("default", node.getNamespace());
        Assertions.assertEquals("web", node.getName());
    }

    @Test
    @DisplayName("creates one node per item")
    void createsOneNodePerItem() {
        ClusterGraphData data = parse(items(
                pod("web", ""),
                pod("api", ""),
                secret("default", "db-pass", "Opaque", false)));
        Assertions.assertNotNull(data);
        Assertions.assertEquals(3, data.getNodes().size());
    }

    @Test
    @DisplayName("creates USES_SA edge when pod has serviceAccountName")
    void createsUsesSaEdge() {
        String podJson = pod("web", "\"serviceAccountName\":\"app-sa\"");
        ClusterGraphData data = parse(items(podJson, serviceAccount("default", "app-sa", null)));
        Assertions.assertNotNull(data);
        Assertions.assertTrue(hasEdge(data, "Pod:default:web", "ServiceAccount:default:app-sa", EdgeType.USES_SA));
    }

    @Test
    @DisplayName("creates MOUNTS_SECRET edge only when secret volume is mounted")
    void createsMountsSecretEdgeOnlyForMountedVolume() {
        String mountedPod = pod("web", """
                "volumes":[{"name":"creds","secret":{"secretName":"db-pass"}}],
                "containers":[{"name":"app","image":"app:1.0","volumeMounts":[{"name":"creds","mountPath":"/creds"}]}]
                """);
        ClusterGraphData mountedData = parse(items(mountedPod, secret("default", "db-pass", "Opaque", true)));
        Assertions.assertNotNull(mountedData);
        Assertions.assertTrue(hasEdge(mountedData, "Pod:default:web", "Secret:default:db-pass", EdgeType.MOUNTS_SECRET));

        String unmountedPod = pod("web", """
                "volumes":[{"name":"creds","secret":{"secretName":"db-pass"}}],
                "containers":[{"name":"app","image":"app:1.0","volumeMounts":[]}]
                """);
        ClusterGraphData unmountedData = parse(items(unmountedPod, secret("default", "db-pass", "Opaque", true)));
        Assertions.assertNotNull(unmountedData);
        Assertions.assertFalse(unmountedData.getEdges().stream().anyMatch(e -> e.getRelationship() == EdgeType.MOUNTS_SECRET));
    }

    @Test
    @DisplayName("creates environment reference edges for envFrom and valueFrom")
    void createsEnvironmentReferenceEdges() {
        String envFromCmPod = pod("web", """
                "containers":[{"name":"app","image":"app:1.0","envFrom":[{"configMapRef":{"name":"app-cfg"}}]}]
                """);
        ClusterGraphData envFromCmData = parse(items(envFromCmPod));
        Assertions.assertNotNull(envFromCmData);
        Assertions.assertTrue(hasEdge(envFromCmData, "Pod:default:web", "ConfigMap:default:app-cfg", EdgeType.USES_CONFIGMAP));

        String envFromSecretPod = pod("web", """
                "containers":[{"name":"app","image":"app:1.0","envFrom":[{"secretRef":{"name":"api-key"}}]}]
                """);
        ClusterGraphData envFromSecretData = parse(items(envFromSecretPod));
        Assertions.assertNotNull(envFromSecretData);
        Assertions.assertTrue(hasEdge(envFromSecretData, "Pod:default:web", "Secret:default:api-key", EdgeType.USES_SECRET));

        String valueFromSecretPod = pod("web", """
                "containers":[{"name":"app","image":"app:1.0",
                  "env":[{"name":"DB_PASS","valueFrom":{"secretKeyRef":{"name":"db-secret","key":"password"}}}]}]
                """);
        ClusterGraphData valueFromSecretData = parse(items(valueFromSecretPod));
        Assertions.assertNotNull(valueFromSecretData);
        Assertions.assertTrue(hasEdge(valueFromSecretData, "Pod:default:web", "Secret:default:db-secret", EdgeType.ENV_FROM_SECRET));

        String valueFromCmPod = pod("web", """
                "containers":[{"name":"app","image":"app:1.0",
                  "env":[{"name":"LOG_LEVEL","valueFrom":{"configMapKeyRef":{"name":"app-cfg","key":"logLevel"}}}]}]
                """);
        ClusterGraphData valueFromCmData = parse(items(valueFromCmPod));
        Assertions.assertNotNull(valueFromCmData);
        Assertions.assertTrue(hasEdge(valueFromCmData, "Pod:default:web", "ConfigMap:default:app-cfg", EdgeType.ENV_FROM_CONFIGMAP));
    }

    @Test
    @DisplayName("creates node-related edges and synthetic node for scheduled pod")
    void createsNodeRelatedEdgesAndSyntheticNode() {
        String privilegedPod = pod("evil", """
                "nodeName":"worker-1",
                "containers":[{"name":"c","image":"img:1","securityContext":{"privileged":true}}]
                """);
        ClusterGraphData privilegedData = parse(items(privilegedPod));
        Assertions.assertNotNull(privilegedData);
        Assertions.assertTrue(hasEdge(privilegedData, "Pod:default:evil", "Node:cluster-scoped:worker-1", EdgeType.NODE_ESCAPE));

        String hostPathPod = pod("hp-pod", """
                "nodeName":"worker-1",
                "volumes":[{"name":"host","hostPath":{"path":"/etc"}}],
                "containers":[{"name":"c","image":"img:1","volumeMounts":[{"name":"host","mountPath":"/host"}]}]
                """);
        ClusterGraphData hostPathData = parse(items(hostPathPod));
        Assertions.assertNotNull(hostPathData);
        Assertions.assertTrue(hasEdge(hostPathData, "Pod:default:hp-pod", "Node:cluster-scoped:worker-1", EdgeType.HOST_PATH_ACCESS));

        String pod1 = pod("pod-a",
                "\"nodeName\":\"worker-2\",\"containers\":[{\"name\":\"c\",\"image\":\"img:1\",\"securityContext\":{\"privileged\":true}}]");
        String pod2 = pod("pod-b",
                "\"nodeName\":\"worker-2\",\"containers\":[{\"name\":\"c\",\"image\":\"img:1\",\"securityContext\":{\"privileged\":true}}]");
        ClusterGraphData dedupData = parse(items(pod1, pod2));
        Assertions.assertNotNull(dedupData);
        long count = dedupData.getNodes().stream()
                .filter(n -> "Node:cluster-scoped:worker-2".equals(n.getId()))
                .count();
        Assertions.assertEquals(1, count);
    }

    @Test
    @DisplayName("creates MANAGES edge from owner reference")
    void createsManagesEdgeFromOwnerReference() {
        String podJson = """
                {
                  "kind":"Pod",
                  "metadata":{
                    "name":"web-abc","namespace":"default",
                    "ownerReferences":[{"kind":"ReplicaSet","name":"web-rs"}]
                  },
                  "spec":{},"status":{}
                }
                """;
        String rsJson = """
                {"kind":"ReplicaSet","metadata":{"name":"web-rs","namespace":"default"},"spec":{}}
                """;
        ClusterGraphData data = parse(items(podJson, rsJson));
        Assertions.assertNotNull(data);
        Assertions.assertTrue(hasEdge(data, "ReplicaSet:default:web-rs", "Pod:default:web-abc", EdgeType.MANAGES));
    }

    @Test
    @DisplayName("creates RoleBinding and ClusterRoleBinding subject edges")
    void createsRoleBindingSubjectEdges() {
        String saBinding = roleBinding("RoleBinding", "default", "dev-rb",
                "Role", "reader",
                "[{\"kind\":\"ServiceAccount\",\"name\":\"app-sa\",\"namespace\":\"default\"}]");
        ClusterGraphData saData = parse(items(saBinding,
                role("Role", "default", "reader", "[]"),
                serviceAccount("default", "app-sa", null)));
        Assertions.assertNotNull(saData);
        Assertions.assertTrue(hasEdge(saData, "ServiceAccount:default:app-sa", "Role:default:reader", EdgeType.BOUND_TO));

        String userBinding = roleBinding("ClusterRoleBinding", "cluster-scoped", "admin-crb",
                "ClusterRole", "admin",
                "[{\"kind\":\"User\",\"name\":\"alice\"}]");
        ClusterGraphData userData = parse(items(userBinding, role("ClusterRole", "cluster-scoped", "admin", "[]")));
        Assertions.assertNotNull(userData);
        Assertions.assertNotNull(requireNode(userData, "User:cluster-scoped:alice"));
        Assertions.assertTrue(userData.getEdges().stream().anyMatch(e ->
                "User:cluster-scoped:alice".equals(e.getSource()) && e.getRelationship() == EdgeType.BOUND_TO));
    }

    @Test
    @DisplayName("creates MEMBER_OF edges for service account groups")
    void createsMemberOfEdgesForServiceAccountGroups() {
        String allSaBinding = roleBinding("ClusterRoleBinding", "cluster-scoped", "all-sa-crb",
                "ClusterRole", "view",
                "[{\"kind\":\"Group\",\"name\":\"system:serviceaccounts\"}]");
        ClusterGraphData allSaData = parse(items(allSaBinding,
                role("ClusterRole", "cluster-scoped", "view", "[]"),
                serviceAccount("default", "app-sa", null),
                serviceAccount("prod", "prod-sa", null)));
        Assertions.assertNotNull(allSaData);
        long allCount = allSaData.getEdges().stream()
                .filter(e -> e.getRelationship() == EdgeType.MEMBER_OF)
                .count();
        Assertions.assertEquals(2, allCount);

        String nsBinding = roleBinding("ClusterRoleBinding", "cluster-scoped", "ns-sa-crb",
                "ClusterRole", "view",
                "[{\"kind\":\"Group\",\"name\":\"system:serviceaccounts:default\"}]");
        ClusterGraphData nsData = parse(items(nsBinding,
                role("ClusterRole", "cluster-scoped", "view", "[]"),
                serviceAccount("default", "app-sa", null),
                serviceAccount("prod", "prod-sa", null)));
        Assertions.assertNotNull(nsData);
        List<GraphEdge> memberOfEdges = nsData.getEdges().stream()
                .filter(e -> e.getRelationship() == EdgeType.MEMBER_OF)
                .toList();
        Assertions.assertEquals(1, memberOfEdges.size());
        Assertions.assertEquals("ServiceAccount:default:app-sa", memberOfEdges.getFirst().getSource());
    }

    @Test
    @DisplayName("creates CAN_ACCESS edges based on role verbs and scope")
    void createsCanAccessEdgesBasedOnRoleRules() {
        String roleJson = role("Role", "default", "secret-creator",
                "[{\"verbs\":[\"create\"],\"resources\":[\"secrets\"],\"apiGroups\":[\"\"]}]");
        ClusterGraphData roleData = parse(items(roleJson, secret("default", "db-pass", "Opaque", true)));
        Assertions.assertNotNull(roleData);
        Assertions.assertTrue(hasEdge(roleData, "Role:default:secret-creator", "Secret:default:db-pass", EdgeType.CAN_ACCESS));

        String readOnlyRole = role("Role", "default", "secret-reader",
                "[{\"verbs\":[\"get\",\"list\",\"watch\"],\"resources\":[\"secrets\"],\"apiGroups\":[\"\"]}]");
        ClusterGraphData readOnlyData = parse(items(readOnlyRole, secret("default", "db-pass", "Opaque", true)));
        Assertions.assertNotNull(readOnlyData);
        Assertions.assertFalse(readOnlyData.getEdges().stream().anyMatch(e -> e.getRelationship() == EdgeType.CAN_ACCESS));

        String clusterRoleJson = role("ClusterRole", "cluster-scoped", "secret-patcher",
                "[{\"verbs\":[\"patch\"],\"resources\":[\"secrets\"],\"apiGroups\":[\"\"]}]");
        ClusterGraphData clusterRoleData = parse(items(clusterRoleJson,
                secret("default", "secret-a", "Opaque", true),
                secret("prod", "secret-b", "Opaque", true)));
        Assertions.assertNotNull(clusterRoleData);
        long edgeCount = clusterRoleData.getEdges().stream()
                .filter(e -> "ClusterRole:cluster-scoped:secret-patcher".equals(e.getSource())
                        && e.getRelationship() == EdgeType.CAN_ACCESS)
                .count();
        Assertions.assertEquals(2, edgeCount);
    }

    @Test
    @DisplayName("restricts CAN_ACCESS by resourceNames")
    void restrictsCanAccessByResourceNames() {
        String roleJson = role("Role", "default", "specific-reader",
                "[{\"verbs\":[\"patch\"],\"resources\":[\"secrets\"],\"resourceNames\":[\"allowed-secret\"],\"apiGroups\":[\"\"]}]");
        ClusterGraphData data = parse(items(roleJson,
                secret("default", "allowed-secret", "Opaque", true),
                secret("default", "other-secret", "Opaque", true)));
        Assertions.assertNotNull(data);
        List<GraphEdge> canAccessEdges = data.getEdges().stream()
                .filter(e -> e.getRelationship() == EdgeType.CAN_ACCESS)
                .toList();
        Assertions.assertEquals(1, canAccessEdges.size());
        Assertions.assertEquals("Secret:default:allowed-secret", canAccessEdges.getFirst().getTarget());
    }

    @Test
    @DisplayName("extracts pod security facts")
    void extractsPodSecurityFacts() {
        String podJson = pod("fact-pod", """
                "hostPID":true,
                "hostNetwork":true,
                "volumes":[{"name":"host","hostPath":{"path":"/etc"}}],
                "containers":[{"name":"c","image":"img:1",
                  "securityContext":{"privileged":true,"runAsUser":0,"capabilities":{"add":["SYS_ADMIN","NET_ADMIN"]}}}]
                """);
        ClusterGraphData data = parse(items(podJson));
        Assertions.assertNotNull(data);
        GraphNode podNode = requireNode(data, "Pod:default:fact-pod");
        Assertions.assertTrue(podNode.getSecurityFacts().isPrivilegedContainer());
        Assertions.assertTrue(podNode.getSecurityFacts().isHostPID());
        Assertions.assertTrue(podNode.getSecurityFacts().isHostNetwork());
        Assertions.assertTrue(podNode.getSecurityFacts().isRunAsRoot());
        Assertions.assertTrue(podNode.getSecurityFacts().isHostPathMounted());
        Assertions.assertTrue(podNode.getSecurityFacts().getAddedCapabilities().contains("sys_admin"));
        Assertions.assertTrue(podNode.getSecurityFacts().getAddedCapabilities().contains("net_admin"));
    }

    @Test
    @DisplayName("extracts RBAC, secret, and service account security facts")
    void extractsRbacSecretAndServiceAccountFacts() {
        String wildcardRole = role("Role", "default", "all-access",
                "[{\"verbs\":[\"*\"],\"resources\":[\"pods\"],\"apiGroups\":[\"\"]}]");
        String escalateClusterRole = role("ClusterRole", "cluster-scoped", "escalator",
                "[{\"verbs\":[\"escalate\"],\"resources\":[\"clusterroles\"],\"apiGroups\":[\"rbac.authorization.k8s.io\"]}]");
        String podJson = pod("web", "\"serviceAccountName\":\"auto-sa\"");

        ClusterGraphData data = parse(items(
                wildcardRole,
                escalateClusterRole,
                secret("default", "api-key", "Opaque", true),
                secret("default", "sa-token", "kubernetes.io/service-account-token", false),
                serviceAccount("default", "auto-sa", true),
                podJson));
        Assertions.assertNotNull(data);

        Assertions.assertTrue(requireNode(data, "Role:default:all-access").getSecurityFacts().isRbacWildcardVerb());
        Assertions.assertTrue(requireNode(data, "ClusterRole:cluster-scoped:escalator").getSecurityFacts().isRbacHasEscalate());
        Assertions.assertTrue(requireNode(data, "Secret:default:api-key").getSecurityFacts().isCredentialMaterial());
        Assertions.assertTrue(requireNode(data, "Secret:default:sa-token").getSecurityFacts().isCredentialMaterial());
        Assertions.assertTrue(requireNode(data, "ServiceAccount:default:auto-sa").getSecurityFacts().isServiceAccountTokenAutomount());
        Assertions.assertTrue(requireNode(data, "Pod:default:web").getSecurityFacts().isServiceAccountTokenAutomount());
    }

    @Test
    @DisplayName("populates podCVEIds with one entry per item")
    void populatesPodCveIdsWithOneEntryPerItem() {
        ClusterGraphData data = parse(items(
                pod("web", ""),
                secret("default", "db-pass", "Opaque", false)));
        Assertions.assertNotNull(data);
        Assertions.assertNotNull(data.getPodCVEIds());
        Assertions.assertEquals(2, data.getPodCVEIds().size());
    }
}