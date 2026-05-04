package io.github.SaptarshiSarkar12.k8sattackmap.ingestion;

import io.github.SaptarshiSarkar12.k8sattackmap.model.ClusterGraphData;
import io.github.SaptarshiSarkar12.k8sattackmap.model.EdgeType;
import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphEdge;
import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphNode;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.StringReader;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("K8sJsonParser tests")
class K8sJsonParserTest {
    private static ClusterGraphData parse(String json) {
        return K8sJsonParser.parse(new StringReader(json));
    }

    private static String items(String... itemJson) {
        return "{\"items\":[" + String.join(",", itemJson) + "]}";
    }

    private static String pod(String namespace, String name, String extraSpec) {
        return """
               {
                 "kind":"Pod",
                 "metadata":{"name":"%s","namespace":"%s"},
                 "spec":{%s},
                 "status":{}
               }
               """.formatted(name, namespace, extraSpec);
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
        String nsField = kind.equals("ClusterRole") ? "" : "\"namespace\":\"%s\",".formatted(namespace);
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
        assertNull(parse("{this is not json"));
    }

    @Test
    @DisplayName("returns null when items field is missing")
    void returnsNullWhenItemsFieldIsMissing() {
        assertNull(parse("{\"notItems\":[]}"));
    }

    @Test
    @DisplayName("returns empty nodes and edges for empty items")
    void returnsEmptyDataForEmptyItems() {
        ClusterGraphData data = parse(items());
        assertNotNull(data);
        assertTrue(data.getNodes().isEmpty());
        assertTrue(data.getEdges().isEmpty());
    }

    @Test
    @DisplayName("creates node id as type:namespace:name")
    void createsNodeWithExpectedId() {
        ClusterGraphData data = parse(items(pod("default", "web", "")));
        assertNotNull(data);
        GraphNode node = requireNode(data, "Pod:default:web");
        assertEquals("Pod", node.getType());
        assertEquals("default", node.getNamespace());
        assertEquals("web", node.getName());
    }

    @Test
    @DisplayName("creates one node per item")
    void createsOneNodePerItem() {
        ClusterGraphData data = parse(items(
                pod("default", "web", ""),
                pod("default", "api", ""),
                secret("default", "db-pass", "Opaque", false)));
        assertNotNull(data);
        assertEquals(3, data.getNodes().size());
    }

    @Test
    @DisplayName("creates USES_SA edge when pod has serviceAccountName")
    void createsUsesSaEdge() {
        String podJson = pod("default", "web", "\"serviceAccountName\":\"app-sa\"");
        ClusterGraphData data = parse(items(podJson, serviceAccount("default", "app-sa", null)));
        assertNotNull(data);
        assertTrue(hasEdge(data, "Pod:default:web", "ServiceAccount:default:app-sa", EdgeType.USES_SA));
    }

    @Test
    @DisplayName("creates MOUNTS_SECRET edge only when secret volume is mounted")
    void createsMountsSecretEdgeOnlyForMountedVolume() {
        String mountedPod = pod("default", "web", """
                "volumes":[{"name":"creds","secret":{"secretName":"db-pass"}}],
                "containers":[{"name":"app","image":"app:1.0","volumeMounts":[{"name":"creds","mountPath":"/creds"}]}]
                """);
        ClusterGraphData mountedData = parse(items(mountedPod, secret("default", "db-pass", "Opaque", true)));
        assertNotNull(mountedData);
        assertTrue(hasEdge(mountedData, "Pod:default:web", "Secret:default:db-pass", EdgeType.MOUNTS_SECRET));

        String unmountedPod = pod("default", "web", """
                "volumes":[{"name":"creds","secret":{"secretName":"db-pass"}}],
                "containers":[{"name":"app","image":"app:1.0","volumeMounts":[]}]
                """);
        ClusterGraphData unmountedData = parse(items(unmountedPod, secret("default", "db-pass", "Opaque", true)));
        assertNotNull(unmountedData);
        assertFalse(unmountedData.getEdges().stream().anyMatch(e -> e.getRelationship() == EdgeType.MOUNTS_SECRET));
    }

    @Test
    @DisplayName("creates environment reference edges for envFrom and valueFrom")
    void createsEnvironmentReferenceEdges() {
        String envFromCmPod = pod("default", "web", """
                "containers":[{"name":"app","image":"app:1.0","envFrom":[{"configMapRef":{"name":"app-cfg"}}]}]
                """);
        ClusterGraphData envFromCmData = parse(items(envFromCmPod));
        assertNotNull(envFromCmData);
        assertTrue(hasEdge(envFromCmData, "Pod:default:web", "ConfigMap:default:app-cfg", EdgeType.USES_CONFIGMAP));

        String envFromSecretPod = pod("default", "web", """
                "containers":[{"name":"app","image":"app:1.0","envFrom":[{"secretRef":{"name":"api-key"}}]}]
                """);
        ClusterGraphData envFromSecretData = parse(items(envFromSecretPod));
        assertNotNull(envFromSecretData);
        assertTrue(hasEdge(envFromSecretData, "Pod:default:web", "Secret:default:api-key", EdgeType.USES_SECRET));

        String valueFromSecretPod = pod("default", "web", """
                "containers":[{"name":"app","image":"app:1.0",
                  "env":[{"name":"DB_PASS","valueFrom":{"secretKeyRef":{"name":"db-secret","key":"password"}}}]}]
                """);
        ClusterGraphData valueFromSecretData = parse(items(valueFromSecretPod));
        assertNotNull(valueFromSecretData);
        assertTrue(hasEdge(valueFromSecretData, "Pod:default:web", "Secret:default:db-secret", EdgeType.ENV_FROM_SECRET));

        String valueFromCmPod = pod("default", "web", """
                "containers":[{"name":"app","image":"app:1.0",
                  "env":[{"name":"LOG_LEVEL","valueFrom":{"configMapKeyRef":{"name":"app-cfg","key":"logLevel"}}}]}]
                """);
        ClusterGraphData valueFromCmData = parse(items(valueFromCmPod));
        assertNotNull(valueFromCmData);
        assertTrue(hasEdge(valueFromCmData, "Pod:default:web", "ConfigMap:default:app-cfg", EdgeType.ENV_FROM_CONFIGMAP));
    }

    @Test
    @DisplayName("creates node-related edges and synthetic node for scheduled pod")
    void createsNodeRelatedEdgesAndSyntheticNode() {
        String privilegedPod = pod("default", "evil", """
                "nodeName":"worker-1",
                "containers":[{"name":"c","image":"img:1","securityContext":{"privileged":true}}]
                """);
        ClusterGraphData privilegedData = parse(items(privilegedPod));
        assertNotNull(privilegedData);
        assertTrue(hasEdge(privilegedData, "Pod:default:evil", "Node:cluster-scoped:worker-1", EdgeType.NODE_ESCAPE));

        String hostPathPod = pod("default", "hp-pod", """
                "nodeName":"worker-1",
                "volumes":[{"name":"host","hostPath":{"path":"/etc"}}],
                "containers":[{"name":"c","image":"img:1","volumeMounts":[{"name":"host","mountPath":"/host"}]}]
                """);
        ClusterGraphData hostPathData = parse(items(hostPathPod));
        assertNotNull(hostPathData);
        assertTrue(hasEdge(hostPathData, "Pod:default:hp-pod", "Node:cluster-scoped:worker-1", EdgeType.HOST_PATH_ACCESS));

        String pod1 = pod("default", "pod-a",
                "\"nodeName\":\"worker-2\",\"containers\":[{\"name\":\"c\",\"image\":\"img:1\",\"securityContext\":{\"privileged\":true}}]");
        String pod2 = pod("default", "pod-b",
                "\"nodeName\":\"worker-2\",\"containers\":[{\"name\":\"c\",\"image\":\"img:1\",\"securityContext\":{\"privileged\":true}}]");
        ClusterGraphData dedupData = parse(items(pod1, pod2));
        assertNotNull(dedupData);
        long count = dedupData.getNodes().stream()
                .filter(n -> n.getId().equals("Node:cluster-scoped:worker-2"))
                .count();
        assertEquals(1, count);
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
        assertNotNull(data);
        assertTrue(hasEdge(data, "ReplicaSet:default:web-rs", "Pod:default:web-abc", EdgeType.MANAGES));
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
        assertNotNull(saData);
        assertTrue(hasEdge(saData, "ServiceAccount:default:app-sa", "Role:default:reader", EdgeType.BOUND_TO));

        String userBinding = roleBinding("ClusterRoleBinding", "cluster-scoped", "admin-crb",
                "ClusterRole", "admin",
                "[{\"kind\":\"User\",\"name\":\"alice\"}]");
        ClusterGraphData userData = parse(items(userBinding, role("ClusterRole", "cluster-scoped", "admin", "[]")));
        assertNotNull(userData);
        assertNotNull(requireNode(userData, "User:cluster-scoped:alice"));
        assertTrue(userData.getEdges().stream().anyMatch(e ->
                e.getSource().equals("User:cluster-scoped:alice") && e.getRelationship() == EdgeType.BOUND_TO));
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
        assertNotNull(allSaData);
        long allCount = allSaData.getEdges().stream()
                .filter(e -> e.getRelationship() == EdgeType.MEMBER_OF)
                .count();
        assertEquals(2, allCount);

        String nsBinding = roleBinding("ClusterRoleBinding", "cluster-scoped", "ns-sa-crb",
                "ClusterRole", "view",
                "[{\"kind\":\"Group\",\"name\":\"system:serviceaccounts:default\"}]");
        ClusterGraphData nsData = parse(items(nsBinding,
                role("ClusterRole", "cluster-scoped", "view", "[]"),
                serviceAccount("default", "app-sa", null),
                serviceAccount("prod", "prod-sa", null)));
        assertNotNull(nsData);
        List<GraphEdge> memberOfEdges = nsData.getEdges().stream()
                .filter(e -> e.getRelationship() == EdgeType.MEMBER_OF)
                .toList();
        assertEquals(1, memberOfEdges.size());
        assertEquals("ServiceAccount:default:app-sa", memberOfEdges.get(0).getSource());
    }

    @Test
    @DisplayName("creates CAN_ACCESS edges based on role verbs and scope")
    void createsCanAccessEdgesBasedOnRoleRules() {
        String roleJson = role("Role", "default", "secret-creator",
                "[{\"verbs\":[\"create\"],\"resources\":[\"secrets\"],\"apiGroups\":[\"\"]}]");
        ClusterGraphData roleData = parse(items(roleJson, secret("default", "db-pass", "Opaque", true)));
        assertNotNull(roleData);
        assertTrue(hasEdge(roleData, "Role:default:secret-creator", "Secret:default:db-pass", EdgeType.CAN_ACCESS));

        String readOnlyRole = role("Role", "default", "secret-reader",
                "[{\"verbs\":[\"get\",\"list\",\"watch\"],\"resources\":[\"secrets\"],\"apiGroups\":[\"\"]}]");
        ClusterGraphData readOnlyData = parse(items(readOnlyRole, secret("default", "db-pass", "Opaque", true)));
        assertNotNull(readOnlyData);
        assertFalse(readOnlyData.getEdges().stream().anyMatch(e -> e.getRelationship() == EdgeType.CAN_ACCESS));

        String clusterRoleJson = role("ClusterRole", "cluster-scoped", "secret-patcher",
                "[{\"verbs\":[\"patch\"],\"resources\":[\"secrets\"],\"apiGroups\":[\"\"]}]");
        ClusterGraphData clusterRoleData = parse(items(clusterRoleJson,
                secret("default", "secret-a", "Opaque", true),
                secret("prod", "secret-b", "Opaque", true)));
        assertNotNull(clusterRoleData);
        long edgeCount = clusterRoleData.getEdges().stream()
                .filter(e -> e.getSource().equals("ClusterRole:cluster-scoped:secret-patcher")
                        && e.getRelationship() == EdgeType.CAN_ACCESS)
                .count();
        assertEquals(2, edgeCount);
    }

    @Test
    @DisplayName("restricts CAN_ACCESS by resourceNames")
    void restrictsCanAccessByResourceNames() {
        String roleJson = role("Role", "default", "specific-reader",
                "[{\"verbs\":[\"patch\"],\"resources\":[\"secrets\"],\"resourceNames\":[\"allowed-secret\"],\"apiGroups\":[\"\"]}]");
        ClusterGraphData data = parse(items(roleJson,
                secret("default", "allowed-secret", "Opaque", true),
                secret("default", "other-secret", "Opaque", true)));
        assertNotNull(data);
        List<GraphEdge> canAccessEdges = data.getEdges().stream()
                .filter(e -> e.getRelationship() == EdgeType.CAN_ACCESS)
                .toList();
        assertEquals(1, canAccessEdges.size());
        assertEquals("Secret:default:allowed-secret", canAccessEdges.get(0).getTarget());
    }

    @Test
    @DisplayName("extracts pod security facts")
    void extractsPodSecurityFacts() {
        String podJson = pod("default", "fact-pod", """
                "hostPID":true,
                "hostNetwork":true,
                "volumes":[{"name":"host","hostPath":{"path":"/etc"}}],
                "containers":[{"name":"c","image":"img:1",
                  "securityContext":{"privileged":true,"runAsUser":0,"capabilities":{"add":["SYS_ADMIN","NET_ADMIN"]}}}]
                """);
        ClusterGraphData data = parse(items(podJson));
        assertNotNull(data);
        GraphNode podNode = requireNode(data, "Pod:default:fact-pod");
        assertTrue(podNode.getSecurityFacts().isPrivilegedContainer());
        assertTrue(podNode.getSecurityFacts().isHostPID());
        assertTrue(podNode.getSecurityFacts().isHostNetwork());
        assertTrue(podNode.getSecurityFacts().isRunAsRoot());
        assertTrue(podNode.getSecurityFacts().isHostPathMounted());
        assertTrue(podNode.getSecurityFacts().getAddedCapabilities().contains("sys_admin"));
        assertTrue(podNode.getSecurityFacts().getAddedCapabilities().contains("net_admin"));
    }

    @Test
    @DisplayName("extracts RBAC, secret, and service account security facts")
    void extractsRbacSecretAndServiceAccountFacts() {
        String wildcardRole = role("Role", "default", "all-access",
                "[{\"verbs\":[\"*\"],\"resources\":[\"pods\"],\"apiGroups\":[\"\"]}]");
        String escalateClusterRole = role("ClusterRole", "cluster-scoped", "escalator",
                "[{\"verbs\":[\"escalate\"],\"resources\":[\"clusterroles\"],\"apiGroups\":[\"rbac.authorization.k8s.io\"]}]");
        String podJson = pod("default", "web", "\"serviceAccountName\":\"auto-sa\"");

        ClusterGraphData data = parse(items(
                wildcardRole,
                escalateClusterRole,
                secret("default", "api-key", "Opaque", true),
                secret("default", "sa-token", "kubernetes.io/service-account-token", false),
                serviceAccount("default", "auto-sa", true),
                podJson));
        assertNotNull(data);

        assertTrue(requireNode(data, "Role:default:all-access").getSecurityFacts().isRbacWildcardVerb());
        assertTrue(requireNode(data, "ClusterRole:cluster-scoped:escalator").getSecurityFacts().isRbacHasEscalate());
        assertTrue(requireNode(data, "Secret:default:api-key").getSecurityFacts().isCredentialMaterial());
        assertTrue(requireNode(data, "Secret:default:sa-token").getSecurityFacts().isCredentialMaterial());
        assertTrue(requireNode(data, "ServiceAccount:default:auto-sa").getSecurityFacts().isServiceAccountTokenAutomount());
        assertTrue(requireNode(data, "Pod:default:web").getSecurityFacts().isServiceAccountTokenAutomount());
    }

    @Test
    @DisplayName("populates podCVEIds with one entry per item")
    void populatesPodCveIdsWithOneEntryPerItem() {
        ClusterGraphData data = parse(items(
                pod("default", "web", ""),
                secret("default", "db-pass", "Opaque", false)));
        assertNotNull(data);
        assertNotNull(data.getPodCVEIds());
        assertEquals(2, data.getPodCVEIds().size());
    }
}