package io.github.SaptarshiSarkar12.k8sattackmap.model;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum EdgeType {
    USES_SA("uses_sa"),
    BOUND_TO("bound_to"),
    CAN_ACCESS("can_access"),
    USES_SECRET("uses_secret"),
    USES_CONFIGMAP("uses_configmap"),
    MOUNTS_SECRET("mounts_secret"),
    MOUNTS_CONFIGMAP("mounts_configmap"),
    MANAGES("manages"), // Deployment -> ReplicaSet -> Pod
    NODE_ESCAPE("node_escape"), // Privileged container escape
    HOST_PATH_ACCESS("host_path_access"),
    MEMBER_OF("member_of"), // ServiceAccount -> Group
    EXPOSES("exposes"), // Service -> Pod
    EXPOSES_TO_NODE("exposes_to_node"), // Service NodePort/LoadBalancer -> Node
    EXEC_INTO("exec_into"), // pods/exec subresource access
    ENV_FROM_SECRET("env_from_secret"), // Pod reads secret via individual env var (valueFrom.secretKeyRef)
    ENV_FROM_CONFIGMAP("env_from_configmap"); // Pod reads configmap via individual env var (valueFrom.configMapKeyRef)

    private final String label;

    @Override
    public String toString() {
        return label;
    }
}