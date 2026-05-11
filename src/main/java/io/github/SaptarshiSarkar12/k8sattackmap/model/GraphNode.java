package io.github.SaptarshiSarkar12.k8sattackmap.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.Setter;

import java.util.List;

/**
 * Represents a Kubernetes resource node in the attack graph.
 * <p>
 * Node IDs follow the format: {@code <Type>:<namespace>:<name>} (e.g., {@code Pod:default:web}).
 * For cluster-scoped resources, namespace is {@link io.github.SaptarshiSarkar12.k8sattackmap.util.AppConstants#CLUSTER_SCOPED}.
 * <p>
 * Nodes contain security-relevant metadata via {@link SecurityFacts}, including RBAC permissions,
 * runtime posture (privileged containers, hostPath mounts), and infrastructure surface indicators.
 * <p>
 * The intrinsic friction of a node (computed by {@link #getIntrinsicFriction()}) represents
 * the ease with which an attacker can move through or exploit that resource. Lower friction = easier exploitation.
 */
@Setter
@Getter
public class GraphNode {
    private String id;
    private String type; // e.g., "Pod", "ServiceAccount"
    private String namespace;
    private String name;
    @JsonProperty("risk_score")
    private double riskScore;
    private String serviceAccountName;
    private SecurityFacts securityFacts = new SecurityFacts();

    public double getIntrinsicFriction() {
        List<String> passiveResources = List.of(
                "Secret", "ConfigMap",
                "ServiceAccount",
                "Service", "Ingress", "NetworkPolicy"
        );

        // RBAC objects grant permissions; giving them a modest base friction
        // so wildcard/escalation deductions remain distinguishable after clamping.
        List<String> rbacResources = List.of(
                "Role", "ClusterRole", "RoleBinding", "ClusterRoleBinding"
        );

        if (passiveResources.contains(this.type)) {
            return 0.0;
        }
        if (rbacResources.contains(this.type)) {
            return 3.0; // moderate baseline — security deductions remain visible
        }
        // For Workloads (Pods, Deployments, etc.)
        return 10.0 - riskScore;
    }

    @Override
    public int hashCode() {
        return id.hashCode();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null || getClass() != obj.getClass()) return false;
        GraphNode other = (GraphNode) obj;
        return id.equals(other.id);
    }

    @Override
    public String toString() {
        return String.format("%s/%s (%s)", namespace, id, type);
    }
}
