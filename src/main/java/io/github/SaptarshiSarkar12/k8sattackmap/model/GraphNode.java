package io.github.SaptarshiSarkar12.k8sattackmap.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.Setter;

import java.util.List;

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
