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
    private SecurityFacts securityFacts = new SecurityFacts();

    public double getIntrinsicFriction() {
        List<String> passiveResources = List.of(
                "Secret", "ConfigMap",
                "ServiceAccount", "Role", "ClusterRole", "RoleBinding", "ClusterRoleBinding",
                "Service", "Ingress", "NetworkPolicy"
        );

        if (passiveResources.contains(this.type)) {
            // The attacker just "takes" or "uses" these once the Edge is traversed.
            return 0.0;
        }
        // For Workloads (Pods, Deployments, etc.)
        // A perfectly secure pod (riskScore = 0.0) has Max Friction (10.0).
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
