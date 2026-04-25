package io.github.SaptarshiSarkar12.k8sattackmap.analysis.remediation;

import io.github.SaptarshiSarkar12.k8sattackmap.analysis.blast.ImpactedAsset;
import io.github.SaptarshiSarkar12.k8sattackmap.model.GraphNode;

import static io.github.SaptarshiSarkar12.k8sattackmap.util.StringUtils.containsAny;
import static io.github.SaptarshiSarkar12.k8sattackmap.util.StringUtils.safeLower;

public class ImpactRemediationAdvisor {
    private ImpactRemediationAdvisor() {
    }

    public static String recommendAction(ImpactedAsset asset) {
        GraphNode node = asset.node();
        String type = safeLower(node.getType());
        String id = safeLower(node.getId());

        boolean isSecret = type.equals("secret") || id.startsWith("secret:");
        boolean isRoleBinding = type.equals("clusterrolebinding") || type.endsWith("rolebinding");
        boolean isServiceAccount = type.equals("serviceaccount");
        boolean isRole = type.equals("role") || type.equals("clusterrole");
        boolean isPod = type.equals("pod");

        if (isSecret) {
            return "Rotate secrets and restrict secret access.";
        }
        if (isRoleBinding) {
            return "Reduce RBAC grants and enforce least privilege.";
        }
        if (isServiceAccount) {
            return "Scope service account permissions and disable token auto-mount if possible.";
        }
        if (isRole) {
            return "Review and tighten role permissions.";
        }
        if (containsAny(id, "ingress", "loadbalancer", "nodeport")) {
            return "Restrict exposure using network policies and allowlists.";
        }
        if (isPod && containsAny(id, "prod", "vault", "db", "auth", "key")) {
            return "Segment and harden critical pods with strict security contexts and network policies.";
        }
        if (isPod) {
            return "Harden pod security context, restrict capabilities, and enforce network policies.";
        }
        if (containsAny(id, "prod", "vault", "db", "auth", "key")) {
            return "Segment and harden critical workloads.";
        }
        if (type.equals("configmap") || type.equals("persistentvolume")) {
            return "Harden access controls and monitor for suspicious activity.";
        }
        return "Apply least privilege, patching, and configuration hardening.";
    }
}