package io.github.SaptarshiSarkar12.k8sattackmap.model;

import lombok.Getter;
import lombok.Setter;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Stores security-relevant metadata about a Kubernetes resource for risk assessment.
 * <p>
 * Populated during parsing by {@link io.github.SaptarshiSarkar12.k8sattackmap.ingestion.K8sJsonParser}
 * and used by {@link io.github.SaptarshiSarkar12.k8sattackmap.security.EdgeRiskScorer} to compute
 * edge weights (friction). Risk scoring considers:
 * <ul>
 *   <li><strong>RBAC:</strong> Wildcard verbs/resources/apiGroups, escalate/bind/impersonate capabilities</li>
 *   <li><strong>Identity:</strong> ServiceAccount token automount, credential material presence</li>
 *   <li><strong>Runtime Posture:</strong> Privileged containers, allowPrivilegeEscalation, hostPath mounts,
 *       hostPID/Network/IPC, running as root, added Linux capabilities</li>
 *   <li><strong>Infrastructure:</strong> Node-level surface exposure, ingress/service exposure</li>
 * </ul>
 */
@Getter
@Setter
public class SecurityFacts {
    // RBAC
    private boolean rbacWildcardVerb;
    private boolean rbacWildcardResource;
    private boolean rbacWildcardApiGroup;
    private boolean rbacHasEscalate;
    private boolean rbacHasBind;
    private boolean rbacHasImpersonate;
    private Set<String> rbacVerbs = new HashSet<>();
    private Set<String> rbacResources = new HashSet<>();
    private Set<String> rbacApiGroups = new HashSet<>();

    // Identity / secret / credential
    private boolean serviceAccountTokenAutomount;
    private boolean credentialMaterial;
    private String secretType;

    // Workload runtime posture
    private boolean privilegedContainer;
    private boolean allowPrivilegeEscalation;
    private boolean hostPID;
    private boolean hostNetwork;
    private boolean hostIPC;
    private boolean runAsRoot;
    private boolean hostPathMounted;
    private List<String> addedCapabilities = new ArrayList<>();

    // Infra surface
    private boolean nodeLevelSurface;
}