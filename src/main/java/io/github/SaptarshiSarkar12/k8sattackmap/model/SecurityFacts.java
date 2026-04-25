package io.github.SaptarshiSarkar12.k8sattackmap.model;

import lombok.Getter;
import lombok.Setter;

import java.util.ArrayList;
import java.util.List;

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
    private List<String> rbacVerbs = new ArrayList<>();
    private List<String> rbacResources = new ArrayList<>();
    private List<String> rbacApiGroups = new ArrayList<>();

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