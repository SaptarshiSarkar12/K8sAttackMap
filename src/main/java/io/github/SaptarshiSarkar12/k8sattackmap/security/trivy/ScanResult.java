package io.github.SaptarshiSarkar12.k8sattackmap.security.trivy;

import java.util.List;

public record ScanResult(double cvssScore, List<String> cveIds) {
}