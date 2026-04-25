package io.github.SaptarshiSarkar12.k8sattackmap.security.trivy;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

public class TrivyJsonParser {
    private static final Logger log = LoggerFactory.getLogger(TrivyJsonParser.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    public static ScanResult parse(String trivyJson) {
        try {
            JsonNode root = MAPPER.readTree(trivyJson);
            JsonNode results = root.path("Results");
            if (results.isMissingNode() || !results.isArray() || results.isEmpty()) {
                return new ScanResult(0.0, null);
            }

            String imageFamily = "unknown";
            if (root.has("Metadata") && root.path("Metadata").has("OS")) {
                imageFamily = root.path("Metadata").path("OS").path("Family").asText(); // e.g., "debian"
            }
            boolean isBitnamiImage = root.path("ArtifactName").asText().contains("bitnami");
            if (isBitnamiImage) {
                imageFamily = "bitnami";
            }
            double maxScore = 0.0;
            List<String> allCveIds = new ArrayList<>();
            for (JsonNode result : results) {
                JsonNode vulnerabilities = result.path("Vulnerabilities");
                if (!vulnerabilities.isMissingNode()) {
                    ScanResult scanResult = getScanResult(vulnerabilities, imageFamily);
                    allCveIds.addAll(scanResult.cveIds());
                    double score = scanResult.cvssScore();
                    if (score > maxScore) {
                        maxScore = score;
                    }
                }
            }
            return new ScanResult(maxScore, allCveIds);
        } catch (Exception e) {
            log.error("Error parsing Trivy JSON: {}", e.getMessage(), e);
            return new ScanResult(0.0, null);
        }
    }

    private static ScanResult getScanResult(JsonNode vulnerabilities, String imageFamily) {
        double maxScore = 0.0;
        List<String> cveIds = new ArrayList<>();
        for (JsonNode vuln : vulnerabilities) {
            JsonNode vulnerabilityId = vuln.path("VulnerabilityID");
            JsonNode cvss = vuln.path("CVSS");
            if (!cvss.isMissingNode()) {
                maxScore = Math.max(maxScore, getCVSSScore(cvss, imageFamily));
            }
            cveIds.add(vulnerabilityId.asText());
        }
        return new ScanResult(maxScore, cveIds);
    }

    private static double getCVSSScore(JsonNode cvss, String imageFamily) {
        List<String> redhatFamily = List.of("redhat", "centos", "fedora", "rocky", "alma", "oracle");
        boolean isRedHatFamily = redhatFamily.contains(imageFamily.toLowerCase());
        boolean isBitnamiImage = imageFamily.equals("bitnami");

        if (isBitnamiImage && cvss.has("bitnami")) {
            return cvss.path("bitnami").path("V3Score").asDouble();
        }

        if (isRedHatFamily && cvss.has("redhat")) {
            return cvss.path("redhat").path("V3Score").asDouble();
        }

        JsonNode ghsa = cvss.path("ghsa");
        if (!ghsa.isMissingNode()) {
            if (ghsa.has("V40Score")) {
                return ghsa.path("V40Score").asDouble();
            } else {
                return ghsa.path("V3Score").asDouble();
            }
        }

        JsonNode nvd = cvss.path("nvd");
        if (!nvd.isMissingNode()) {
            return nvd.path("V3Score").asDouble();
        }

        double maxVendorScore = 0.0;
        for (JsonNode vendorScore : cvss) {
            if (vendorScore.has("V3Score")) {
                maxVendorScore = Math.max(maxVendorScore, vendorScore.path("V3Score").asDouble());
            }
        }

        return maxVendorScore;
    }
}