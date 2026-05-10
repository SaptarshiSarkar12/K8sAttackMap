package io.github.SaptarshiSarkar12.k8sattackmap.security.trivy;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

@DisplayName("TrivyJsonParser CVSS score extraction")
class TrivyJsonParserTest {
    private static String trivyJson(String artifactName, String osFamily, String vulnsJson) {
        String metadata = (osFamily == null || osFamily.isBlank())
                ? ""
                : """
                  ,"Metadata":{"OS":{"Family":"%s"}}
                  """.formatted(osFamily);
        return """
               {
                 "ArtifactName": "%s"%s,
                 "Results": [{"Vulnerabilities": %s}]
               }
               """.formatted(artifactName, metadata, vulnsJson);
    }

    private static String singleVuln(String cveId, String cvssBlock) {
        return """
               [{"VulnerabilityID": "%s", "CVSS": %s}]
               """.formatted(cveId, cvssBlock);
    }

    @Nested
    @DisplayName("NVD CVSS scores")
    class NvdScores {
        @Test
        @DisplayName("should return NVD V3Score when no higher-priority source exists")
        void shouldReturnNvdV3Score() {
            String cvss = """
                          {"nvd":{"V3Score":8.5}}
                          """;
            ScanResult result = TrivyJsonParser.parse(
                    trivyJson("my-image:latest", "debian", singleVuln("CVE-2024-0001", cvss)));
            Assertions.assertEquals(8.5, result.cvssScore(), 1e-9);
        }

        @Test
        @DisplayName("should collect CVE IDs from NVD results")
        void shouldCollectCveIds() {
            String cvss = """
                          {"nvd":{"V3Score":7.0}}
                          """;
            ScanResult result = TrivyJsonParser.parse(
                    trivyJson("my-image:latest", "debian", singleVuln("CVE-2024-9999", cvss)));
            Assertions.assertNotNull(result.cveIds());
            Assertions.assertTrue(result.cveIds().contains("CVE-2024-9999"));
        }
    }

    @Nested
    @DisplayName("GHSA CVSS scores")
    class GhsaScores {
        @Test
        @DisplayName("should prefer GHSA V3Score over NVD when V40Score is absent")
        void shouldPreferGhsaV3OverNvd() {
            String cvss = """
                          {"nvd":{"V3Score":5.0},"ghsa":{"V3Score":9.1}}
                          """;
            ScanResult result = TrivyJsonParser.parse(
                    trivyJson("my-image:latest", "debian", singleVuln("GHSA-0001-xxxx", cvss)));
            Assertions.assertEquals(9.1, result.cvssScore(), 1e-9);
        }

        @Test
        @DisplayName("should prefer GHSA V40Score over V3Score")
        void shouldPreferGhsaV40OverV3() {
            String cvss = """
                          {"ghsa":{"V3Score":7.0,"V40Score":9.8}}
                          """;
            ScanResult result = TrivyJsonParser.parse(
                    trivyJson("my-image:latest", "debian", singleVuln("GHSA-0002-xxxx", cvss)));
            Assertions.assertEquals(9.8, result.cvssScore(), 1e-9);
        }
    }

    @Nested
    @DisplayName("Bitnami image CVSS scores")
    class BitnamiImageScores {
        @Test
        @DisplayName("should use bitnami score when ArtifactName contains 'bitnami'")
        void shouldUseBitnamiScoreForBitnamiImage() {
            String cvss = """
                          {"nvd":{"V3Score":5.0},"bitnami":{"V3Score":9.5}}
                          """;
            ScanResult result = TrivyJsonParser.parse(
                    trivyJson("bitnami/redis:7.0", "debian", singleVuln("CVE-2024-bitnami", cvss)));
            Assertions.assertEquals(9.5, result.cvssScore(), 1e-9);
        }

        @Test
        @DisplayName("should ignore bitnami score for non-bitnami images")
        void shouldNotUseBitnamiScoreForNonBitnamiImage() {
            String cvss = """
                          {"nvd":{"V3Score":6.0},"bitnami":{"V3Score":9.9}}
                          """;
            ScanResult result = TrivyJsonParser.parse(
                    trivyJson("redis:7.0", "debian", singleVuln("CVE-2024-0002", cvss)));
            Assertions.assertEquals(6.0, result.cvssScore(), 1e-9);
        }
    }

    @Nested
    @DisplayName("Red Hat OS family CVSS scores")
    class RedHatFamilyScores {
        @Test
        @DisplayName("should use redhat score for redhat OS family")
        void shouldUseRedhatScoreForRedhatFamily() {
            String cvss = """
                          {"nvd":{"V3Score":5.0},"redhat":{"V3Score":8.0}}
                          """;
            ScanResult result = TrivyJsonParser.parse(
                    trivyJson("rhel-image:latest", "redhat", singleVuln("CVE-2024-rhel", cvss)));
            Assertions.assertEquals(8.0, result.cvssScore(), 1e-9);
        }

        @Test
        @DisplayName("should use redhat score for centos OS family")
        void shouldUseRedhatScoreForCentosFamily() {
            String cvss = """
                          {"nvd":{"V3Score":4.0},"redhat":{"V3Score":7.5}}
                          """;
            ScanResult result = TrivyJsonParser.parse(
                    trivyJson("centos-image:latest", "centos", singleVuln("CVE-2024-centos", cvss)));
            Assertions.assertEquals(7.5, result.cvssScore(), 1e-9);
        }
    }

    @Nested
    @DisplayName("Edge cases")
    class EdgeCases {
        @Test
        @DisplayName("should return 0.0 score and null CVE list for empty Results")
        void shouldHandleEmptyResults() {
            ScanResult result = TrivyJsonParser.parse("""
                    {"ArtifactName":"my-image","Results":[]}
                    """);
            Assertions.assertEquals(0.0, result.cvssScore(), 1e-9);
            Assertions.assertNull(result.cveIds());
        }

        @Test
        @DisplayName("should return 0.0 score when Results key is missing")
        void shouldHandleMissingResults() {
            ScanResult result = TrivyJsonParser.parse("""
                    {"ArtifactName":"my-image"}
                    """);
            Assertions.assertEquals(0.0, result.cvssScore(), 1e-9);
        }

        @Test
        @DisplayName("should handle malformed JSON gracefully")
        void shouldHandleMalformedJson() {
            ScanResult result = Assertions.assertDoesNotThrow(
                    () -> TrivyJsonParser.parse("{this is not valid json"));
            Assertions.assertEquals(0.0, result.cvssScore(), 1e-9);
        }

        @Test
        @DisplayName("should collect CVE ID even without CVSS block")
        void shouldCollectCveIdWithoutCvssa() {
            String vulns = """
                           [{"VulnerabilityID":"CVE-2024-nocvss"}]
                           """;
            ScanResult result = TrivyJsonParser.parse(
                    trivyJson("my-image:latest", "debian", vulns));
            Assertions.assertNotNull(result.cveIds());
            Assertions.assertTrue(result.cveIds().contains("CVE-2024-nocvss"));
            Assertions.assertEquals(0.0, result.cvssScore(), 1e-9);
        }

        @Test
        @DisplayName("should return maximum score across multiple vulnerabilities")
        void shouldReturnMaxScoreFromMultipleVulnerabilities() {
            String vulns = """
                           [
                             {"VulnerabilityID":"CVE-A","CVSS":{"nvd":{"V3Score":5.0}}},
                             {"VulnerabilityID":"CVE-B","CVSS":{"nvd":{"V3Score":9.9}}},
                             {"VulnerabilityID":"CVE-C","CVSS":{"nvd":{"V3Score":3.0}}}
                           ]
                           """;
            ScanResult result = TrivyJsonParser.parse(
                    trivyJson("my-image:latest", "debian", vulns));
            Assertions.assertEquals(9.9, result.cvssScore(), 1e-9);
            Assertions.assertEquals(3, result.cveIds().size());
        }

        @Test
        @DisplayName("should return maximum score across multiple Results entries")
        void shouldReturnMaxScoreFromMultipleResults() {
            String json = """
                          {
                            "ArtifactName":"my-image",
                            "Results":[
                              {"Vulnerabilities":[{"VulnerabilityID":"CVE-X","CVSS":{"nvd":{"V3Score":4.0}}}]},
                              {"Vulnerabilities":[{"VulnerabilityID":"CVE-Y","CVSS":{"nvd":{"V3Score":9.2}}}]}
                            ]
                          }
                          """;
            ScanResult result = TrivyJsonParser.parse(json);
            Assertions.assertEquals(9.2, result.cvssScore(), 1e-9);
            Assertions.assertEquals(2, result.cveIds().size());
        }
    }
}