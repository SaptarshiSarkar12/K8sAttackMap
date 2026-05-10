package io.github.SaptarshiSarkar12.k8sattackmap.ingestion;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("KubectlExtractor Tests")
class KubectlExtractorTest {
    @Test
    @DisplayName("getClusterContext returns a non-null value")
    void getClusterContextReturnsNonNullValue() {
        Assertions.assertNotNull(KubectlExtractor.getClusterContext());
    }

    @Test
    @DisplayName("fetchClusterStateAsJson does not throw an exception")
    void fetchClusterStateAsJsonDoesNotThrow() {
        Assertions.assertDoesNotThrow(KubectlExtractor::fetchClusterStateAsJson);
    }
}