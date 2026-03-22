package io.github.SaptarshiSarkar12.k8sattackmap.ingestion;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

public class KubectlExtractor {
    private static final Logger log = LoggerFactory.getLogger(KubectlExtractor.class);

    public static String fetchClusterStateAsJson() {
        log.info("Fetching cluster state from Kubectl...");
        ProcessBuilder pb = new ProcessBuilder("kubectl", "get",
                "pods,services,configmaps,secrets,serviceaccounts,replicasets,deployments,statefulsets,daemonsets,jobs,cronjobs,ingresses,roles,rolebindings,clusterroles,clusterrolebindings",
                "-A", "-o", "json");
        try (Process process = pb.start()) {
            CompletableFuture<String> outputFuture = CompletableFuture.supplyAsync(() -> {
                try {
                    return new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
                } catch (Exception e) {
                    return "";
                }
            });
            CompletableFuture<String> errorFuture = CompletableFuture.supplyAsync(() -> {
                try {
                    return new String(process.getErrorStream().readAllBytes(), StandardCharsets.UTF_8);
                } catch (Exception e) {
                    return "";
                }
            });
            boolean finishedInTime = process.waitFor(5, TimeUnit.SECONDS);
            if (!finishedInTime) {
                log.error("CRITICAL: kubectl timed out after 5 seconds. The cluster is unreachable.");
                process.destroyForcibly();
                return null;
            }
            int exitCode = process.exitValue();
            String clusterStateJson = outputFuture.get();
            String errorOutput = errorFuture.get();

            if (exitCode == 0) {
                log.debug("Successfully fetched cluster state JSON. Length: {} characters", clusterStateJson.length());
                return clusterStateJson;
            } else {
                log.error("kubectl failed to connect to the cluster. Exit code: {}", exitCode);
                // Clean up the error output so it prints cleanly
                if (!errorOutput.isBlank()) {
                    log.error("Reason: {}", errorOutput.split("\n")[0].trim());
                }
                return null;
            }
        } catch (Exception e) {
            log.error("Exception while executing kubectl: {}", e.getMessage(), e);
            return null;
        }
    }
}
