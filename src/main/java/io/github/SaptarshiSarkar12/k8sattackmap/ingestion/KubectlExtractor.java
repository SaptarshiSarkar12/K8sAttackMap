package io.github.SaptarshiSarkar12.k8sattackmap.ingestion;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

public class KubectlExtractor {
    private static final Logger log = LoggerFactory.getLogger(KubectlExtractor.class);

    public static String fetchClusterStateAsJson() {
        log.info("Fetching cluster state from Kubectl...");
        ProcessBuilder pb = new ProcessBuilder("kubectl", "get",
                "pods,services,configmaps,secrets,serviceaccounts,replicasets,deployments,statefulsets,daemonsets,jobs,cronjobs,ingresses,roles,rolebindings,clusterroles,clusterrolebindings,nodes",
                "-A", "-o", "json");
        Process process;
        try {
            process = pb.start();
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

    public static String getClusterContext() {
        final String unknown = "Unknown/Offline Environment";
        ProcessBuilder processBuilder = new ProcessBuilder("kubectl", "config", "current-context").redirectErrorStream(true);
        Process process;
        BufferedReader outputReader;
        try {
            process = processBuilder.start();
            outputReader = new BufferedReader(process.inputReader(StandardCharsets.UTF_8));
            if (!process.waitFor(5, TimeUnit.SECONDS)) {
                process.destroyForcibly();
                return unknown;
            }

            int exitCode = process.exitValue();
            String context = outputReader.readLine();

            if (exitCode != 0 || context == null || context.trim().isEmpty()) {
                log.debug("Could not determine cluster context. kubectl exit code: {}, output: {}", exitCode, context);
                return unknown;
            }

            context = context.trim();

            if (context.startsWith("arn:aws:eks:")) {
                return context.substring(context.lastIndexOf("/") + 1);
            }

            if (context.startsWith("gke_")) {
                String[] parts = context.split("_");
                return parts[parts.length - 1];
            }

            if (context.startsWith("kind-")) {
                return context.replace("kind-", "") + " (Local)";
            }

            if (context.equals("minikube")) {
                return "Minikube (Local Development)";
            }

            return context;
        } catch (Exception e) {
            log.error("Exception while fetching cluster context: {}", e.getMessage(), e);
            return unknown;
        }
    }
}
