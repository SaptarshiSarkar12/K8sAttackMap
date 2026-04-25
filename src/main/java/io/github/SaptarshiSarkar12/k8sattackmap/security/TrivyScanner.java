package io.github.SaptarshiSarkar12.k8sattackmap.security;

import io.github.SaptarshiSarkar12.k8sattackmap.security.trivy.ScanResult;
import io.github.SaptarshiSarkar12.k8sattackmap.security.trivy.TrivyCache;
import io.github.SaptarshiSarkar12.k8sattackmap.security.trivy.TrivyJsonParser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.util.concurrent.CompletableFuture;

public class TrivyScanner {
    private static final Logger log = LoggerFactory.getLogger(TrivyScanner.class);
    private static final TrivyCache trivyCache = new TrivyCache();

    public static ScanResult scanImage(String imageRef) {
        if (imageRef == null || imageRef.isEmpty()) {
            log.warn("Image name is null or empty. Returning default risk score of 0.0.");
            return new ScanResult(0.0, null);
        }
        ScanResult cachedResult = trivyCache.getCachedResult(imageRef);
        if (cachedResult != null) {
            log.debug("CACHE HIT: Found CVSS {} for image {}", cachedResult.cvssScore(), imageRef);
            return cachedResult;
        }
        log.debug("CACHE MISS: Running Trivy scan for {}...", imageRef);
        String trivyJson = getTrivyJson(imageRef);
        if (trivyJson == null) {
            log.warn("Trivy scan failed for image {}. Returning default risk score of 0.0.", imageRef);
            return new ScanResult(0.0, null);
        }
        ScanResult scanResult = TrivyJsonParser.parse(trivyJson);
        trivyCache.saveResultToCache(imageRef, scanResult);
        log.debug("💾 Saved CVSS {} for {} to cache.", scanResult.cvssScore(), imageRef);
        return scanResult;
    }

    private static String getTrivyJson(String imageName) {
        log.debug("Scanning image {}", imageName);
        ProcessBuilder pb = new ProcessBuilder("trivy", "image", "--format", "json", "--quiet", imageName);
        try (Process process = pb.start()) {
            CompletableFuture<String> outputFuture = CompletableFuture.supplyAsync(() -> {
                try {
                    return new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
                } catch (Exception e) {
                    log.error("Error reading Trivy output stream for image {}: {}", imageName, e.getMessage(), e);
                    return "";
                }
            });
            CompletableFuture<String> errorFuture = CompletableFuture.supplyAsync(() -> {
                try {
                    return new String(process.getErrorStream().readAllBytes(), StandardCharsets.UTF_8);
                } catch (Exception e) {
                    log.error("Error reading Trivy error stream for image {}: {}", imageName, e.getMessage(), e);
                    return "";
                }
            });
            int exitCode = process.waitFor();
            String trivyOutput = outputFuture.get();
            String trivyError = errorFuture.get();
            if (exitCode == 0) {
                return trivyOutput;
            } else {
                log.error("Trivy image scan returned with error code {} and error message {}", exitCode, trivyError);
                return null;
            }
        } catch (Exception e) {
            log.error("Error executing Trivy scan for image {}: {}", imageName, e.getMessage(), e);
            return null;
        }
    }
}
