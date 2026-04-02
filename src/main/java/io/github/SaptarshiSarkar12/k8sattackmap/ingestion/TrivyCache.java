package io.github.SaptarshiSarkar12.k8sattackmap.ingestion;

import io.github.SaptarshiSarkar12.k8sattackmap.util.WorkspaceManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.nio.file.Path;
import java.util.Properties;

public class TrivyCache {
    private static final Logger log = LoggerFactory.getLogger(TrivyCache.class);
    private static final String CACHE_FILE_NAME = "trivy-cvss-cache.properties";
    private static final File CACHE_FILE = WorkspaceManager.getAppDirectory().resolve(CACHE_FILE_NAME).toFile();
    private final Properties cache;

    public TrivyCache() {
        this.cache = new Properties();
        loadCache();
    }

    private void loadCache() {
        if (CACHE_FILE.exists()) {
            try (InputStream input = new FileInputStream(CACHE_FILE)) {
                cache.load(input);
            } catch (IOException e) {
                log.warn("Failed to load Trivy cache file. Starting with an empty cache.", e);
            }
        }
    }

    public Double getCachedScore(String imageName) {
        String score = cache.getProperty(imageName);
        if (score != null) {
            return Double.parseDouble(score);
        }
        return null; // Cache miss
    }

    public synchronized void saveScoreToCache(String imageName, double cvssScore) {
        cache.setProperty(imageName, String.valueOf(cvssScore));

        try (OutputStream output = new FileOutputStream(CACHE_FILE)) {
            // The second parameter is a comment written at the top of the file
            cache.store(output, "K8sAttackMap - Trivy CVSS Score Cache");
        } catch (IOException e) {
            log.error("Failed to save CVSS score to cache file for image {}: {}", imageName, e.getMessage(), e);
        }
    }
}