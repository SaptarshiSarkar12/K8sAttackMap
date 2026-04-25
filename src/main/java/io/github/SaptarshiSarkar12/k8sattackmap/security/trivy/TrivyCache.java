package io.github.SaptarshiSarkar12.k8sattackmap.security.trivy;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.SaptarshiSarkar12.k8sattackmap.util.WorkspaceManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.util.HashMap;
import java.util.Map;

public class TrivyCache {
    private static final Logger log = LoggerFactory.getLogger(TrivyCache.class);
    private static final String CACHE_FILE_NAME = "trivy-cvss-cache.json";
    private static final File CACHE_FILE = WorkspaceManager.getAppDirectory().resolve(CACHE_FILE_NAME).toFile();
    private final Map<String, ScanResult> cache = new HashMap<>();
    private final ObjectMapper mapper = new ObjectMapper();

    public TrivyCache() {
        loadCache();
    }

    private void loadCache() {
        if (CACHE_FILE.exists()) {
            try {
                Map<String, ScanResult> loaded = mapper.readValue(
                        CACHE_FILE,
                        mapper.getTypeFactory().constructMapType(HashMap.class, String.class, ScanResult.class)
                );
                cache.putAll(loaded);
            } catch (IOException e) {
                log.warn("Failed to load Trivy cache file. Starting with an empty cache.", e);
            }
        }
    }

    public ScanResult getCachedResult(String imageName) {
        return cache.get(imageName);
    }

    public synchronized void saveResultToCache(String imageName, ScanResult result) {
        cache.put(imageName, result);
        try {
            mapper.writeValue(CACHE_FILE, cache);
        } catch (IOException e) {
            log.error("Failed to save result to cache file for image {}: {}", imageName, e.getMessage(), e);
        }
    }
}
