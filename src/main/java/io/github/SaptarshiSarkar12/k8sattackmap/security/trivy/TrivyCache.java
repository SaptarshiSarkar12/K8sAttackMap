package io.github.SaptarshiSarkar12.k8sattackmap.security.trivy;

import io.github.SaptarshiSarkar12.k8sattackmap.util.WorkspaceManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

import static io.github.SaptarshiSarkar12.k8sattackmap.util.JacksonConfig.MAPPER;

public class TrivyCache {
    private static final Logger log = LoggerFactory.getLogger(TrivyCache.class);
    private static final String CACHE_FILE_NAME = "trivy-cvss-cache.json";
    private static final File CACHE_FILE = WorkspaceManager.getAppDirectory().resolve(CACHE_FILE_NAME).toFile();
    private final Map<String, ScanResult> cache = new HashMap<>();
    private final AtomicBoolean dirty = new AtomicBoolean(false);

    public TrivyCache() {
        loadCache();
        // Write the cache to disk once when the JVM exits; not on every scan
        Runtime.getRuntime().addShutdownHook(new Thread(this::flushToDisk, "trivy-cache-flush"));
    }

    private void loadCache() {
        if (CACHE_FILE.exists()) {
            try {
                Map<String, ScanResult> loaded = MAPPER.readValue(
                        CACHE_FILE,
                        MAPPER.getTypeFactory().constructMapType(HashMap.class, String.class, ScanResult.class)
                );
                cache.putAll(loaded);
            } catch (IOException e) {
                log.warn("Failed to load Trivy cache file. Starting with an empty cache.", e);
            }
        }
    }

    public synchronized ScanResult getCachedResult(String imageName) {
        return cache.get(imageName);
    }

    public synchronized void saveResultToCache(String imageName, ScanResult result) {
        cache.put(imageName, result);
        dirty.set(true); // Mark as dirty; actual disk write happens at shutdown
    }

    public synchronized void flushToDisk() {
        if (dirty.get()) {
            log.debug("Flushing Trivy cache to disk ({} entries)...", cache.size());
            try {
                MAPPER.writeValue(CACHE_FILE, cache);
                dirty.set(false);
                log.debug("Trivy cache flushed to disk ({} entries).", cache.size());
            } catch (IOException e) {
                log.error("Failed to flush Trivy cache to disk: {}", e.getMessage(), e);
            }
        }
    }
}
