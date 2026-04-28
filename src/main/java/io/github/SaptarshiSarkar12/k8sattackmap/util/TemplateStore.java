package io.github.SaptarshiSarkar12.k8sattackmap.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Objects;

/**
 * Holds the runtime-loaded HTML/PDF report template strings.
 * Templates are read once at startup via {@link #load(Class)} and
 * are then available as plain fields for the lifetime of the process.
 */
public final class TemplateStore {
    private static final Logger log = LoggerFactory.getLogger(TemplateStore.class);

    private TemplateStore() {}

    public static String HTML;
    public static String PDF;

    /**
     * Loads both templates from the classpath. Exits the process if either
     * template cannot be found, because the application cannot produce any
     * output without them.
     *
     * @param caller the class whose classloader should resolve the resource paths
     */
    public static void load(Class<?> caller) {
        HTML = loadTemplate(caller, AppConstants.HTML_TEMPLATE_RESOURCE_PATH, "HTML");
        PDF  = loadTemplate(caller, AppConstants.PDF_TEMPLATE_RESOURCE_PATH,  "PDF");
    }

    private static String loadTemplate(Class<?> caller, String resourcePath, String label) {
        try {
            return Files.readString(Paths.get(Objects.requireNonNull(caller.getResource(resourcePath)).toURI()));
        } catch (Exception e) {
            return loadTemplateFromStream(caller, resourcePath, label, e);
        }
    }

    private static String loadTemplateFromStream(Class<?> caller, String resourcePath, String label, Exception fallbackException) {
        String adjustedPath = resourcePath.substring(1); // Remove leading slash for classloader access
        try (InputStream is = caller.getClassLoader().getResourceAsStream(adjustedPath)) {
            if (is == null) {
                throw new IOException("Resource not found on classpath: " + adjustedPath);
            }
            return new String(is.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException ex) {
            log.error("Failed to load {} report template from {}: {}", label, resourcePath, fallbackException.getMessage(), fallbackException);
            System.exit(1);
            return null;
        }
    }
}