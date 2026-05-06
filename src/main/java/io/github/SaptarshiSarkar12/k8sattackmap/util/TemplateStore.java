package io.github.SaptarshiSarkar12.k8sattackmap.util;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

@Slf4j
public final class TemplateStore {
    @Getter
    private static volatile String html;
    @Getter
    private static volatile String pdf;

    private TemplateStore() {
    }

    public static void load(Class<?> caller) {
        Objects.requireNonNull(caller, "caller must not be null");
        html = readResourceText(caller, AppConstants.HTML_TEMPLATE_RESOURCE_PATH, "HTML");
        pdf = readResourceText(caller, AppConstants.PDF_TEMPLATE_RESOURCE_PATH, "PDF");
    }

    private static String readResourceText(Class<?> caller, String resourcePath, String label) {
        try (InputStream inputStream = caller.getResourceAsStream(resourcePath)) {
            if (inputStream == null) {
                throw new IllegalStateException("Missing " + label + " template on classpath: " + resourcePath);
            }
            return new String(inputStream.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            log.error("Failed to read {} template from {}", label, resourcePath, e);
            throw new IllegalStateException("Unable to read " + label + " template: " + resourcePath, e);
        }
    }
}