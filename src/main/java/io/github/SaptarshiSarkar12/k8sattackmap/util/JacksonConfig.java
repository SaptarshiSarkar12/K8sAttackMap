package io.github.SaptarshiSarkar12.k8sattackmap.util;

import com.fasterxml.jackson.databind.ObjectMapper;

public final class JacksonConfig {
    private JacksonConfig() {}

    public static final ObjectMapper MAPPER = new ObjectMapper();
}