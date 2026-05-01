package io.github.SaptarshiSarkar12.k8sattackmap.util;

import lombok.Getter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.io.IOException;

public class WorkspaceManager {
    private static final Logger log = LoggerFactory.getLogger(WorkspaceManager.class);
    @Getter
    private static Path appDirectory;

    public static void initializeWorkspace() {
        String os = System.getProperty("os.name").toLowerCase();

        if (os.contains("win")) {
            // Use %LOCALAPPDATA% on Windows, fallback to user.home if missing
            String localAppData = System.getenv("LOCALAPPDATA");
            if (localAppData != null && !localAppData.isBlank()) {
                appDirectory = resolveWorkspaceUnderBase(localAppData, "k8sattackmap");
            } else {
                appDirectory = resolveWorkspaceUnderBase(System.getProperty("user.home"), ".k8sattackmap");
            }
        } else {
            // Use ~/.k8sattackmap for Linux and macOS
            appDirectory = resolveWorkspaceUnderBase(System.getProperty("user.home"), ".k8sattackmap");
        }

        try {
            if (Files.notExists(appDirectory)) {
                Files.createDirectories(appDirectory);
                log.debug("Created application directory at {}", appDirectory.toAbsolutePath());
            }
        } catch (IOException e) {
            log.error("Error creating app directory", e);
            System.exit(1);
        } catch (IllegalArgumentException e) {
            log.error("Invalid workspace directory configuration", e);
            System.exit(1);
        }
    }

    private static Path resolveWorkspaceUnderBase(String baseDir, String childDirName) {
        if (baseDir == null || baseDir.isBlank()) {
            throw new IllegalArgumentException("Base directory is missing");
        }
        if (childDirName == null || childDirName.isBlank()
                || childDirName.contains("..")
                || childDirName.contains("/")
                || childDirName.contains("\\")) {
            throw new IllegalArgumentException("Invalid child directory name");
        }

        Path basePath = Paths.get(baseDir).toAbsolutePath().normalize();
        Path resolvedPath = basePath.resolve(childDirName).toAbsolutePath().normalize();

        if (!resolvedPath.startsWith(basePath)) {
            throw new IllegalArgumentException("Resolved workspace directory escapes base directory");
        }

        return resolvedPath;
    }
}