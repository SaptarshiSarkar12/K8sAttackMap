package io.github.SaptarshiSarkar12.k8sattackmap.cli;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("CommandParser parses CLI arguments into typed fields")
class CommandParserTest {
    @Test
    @DisplayName("parses -k flag and stores the k8s JSON path")
    void shouldParseK8sJsonPath() {
        CommandParser parser = new CommandParser();
        boolean result = parser.parse(new String[]{"-k", "cluster.json"});

        assertTrue(result);
        assertNotNull(parser.getK8sJsonPath());
        assertEquals("cluster.json", parser.getK8sJsonPath().toString());
    }

    @Test
    @DisplayName("parses -s flag and populates source node set")
    void shouldParseSourceNodes() {
        CommandParser parser = new CommandParser();
        parser.parse(new String[]{"-s", "Pod:default:web,Pod:default:api"});

        assertEquals(2, parser.getSourceNodes().size());
        assertTrue(parser.getSourceNodes().contains("Pod:default:web"));
        assertTrue(parser.getSourceNodes().contains("Pod:default:api"));
    }

    @Test
    @DisplayName("parses -t flag and populates target node set")
    void shouldParseTargetNodes() {
        CommandParser parser = new CommandParser();
        parser.parse(new String[]{"-t", "Secret:default:db-creds"});

        assertEquals(1, parser.getTargetNodes().size());
        assertTrue(parser.getTargetNodes().contains("Secret:default:db-creds"));
    }

    @Test
    @DisplayName("parses -o flag and accepts html and pdf as valid output formats")
    void shouldParseOutputFormats() {
        CommandParser parser = new CommandParser();
        parser.parse(new String[]{"-o", "html,pdf"});

        assertTrue(parser.getOutputFormats().contains("html"));
        assertTrue(parser.getOutputFormats().contains("pdf"));
    }

    @Test
    @DisplayName("ignores unsupported output format and does not add it to the set")
    void shouldIgnoreUnsupportedOutputFormat() {
        CommandParser parser = new CommandParser();
        parser.parse(new String[]{"-o", "html,json"});

        assertTrue(parser.getOutputFormats().contains("html"));
        assertFalse(parser.getOutputFormats().contains("json"));
    }

    @Test
    @DisplayName("parses -m flag and sets max hops")
    void shouldParseMaxHops() {
        CommandParser parser = new CommandParser();
        parser.parse(new String[]{"-m", "5"});

        assertEquals(5, parser.getMaxHops());
    }

    @Test
    @DisplayName("defaults maxHops to 3 when -m flag is not provided")
    void shouldDefaultMaxHopsToThree() {
        CommandParser parser = new CommandParser();
        parser.parse(new String[]{"-k", "cluster.json"});

        assertEquals(3, parser.getMaxHops());
    }

    @Test
    @DisplayName("parses --show-all-paths flag and sets the field to true")
    void shouldParseShowAllPathsFlag() {
        CommandParser parser = new CommandParser();
        parser.parse(new String[]{"--show-all-paths"});

        assertTrue(parser.isShowAllPaths());
    }

    @Test
    @DisplayName("showAllPaths defaults to false when flag is absent")
    void shouldDefaultShowAllPathsToFalse() {
        CommandParser parser = new CommandParser();
        parser.parse(new String[]{"-k", "cluster.json"});

        assertFalse(parser.isShowAllPaths());
    }

    @Test
    @DisplayName("parses --verbose flag and sets the verbose field to true")
    void shouldParseVerboseFlag() {
        CommandParser parser = new CommandParser();
        parser.parse(new String[]{"--verbose"});

        assertTrue(parser.isVerbose());
    }

    @Test
    @DisplayName("returns false and does not throw when --help flag is provided")
    void shouldReturnFalseForHelpFlag() {
        CommandParser parser = new CommandParser();
        boolean result = assertDoesNotThrow(() -> parser.parse(new String[]{"--help"}));
        assertFalse(result);
    }

    @Test
    @DisplayName("returns false and does not throw when --version flag is provided")
    void shouldReturnFalseForVersionFlag() {
        CommandParser parser = new CommandParser();
        boolean result = assertDoesNotThrow(() -> parser.parse(new String[]{"--version"}));
        assertFalse(result);
    }

    @Test
    @DisplayName("returns false and does not throw for an unrecognised flag")
    void shouldReturnFalseForUnknownFlag() {
        CommandParser parser = new CommandParser();
        boolean result = assertDoesNotThrow(() -> parser.parse(new String[]{"--unknown-flag"}));
        assertFalse(result);
    }

    @Test
    @DisplayName("returns true when valid arguments are provided with no issues")
    void shouldReturnTrueForValidArguments() {
        CommandParser parser = new CommandParser();
        boolean result = parser.parse(new String[]{
                "-k", "cluster.json",
                "-s", "Pod:default:web",
                "-t", "Secret:default:db",
                "-o", "html",
                "-m", "4"
        });
        assertTrue(result);
    }
}