package io.github.SaptarshiSarkar12.k8sattackmap.cli;

import io.github.SaptarshiSarkar12.k8sattackmap.util.AppConstants;
import lombok.Getter;
import org.apache.commons.cli.*;
import org.apache.commons.cli.help.HelpFormatter;
import org.apache.commons.cli.help.TextHelpAppendable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.Set;

@Getter
public class CommandParser {
    private Path k8sJsonPath;
    private String sourceNode; // Todo: Allow multiple source nodes
    private String targetNode; // TODO: Allow multiple target nodes
    private int maxHops = 3;
    private boolean verbose;
    private final Set<String> outputFormats = new HashSet<>();
    private static final Logger log = LoggerFactory.getLogger(CommandParser.class);

    public boolean parse(String[] args) {
        Options options = new Options();
        options.addOption("h", "help", false, "Print this message");
        options.addOption("v", "version", false, "Print version");
        options.addOption("s", "source-node", true, "Source node for pathfinding. Format: <type>:<namespace>:<name>. Example: \"Pod:default:web\"");
        options.addOption("t", "target-node", true, "Target node for pathfinding. Format: <type>:<namespace>:<name>. Example: \"Secret:default:my-secret\"");
        options.addOption("k", "k8s-json", true, "Path to Kubernetes cluster configuration JSON file");
        options.addOption(Option.builder("m").longOpt("max-hops").hasArg().desc("Maximum number of hops for finding affected components for a compromised node (default: 3)").type(Integer.class).get());
        options.addOption(Option.builder("o").longOpt("output").hasArgs().valueSeparator(',').desc("Comma-separated list of output formats ('html' for D3.js map, 'pdf' for report)").get());
        options.addOption(Option.builder().longOpt("verbose").desc("Enable verbose output for debugging").get());
        CommandLineParser parser = new DefaultParser();
        try {
            CommandLine cmd = parser.parse(options, args);
            this.sourceNode = cmd.getOptionValue("source-node");
            this.targetNode = cmd.getOptionValue("target-node");
            this.verbose = cmd.hasOption("verbose");
            if (cmd.hasOption("k8s-json")) {
                try {
                    this.k8sJsonPath = Path.of(cmd.getOptionValue("k8s-json"));
                } catch (InvalidPathException e) {
                    log.warn("Invalid path for k8s-json: {}", e.getMessage(), e);
                }
            }
            if (cmd.hasOption("output")) {
                String[] formats = cmd.getOptionValues("output");
                for (String format : formats) {
                    String fmt = format.trim().toLowerCase();
                    if (fmt.equals("html") || fmt.equals("pdf")) {
                        outputFormats.add(fmt);
                    } else {
                        log.warn("Unsupported output format specified: {}. Supported formats are 'html' and 'pdf'. Ignoring this value.", format);
                    }
                }
            }
            if (cmd.hasOption("max-hops")) {
                this.maxHops = Integer.parseInt(cmd.getOptionValue("max-hops"));
            }
            if (cmd.hasOption("help")) {
                printHelp(options);
                return false;
            }
            if (cmd.hasOption("version")) {
                System.out.println(AppConstants.APP_NAME + " " + AppConstants.APP_VERSION);
                return false;
            }
        } catch (ParseException e) {
            log.error("Error parsing command-line arguments: {}", e.getMessage(), e);
            printHelp(options);
            return false;
        }
        return true;
    }

    private void printHelp(Options options) {
        TextHelpAppendable h = new TextHelpAppendable(System.out);
        h.setMaxWidth(80);
        HelpFormatter formatter = HelpFormatter.builder().setHelpAppendable(h).setShowSince(false).get();
        try {
            formatter.printHelp(AppConstants.APP_NAME, null, options, AppConstants.FOOTER, true);
        } catch (IOException e) {
            log.error("Error printing help message: {}", e.getMessage(), e);
        }
    }
}
