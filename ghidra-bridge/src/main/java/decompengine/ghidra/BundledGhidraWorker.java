package decompengine.ghidra;

import generic.stl.Pair;
import ghidra.GhidraApplicationLayout;
import ghidra.app.util.headless.HeadlessAnalyzer;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public final class BundledGhidraWorker {
    private static boolean exportsCompleted;

    public static void exportsCompleted() {
        exportsCompleted = true;
    }

    public static void main(String[] arguments) {
        try {
            run(arguments);
            System.exit(0);
        } catch (Exception failure) {
            failure.printStackTrace(System.err);
            System.exit(1);
        }
    }

    private static void run(String[] arguments) throws Exception {
        if (arguments.length < 2) throw new IllegalArgumentException("Expected bundle and operation");
        Path bundle = Path.of(arguments[0]).toAbsolutePath().normalize();
        var configuration = new HeadlessGhidraApplicationConfiguration();
        Application.initializeApplication(new GhidraApplicationLayout(bundle.toFile()), configuration);
        if (arguments.length == 2 && arguments[1].equals("probe")) {
            var languages = ghidra.program.util.DefaultLanguageService.getLanguageService();
            if (languages.getLanguageDescriptions(false).isEmpty()) {
                throw new IllegalStateException("Bundled Ghidra has no processor languages");
            }
            System.out.println("Bundled Ghidra direct API ready: " + Application.getApplicationVersion());
            return;
        }
        if (arguments.length < 8 || !arguments[1].equals("analyze")) {
            throw new IllegalArgumentException("Expected analyze, project, name, input, scripts and post-script arguments");
        }
        Path project = Path.of(arguments[2]);
        String projectName = arguments[3];
        Path binary = Path.of(arguments[4]);
        Path scripts = Path.of(arguments[5]);
        List<Pair<String, String[]>> postScripts = new ArrayList<>();
        for (int index = 6; index < arguments.length;) {
            String script = arguments[index++];
            int count = Integer.parseInt(arguments[index++]);
            if (count < 0 || count > 16 || count > arguments.length - index) {
                throw new IllegalArgumentException("Invalid post-script argument count");
            }
            postScripts.add(new Pair<>(script, Arrays.copyOfRange(arguments, index, index + count)));
            index += count;
        }
        Files.createDirectories(project);
        HeadlessAnalyzer analyzer = HeadlessAnalyzer.getInstance();
        analyzer.getOptions().enableOverwriteOnConflict(true);
        analyzer.getOptions().setScriptDirectories(List.of(bundle.getParent().resolve("scripts").toString(), scripts.toString()));
        List<String> guardedArguments = new ArrayList<>();
        for (Pair<String, String[]> script : postScripts) {
            guardedArguments.add(script.first);
            guardedArguments.add(Integer.toString(script.second.length));
            guardedArguments.addAll(Arrays.asList(script.second));
        }
        analyzer.getOptions().setPostScriptsWithArgs(List.of(new Pair<>(
            "RunBundledExports.class", guardedArguments.toArray(String[]::new))));
        analyzer.processLocal(project.toString(), projectName, "/", List.of(binary.toFile()));
        if (analyzer.checkAnalysisTimedOut()) throw new IllegalStateException("Ghidra analysis timed out");
        if (!exportsCompleted) throw new IllegalStateException("Bundled Ghidra import or export failed; existing output is not a successful result");
    }
}
