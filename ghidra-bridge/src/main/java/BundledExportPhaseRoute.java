/** Pure invocation-shape selector shared by the wrapper and verifier tests. */
public final class BundledExportPhaseRoute {
    private BundledExportPhaseRoute() {}

    public static String route(String[] arguments) {
        if (arguments.length == 27 && arguments[14].equals("ExportInferredInterfacesV1.class")) return "invocation9";
        if (arguments.length == 34 && arguments[14].equals("ExportInferredInterfacesV1.class") &&
                arguments[27].equals("ExportGlobalTypeObservationsV1.class")) return "invocation10";
        return "none";
    }

    public static boolean hasSharedStagingBudget(String[] arguments) {
        return !route(arguments).equals("none");
    }
}
