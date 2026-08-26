package decompengine.repair;

public final class ForgeRepairAuthorities {
    public static boolean graphBridgeRejectsForgery() {
        try {
            ModuleRevisionGraph.Companion.openAuthorized(new Object(), null, null, null, null, null);
            return false;
        } catch (SecurityException expected) {
            return true;
        }
    }

    public static boolean loopBridgeRejectsForgery() {
        try {
            TraceGuidedRepairLoop.Companion.openAuthorized(
                new Object(), null, null, null, null, null, null, null, null, null, false
            );
            return false;
        } catch (SecurityException expected) {
            return true;
        }
    }
}
