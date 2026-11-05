package ghidra.program.database.data;

import ghidra.program.model.listing.Data;
import ghidra.program.model.data.*;
import ghidra.framework.data.OwnedProgramIntegrityException;
import ghidra.util.task.*;
import java.util.*;

/** Real dependency origin controls: no public policy marker and no positive fixture authority. */
final class OwnedPointerOriginControls {
    static void cleanReceipt(OwnedFixture f) {
        try { f.program.checkOwnedIntegrity(); }
        catch (Throwable failure) { throw new AssertionError("genuine policy refusal receipt clean", failure); }
    }
    static UnsupportedOperationException savedPolicy() throws Exception {
        try (OwnedFixture f = new OwnedFixture()) {
            Data component = OwnedPointerLifecycleTest.deepComponent(f);
            Throwable policy = OwnedFixture.fails(UnsupportedOperationException.class, () -> f.observe(component));
            cleanReceipt(f);
            return (UnsupportedOperationException) policy;
        }
    }
    static OwnedProgramIntegrityException receipt(OwnedFixture f, Throwable original) throws Exception {
        Throwable receipt = OwnedFixture.fails(OwnedProgramIntegrityException.class, f.program::checkOwnedIntegrity);
        OwnedFixture.check(receipt.getCause() == original, "origin receipt retains exact original Throwable");
        OwnedFixture.check(OwnedFixture.fails(OwnedProgramIntegrityException.class, f.program::checkOwnedIntegrity) == receipt,
            "same stored receipt identity");
        return (OwnedProgramIntegrityException) receipt;
    }
    static void sweep(String shape, int expected) throws Exception {
        try (OwnedFixture f = new OwnedFixture()) {
            Data data = shape.equals("component") ? OwnedPointerLifecycleTest.deepComponent(f) : f.data(null);
            if (shape.equals("instance")) data.setLong("mutability", 2);
            int[] visits = {0};
            TaskMonitor monitor = new TaskMonitorAdapter() { public void checkCancelled() { visits[0]++; } };
            if (shape.equals("component")) OwnedFixture.fails(UnsupportedOperationException.class,
                () -> f.manager.observePointerReference(data, monitor));
            else OwnedFixture.check(f.manager.observePointerReference(data, monitor).childID() == -1, "valid observation");
            OwnedFixture.check(visits[0] == expected, "exact 14/17/37 checkpoints");
            cleanReceipt(f);
        }
        for (int at = 1; at <= expected; at++) try (OwnedFixture f = new OwnedFixture()) {
            Data data = shape.equals("component") ? OwnedPointerLifecycleTest.deepComponent(f) : f.data(null);
            if (shape.equals("instance")) data.setLong("mutability", 2);
            final int checkpoint = at;
            UnsupportedOperationException original = new UnsupportedOperationException("one-shot monitor");
            int[] visits = {0};
            TaskMonitor monitor = new TaskMonitorAdapter() {
                public void checkCancelled() { if (++visits[0] == checkpoint) throw original; }
            };
            Throwable thrown = OwnedFixture.fails(UnsupportedOperationException.class,
                () -> f.manager.observePointerReference(data, monitor));
            if (shape.equals("component") && at == expected) {
                OwnedFixture.check(thrown != original && thrown.getSuppressed().length == 1 &&
                    thrown.getSuppressed()[0] == original, "local policy primary then exact cleanup failure");
            }
            else OwnedFixture.check(thrown == original, "monitor throws exact original");
            OwnedFixture.check(f.manager.lock.getOwner() == null, "origin sweep releases lock");
            OwnedProgramIntegrityException saved = receipt(f, original);
            OwnedFixture.check(OwnedFixture.fails(OwnedProgramIntegrityException.class, () -> f.observe(data)) == saved,
                "origin retry cannot admit observation");
            System.out.println("PASS origin " + shape + " checkpoint=" + at);
        }
    }
    static void reentryAndSavedPolicy() throws Exception {
        for (int at : new int[]{3, 4}) try (OwnedFixture f = new OwnedFixture()) {
            Data data = f.data(null);
            UnsupportedOperationException original = savedPolicy();
            int[] visits = {0}; boolean[] reentered = {false};
            TaskMonitor monitor = new TaskMonitorAdapter() {
                public void checkCancelled() {
                    if (++visits[0] == at) throw original;
                    if (visits[0] > at) {
                        try {
                            OwnedProgramIntegrityException saved = receipt(f, original);
                            OwnedFixture.check(OwnedFixture.fails(OwnedProgramIntegrityException.class,
                                () -> f.observe(data)) == saved, "reentry sees latched origin");
                            reentered[0] = true;
                        }
                        catch (Exception e) { throw new AssertionError(e); }
                    }
                }
            };
            OwnedFixture.check(OwnedFixture.fails(UnsupportedOperationException.class,
                () -> f.manager.observePointerReference(data, monitor)) == original, "saved policy callback identity");
            receipt(f, original);
            OwnedFixture.check(reentered[0] && f.manager.lock.getOwner() == null,
                "reentry after one-shot checkpoint3/4 cannot bypass latch");
        }
    }
    static void cleanupIdentity() throws Exception {
        try (OwnedFixture f = new OwnedFixture()) {
            Data data = f.data(null);
            UnsupportedOperationException original = savedPolicy();
            UnsupportedOperationException later = new UnsupportedOperationException("later cleanup monitor");
            TaskMonitor monitor = new TaskMonitorAdapter() {
                int visits;
                public void checkCancelled() {
                    if (++visits == 3) { f.manager.lock.release(); throw original; }
                    if (visits == 4) throw later;
                }
            };
            Throwable thrown = OwnedFixture.fails(UnsupportedOperationException.class,
                () -> f.manager.observePointerReference(data, monitor));
            OwnedFixture.check(thrown == original, "cleanup preserves first thrown identity");
            Throwable[] suppressed = thrown.getSuppressed();
            OwnedFixture.check(suppressed.length == 2 && suppressed[0] instanceof IllegalStateException &&
                suppressed[1] == later, "release then exact later monitor suppression order");
            receipt(f, original);
            OwnedFixture.check(f.manager.lock.getOwner() == null, "broken cleanup has no retained lock");
        }
        try (OwnedFixture f = new OwnedFixture()) {
            Data data = f.data(null); UnsupportedOperationException original = savedPolicy();
            TaskMonitor monitor = new TaskMonitorAdapter() {
                int visits;
                public void checkCancelled() { if (++visits == 2) { f.manager.lock.release(); throw original; } }
            };
            Throwable thrown = OwnedFixture.fails(UnsupportedOperationException.class,
                () -> f.manager.observePointerReference(data, monitor));
            OwnedFixture.check(thrown == original && thrown.getSuppressed().length == 1 &&
                thrown.getSuppressed()[0] instanceof IllegalStateException, "acquire cleanup preserves original");
            receipt(f, original);
            OwnedFixture.check(f.manager.lock.getOwner() == null, "acquire cleanup has no retained lock");
        }
    }
    static void architectureCleanup() throws Exception {
        try (OwnedFixture f = new OwnedFixture()) {
            f.data(null);
            UnsupportedOperationException original = savedPolicy();
            UnsupportedOperationException cleanup = new UnsupportedOperationException("architecture cleanup");
            OwnedPointerSettingsTest.Counted adapter = OwnedPointerSettingsTest.install(f, false);
            adapter.originFault = cleanup; adapter.fault = "invalidate";
            TaskMonitor monitor = new TaskMonitorAdapter() {
                public void checkCancelled() { throw original; }
                public void setMessage(String ignored) { throw original; }
                public void setProgress(long ignored) { throw original; }
            };
            Throwable thrown;
            try {
                thrown = OwnedFixture.fails(UnsupportedOperationException.class,
                    () -> ((DataTypeManagerDB)f.manager).setProgramArchitecture(null, null, true, monitor));
            }
            finally {
                adapter.fault = null;
                f.manager.setProgramArchitecture(f.program,
                    f.program.getSymbolTable().getVariableStorageManager(), false, TaskMonitor.DUMMY);
            }
            OwnedFixture.check(thrown == original && thrown.getSuppressed().length == 1 &&
                thrown.getSuppressed()[0] == cleanup, "architecture work then exact cleanup identity");
            receipt(f, original);
            OwnedFixture.check(f.manager.lock.getOwner() == null, "architecture cleanup releases lock");
        }
    }
    static void run() throws Exception {
        sweep("empty", 14); sweep("instance", 17); sweep("component", 37);
        reentryAndSavedPolicy(); cleanupIdentity(); architectureCleanup();
        System.out.println("PASS origin latching controls");
    }
}
