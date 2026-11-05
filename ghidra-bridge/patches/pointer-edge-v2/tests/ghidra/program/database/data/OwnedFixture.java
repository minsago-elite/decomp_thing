package ghidra.program.database.data;

import ghidra.GhidraApplicationLayout;
import ghidra.framework.*;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.lang.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Data;
import ghidra.program.model.address.Address;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;
import ghidra.util.classfinder.ClassSearcher;

/** Actual CREATE ProgramDB fixture. No analyzer, worker, decompiler, importer or proxy. */
final class OwnedFixture implements AutoCloseable {
    static Language language;
    final Object consumer = new Object();
    final ProgramDB program;
    final ProgramDataTypeManager manager;
    final Address address;
    int transaction;
    OwnedFixture() throws Exception { this(language, "gcc"); }
    OwnedFixture(Language fixtureLanguage, String compiler) throws Exception {
        program = new ProgramDB("owned-dependency-fixture", fixtureLanguage,
            fixtureLanguage.getCompilerSpecByID(new CompilerSpecID(compiler)), consumer);
        manager = program.getDataTypeManager();
        transaction = program.startTransaction("dependency control");
        address = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x403008);
        program.getMemory().createInitializedBlock("fixture", address, 4096, (byte)0, TaskMonitor.DUMMY, false);
        check(manager.isOwnedStrict(), "actual CREATE authority");
        check(program.getConsumerList().size()==1 && program.getConsumerList().get(0)==consumer,"exactly original consumer");
    }
    Data data(DataType child) throws Exception {
        return program.getListing().createData(address, new PointerDataType(child));
    }
    PointerReferenceObservation observe(Data data) throws Exception {
        return manager.observePointerReference(data, TaskMonitor.DUMMY);
    }
    void commit() { program.endTransaction(transaction, true); transaction = -1; }
    static void check(boolean b, String text) { if (!b) throw new AssertionError(text); }
    static void boot(String bundle) throws Exception {
        ApplicationConfiguration configuration = new ApplicationConfiguration();
        configuration.setInitializeLogging(false);
        Application.initializeApplication(new GhidraApplicationLayout(new java.io.File(bundle)), configuration);
        java.nio.file.Path modules=java.nio.file.Path.of(System.getProperty("owned.test.modules"));
        for(Class<?> type:new Class<?>[]{PointerDB.class,ProgramDataTypeManager.class,PointerReferenceObservation.class,ProgramDB.class})
            check(java.nio.file.Path.of(type.getProtectionDomain().getCodeSource().getLocation().toURI()).equals(modules.resolve("SoftwareModeling/lib/SoftwareModeling.jar")),"executing derived SoftwareModeling: "+type);
        check(java.nio.file.Path.of(ghidra.framework.data.DomainObjectAdapterDB.class.getProtectionDomain().getCodeSource().getLocation().toURI()).equals(modules.resolve("Project/lib/Project.jar")),"executing derived Project");
        check(PointerDB.class.getClassLoader()==ProgramDB.class.getClassLoader() &&
            ProgramDB.class.getClassLoader()==ghidra.framework.data.DomainObjectAdapterDB.class.getClassLoader(),"fixture defining loader relationship");
        ClassSearcher.search(TaskMonitor.DUMMY);
        language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("x86:LE:64:default"));
    }
    @Override public void close() {
        try { if (transaction != -1) program.endTransaction(transaction, false); }
        finally { program.release(consumer); }
        check(program.isClosed(), "consumer released and Program closed");
        check(program.getConsumerList().isEmpty(),"no receipt consumer retained");
        check(ProcessHandle.current().children().count()==0,"no worker/native child processes");
    }
    interface Checked { void run() throws Exception; }
    static Throwable fails(Class<? extends Throwable> type, Checked body) throws Exception {
        try { body.run(); }
        catch (Throwable failure) {
            if (!type.isInstance(failure)) throw new AssertionError("Expected " + type + ", got " + failure, failure);
            return failure;
        }
        throw new AssertionError("Expected failure " + type);
    }
}
