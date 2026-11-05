package ghidra.program.database.data;

import ghidra.program.model.data.*;
import ghidra.framework.data.OwnedProgramIntegrityException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.classfinder.ClassSearcher;
import java.util.*;

public final class OwnedPointerIngressTest {
    static final class Forged extends PointerDataType {
        @Override public DataType getDataType() { throw new AssertionError("forged getter invoked"); }
    }
    static final class LostBuiltin extends IntegerDataType {
        @Override public IntegerDataType clone(DataTypeManager destination) {return null;}
    }
    static final class ThrowingBuiltin extends IntegerDataType {
        @Override public IntegerDataType clone(DataTypeManager destination) {throw new IllegalArgumentException("injected clone failure");}
    }
    public static void main(String[] args) throws Exception {
        OwnedFixture.boot(args[0]);
        Class<?>[] factories = {PointerDataType.class,Pointer8DataType.class,Pointer16DataType.class,
            Pointer24DataType.class,Pointer32DataType.class,Pointer40DataType.class,Pointer48DataType.class,
            Pointer56DataType.class,Pointer64DataType.class};
        try (OwnedFixture f = new OwnedFixture()) {
            for (Class<?> factory : factories) {
                DataType input = (DataType) factory.getConstructor().newInstance();
                DataType first = f.manager.resolve(input, null);
                OwnedFixture.check(first instanceof PointerDB, "factory resolves to exact PointerDB");
                DataType same = f.manager.resolve(first, DataTypeConflictHandler.REPLACE_HANDLER);
                OwnedFixture.check(first == same, "contains exit retains exact identity");
                DataType repeat = f.manager.resolve(input, DataTypeConflictHandler.DEFAULT_HANDLER);
                OwnedFixture.check(first == repeat, "equivalent factory reuse");
            }
            f.program.checkOwnedIntegrity();
        }
        BuiltInDataTypeManager builtin = BuiltInDataTypeManager.getDataTypeManager();
        int expected = 0;
        for (BuiltInDataType type : ClassSearcher.getInstances(BuiltInDataType.class, new BuiltInDataTypeClassExclusionFilter())) {
            DataType present = builtin.getDataType(type.getCategoryPath(), type.getName());
            OwnedFixture.check(present != null, "complete discovered builtin population: " + type.getClass());
            expected++;
        }
        OwnedFixture.check(expected > 50, "non-vacuous builtin population");
        System.out.println("PASS builtin population " + expected);
        for (int copy = 0; copy < 4; copy++) try (OwnedFixture f = new OwnedFixture()) {
            Pointer forged = new Forged();
            if (copy == 1) try (StandAloneDataTypeManager intermediate = new StandAloneDataTypeManager("intermediate")) { forged = (Pointer) forged.clone(intermediate).clone(null); }
            if (copy == 2) forged = forged.newPointer(null);
            if (copy == 3) forged = PointerDataType.copyForManager(forged, null);
            Pointer input = forged;
            OwnedFixture.fails(OwnedProgramIntegrityException.class, () -> f.manager.resolve(input, null));
            OwnedFixture.fails(OwnedProgramIntegrityException.class, f.program::checkOwnedIntegrity);
        }
        try (OwnedFixture source = new OwnedFixture(); OwnedFixture destination = new OwnedFixture()) {
            Pointer pointer = (Pointer) source.data(null).getDataType();
            OwnedFixture.fails(OwnedProgramIntegrityException.class, () -> pointer.clone(destination.manager));
            source.program.checkOwnedIntegrity();
        }
        try (OwnedFixture source = new OwnedFixture(); OwnedFixture destination = new OwnedFixture()) {
            DataType pointer = source.data(IntegerDataType.dataType).getDataType();
            OwnedFixture.fails(OwnedProgramIntegrityException.class, () -> destination.manager.resolve(pointer,null));
            source.program.checkOwnedIntegrity();
        }
        try (OwnedFixture destination = new OwnedFixture()) {
            DataType pointer = builtin.getDataType(PointerDataType.dataType.getCategoryPath(), "pointer");
            OwnedFixture.fails(OwnedProgramIntegrityException.class, () -> destination.manager.resolve(pointer,null));
        }
        try (StandAloneDataTypeManager source = new StandAloneDataTypeManager("foreign" ); OwnedFixture destination = new OwnedFixture()) {
            int tx=source.startTransaction("pointer");
            DataType pointer;
            try { pointer=source.resolve(new PointerDataType(),null); } finally { source.endTransaction(tx,true); }
            OwnedFixture.fails(OwnedProgramIntegrityException.class, () -> destination.manager.resolve(pointer,null));
        }
        try (OwnedFixture f = new OwnedFixture()) {
            PointerDB pointer = (PointerDB) f.manager.resolve(new PointerDataType(IntegerDataType.dataType),null);
            DataType child = pointer.getDataType();
            pointer.dataTypeReplaced(child,pointer);
            OwnedFixture.check(pointer.getDataType()==DataType.DEFAULT, "self replacement preserves DEFAULT");
        }
        // Both child resolution calls execute under one existing outer owner without draining it.
        try (OwnedFixture f = new OwnedFixture()) {
            f.manager.addDataTypes(List.of(new PointerDataType(),new PointerDataType(IntegerDataType.dataType)),
                DataTypeConflictHandler.DEFAULT_HANDLER,TaskMonitor.DUMMY);
            f.program.checkOwnedIntegrity();
        }
        try(OwnedFixture f=new OwnedFixture()) {
            Pointer forged=(Pointer)java.lang.reflect.Proxy.newProxyInstance(Pointer.class.getClassLoader(),
                new Class<?>[]{Pointer.class},(o,m,a)->{throw new AssertionError("foreign getter");});
            OwnedFixture.fails(OwnedProgramIntegrityException.class,()->f.manager.resolve(forged,null));
        }
        try(OwnedFixture source=new OwnedFixture();OwnedFixture destination=new OwnedFixture()) {
            DataType pointer=source.data(null).getDataType();
            source.program.recordOwnedIntegrityFailure(new java.io.IOException("source poisoned"));
            OwnedFixture.fails(OwnedProgramIntegrityException.class,()->destination.manager.resolve(pointer,null));
        }
        java.io.File archive=new java.io.File(System.getProperty("java.io.tmpdir"),"foreign.gdt");
        java.nio.file.Files.deleteIfExists(archive.toPath());
        try(FileDataTypeManager source=FileDataTypeManager.createFileArchive(archive);OwnedFixture destination=new OwnedFixture()) {
            int tx=source.startTransaction("factory");DataType pointer;
            try{pointer=source.resolve(new PointerDataType(),null);}finally{source.endTransaction(tx,true);}
            OwnedFixture.fails(OwnedProgramIntegrityException.class,()->destination.manager.resolve(pointer,null));
            source.save();
        }
        for(boolean update:new boolean[]{false,true})
        try(FileDataTypeManager source=FileDataTypeManager.openFileArchive(archive,update);OwnedFixture destination=new OwnedFixture()) {
            DataType pointer=source.getDataType(CategoryPath.ROOT,"pointer");
            OwnedFixture.check(pointer!=null,"real reopened archive pointer");
            OwnedFixture.fails(OwnedProgramIntegrityException.class,()->destination.manager.resolve(pointer,null));
        }
        java.nio.file.Files.delete(archive.toPath());
        try(OwnedFixture f=new OwnedFixture()) {
            PointerDataType deleted=new PointerDataType(IntegerDataType.dataType);
            deleted.dataTypeDeleted(IntegerDataType.dataType);
            OwnedFixture.fails(OwnedProgramIntegrityException.class,()->f.manager.resolve(deleted,null));
        }
        try(OwnedFixture f=new OwnedFixture()) {
            StructureDataType input=new StructureDataType("conflicted",0);input.add(IntegerDataType.dataType);
            DataType first=f.manager.resolve(input,null);
            StructureDataType changed=new StructureDataType("conflicted",0);changed.add(LongDataType.dataType);
            DataType p1=f.manager.resolve(new PointerDataType(first),null);
            DataType p2=f.manager.resolve(new PointerDataType(changed),DataTypeConflictHandler.REPLACE_HANDLER);
            OwnedFixture.check(p2 instanceof PointerDB,"conflict final canonical pointer");
            f.program.checkOwnedIntegrity();
        }
        for(DataType child:new DataType[]{new LostBuiltin(),new ThrowingBuiltin()}) try(OwnedFixture f=new OwnedFixture()) {
            PointerDataType receiver=new PointerDataType(null,-1,f.manager);
            OwnedFixture.fails(RuntimeException.class,()->receiver.newPointer(child));
            OwnedFixture.fails(OwnedProgramIntegrityException.class,f.program::checkOwnedIntegrity);
        }
        try(OwnedFixture f=new OwnedFixture()) {
            OwnedFixture.fails(RuntimeException.class,()->f.manager.resolve(new PointerDataType(new LostBuiltin()),null));
            OwnedFixture.fails(OwnedProgramIntegrityException.class,f.program::checkOwnedIntegrity);
            OwnedFixture.check(f.program.getDBHandle().getTable("Pointers").getRecordCount()==0,"lost child never becomes -1 row");
        }
        try(OwnedFixture f=new OwnedFixture()) {
            f.manager.lock.acquire();
            try {
                OwnedFixture.check(f.manager.activateResolveCache(),"outer owns resolve queue");
                Object queue=OwnedPointerSettingsTest.field(f.manager,DataTypeManagerDB.class,"resolveQueue");
                f.manager.resolve(new PointerDataType(IntegerDataType.dataType),null);
                OwnedFixture.check(OwnedPointerSettingsTest.field(f.manager,DataTypeManagerDB.class,"resolveQueue")==queue,
                    "nested calls never drain foreign queue");
                f.manager.processResolveQueue(true);
                f.program.checkOwnedIntegrity();
            }
            finally {f.manager.lock.release();}
        }
        try(OwnedFixture f=new OwnedFixture()) {
            StructureDataType a=new StructureDataType("old_child",0);a.add(IntegerDataType.dataType);
            StructureDataType b=new StructureDataType("new_child",0);b.add(ShortDataType.dataType);
            DataType old=f.manager.resolve(a,null),replacement=f.manager.resolve(b,null);
            PointerDB pa=(PointerDB)f.manager.resolve(new PointerDataType(old),null);
            PointerDB pb=(PointerDB)f.manager.resolve(new PointerDataType(replacement),null);
            f.manager.replaceDataType(old,replacement,false);
            OwnedFixture.check(pa.isDeleted() && pb.getDataType()==replacement,"duplicate replacement survivor");
            f.program.checkOwnedIntegrity();
        }
        // Exercise the actual V1->V2 pointer adapter upgrade in a repository-local archive.
        java.io.File legacy=new java.io.File(System.getProperty("java.io.tmpdir"),"legacy.gdt");
        java.nio.file.Files.deleteIfExists(legacy.toPath());
        long legacyID;
        try(FileDataTypeManager source=FileDataTypeManager.createFileArchive(legacy)) {
            int tx=source.startTransaction("legacy fixture");
            try {
                DataType ptr=source.resolve(new PointerDataType(),null);legacyID=source.getID(ptr);
                db.DBHandle handle=((DataTypeManagerDB)source).dbHandle;
                handle.deleteTable("Pointers");
                db.Schema schema=new db.Schema(1,"Pointer ID",new db.Field[]{db.LongField.INSTANCE,db.LongField.INSTANCE},new String[]{"Data Type ID","Category ID"});
                db.Table table=handle.createTable("Pointers",schema,new int[]{1});db.DBRecord row=schema.createRecord(legacyID);
                row.setLongValue(0,-1);row.setLongValue(1,0);table.putRecord(row);
            }
            finally {source.endTransaction(tx,true);}
            source.save();
        }
        try(FileDataTypeManager source=FileDataTypeManager.openFileArchive(legacy,true);OwnedFixture destination=new OwnedFixture()) {
            OwnedFixture.check(((DataTypeManagerDB)source).dbHandle.getTable("Pointers").getSchema().getVersion()==2,"real archive upgraded");
            DataType ptr=source.getDataType(legacyID);
            OwnedFixture.fails(OwnedProgramIntegrityException.class,()->destination.manager.resolve(ptr,null));
        }
        java.nio.file.Files.delete(legacy.toPath());
        System.out.println("PASS OwnedPointerIngressTest");
    }
}
