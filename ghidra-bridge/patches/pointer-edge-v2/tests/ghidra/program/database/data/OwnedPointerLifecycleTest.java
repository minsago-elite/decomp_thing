package ghidra.program.database.data;

import ghidra.program.model.listing.Data;
import ghidra.program.model.data.*;
import ghidra.framework.data.OwnedProgramIntegrityException;
import ghidra.util.task.*;
import ghidra.util.exception.CancelledException;
import java.io.IOException;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicReference;
import db.*;

public final class OwnedPointerLifecycleTest {
    static final class CancelAt extends TaskMonitorAdapter {
        int visits; final int at; final boolean thread;
        CancelAt(int at, boolean thread) {this.at=at;this.thread=thread;}
        @Override public void checkCancelled() throws CancelledException {
            if (++visits==at) {
                if(thread) Thread.currentThread().interrupt();
                else throw new CancelledException();
            }
        }
    }
    static Data deepComponent(OwnedFixture f) throws Exception {
        DataType type=new PointerDataType();
        for(int i=0;i<32;i++)type=new ArrayDataType(type,1,type.getLength());
        Data data=f.program.getListing().createData(f.address,type);
        for(int i=0;i<32;i++)data=data.getComponent(0);
        return data;
    }
    public static void main(String[] args) throws Exception {
        OwnedFixture.boot(args[0]);
        OwnedPointerOriginControls.run();
        OwnedFixture clean=new OwnedFixture(); Data stale=clean.data(null);clean.commit();clean.close();
        clean.program.checkOwnedIntegrity();
        OwnedFixture.fails(OwnedProgramIntegrityException.class,()->clean.observe(stale));
        try(OwnedFixture f=new OwnedFixture()) {
            f.data(null);IOException first=new IOException("first");
            OwnedProgramIntegrityException receipt=f.program.recordOwnedIntegrityFailure(first);
            OwnedFixture.check(f.program.recordOwnedIntegrityFailure(new IllegalStateException("second"))==receipt,"first cause stable");
            OwnedFixture.fails(ghidra.framework.model.DomainObjectException.class,()->f.program.dbError(new IOException("reported")));
            OwnedFixture.check(OwnedFixture.fails(OwnedProgramIntegrityException.class,f.program::checkOwnedIntegrity)==receipt,"dbError preserves first");
        }
        try(OwnedFixture f=new OwnedFixture()) {
            Data selected=f.data(null);f.commit();
            long before=f.observe(selected).generation();
            f.manager.invalidateCache();
            // Observation is never the refresh mechanism. Ordinary getters refresh unchanged rows.
            ((Pointer)selected.getDataType()).getDataType();
            selected=f.program.getListing().getDataAt(f.address);
            OwnedFixture.check(f.observe(selected).generation()>before,"generation revoked and unchanged ordinary refresh");
            before=f.manager.ownedGeneration();f.manager.invalidateCache(false);
            OwnedFixture.check(f.manager.ownedGeneration()==before+1,"boolean invalidation increments once");
        }
        try(OwnedFixture f=new OwnedFixture()) {
            Data selected=f.data(null);f.commit();
            f.transaction=f.program.startTransaction("unchanged rollback");
            f.program.endTransaction(f.transaction,false);f.transaction=-1;
            selected=f.program.getListing().getDataAt(f.address);
            OwnedFixture.check(f.observe(selected).childID()==-1,"unchanged rollback");
        }
        for(String mutation:new String[]{"child","category","length","missing"}) try(OwnedFixture f=new OwnedFixture()) {
            Data selected=f.data(null);PointerDB p=(PointerDB)selected.getDataType();
            Table table=f.program.getDBHandle().getTable("Pointers");DBRecord row=table.getRecord(p.getKey());
            if(mutation.equals("child")) row.setLongValue(PointerDBAdapter.PTR_DT_ID_COL,99);
            if(mutation.equals("category")) row.setLongValue(PointerDBAdapter.PTR_CATEGORY_COL,99);
            if(mutation.equals("length")) row.setByteValue(PointerDBAdapter.PTR_LENGTH_COL,(byte)4);
            if(mutation.equals("missing")) table.deleteRecord(row.getKey());else table.putRecord(row);
            f.manager.invalidateCache();
            OwnedFixture.fails(OwnedProgramIntegrityException.class,()->p.getName());
            OwnedFixture.fails(OwnedProgramIntegrityException.class,f.program::checkOwnedIntegrity);
        }
        int checkpoints;
        try(OwnedFixture f=new OwnedFixture()) {
            Data data=f.data(null);CancelAt monitor=new CancelAt(Integer.MAX_VALUE,false);
            f.manager.observePointerReference(data,monitor);checkpoints=monitor.visits;
        }
        OwnedFixture.check(checkpoints>10,"non-vacuous cancellation points");
        for(boolean thread:new boolean[]{false,true}) for(int at=1;at<=checkpoints;at++) {
            try(OwnedFixture f=new OwnedFixture()) {
                Data data=f.data(null);CancelAt monitor=new CancelAt(at,thread);
                try { OwnedFixture.fails(Exception.class,()->f.manager.observePointerReference(data,monitor)); }
                finally { Thread.interrupted(); }
                OwnedFixture.check(f.manager.lock.getOwner()==null,"lock released on cancellation "+at);
                OwnedFixture.fails(OwnedProgramIntegrityException.class,f.program::checkOwnedIntegrity);
            }
        }
        try(OwnedFixture f=new OwnedFixture()) {
            Data data=f.data(null);CountDownLatch held=new CountDownLatch(1),release=new CountDownLatch(1);
            Thread holder=new Thread(()->{f.manager.lock.acquire();try {held.countDown();release.await();}catch(InterruptedException e){throw new AssertionError(e);}finally{f.manager.lock.release();}});
            holder.start();held.await();
            try {OwnedFixture.fails(OwnedProgramIntegrityException.class,()->f.observe(data));}
            finally {release.countDown();holder.join(2000);}
            OwnedFixture.check(!holder.isAlive(),"contention cleanup bounded");
        }
        try(OwnedFixture f=new OwnedFixture()) {
            CountDownLatch go=new CountDownLatch(1);AtomicReference<OwnedProgramIntegrityException> a=new AtomicReference<>(),b=new AtomicReference<>();
            Thread x=new Thread(()->{try{go.await();a.set(f.program.recordOwnedIntegrityFailure(new IOException("a")));}catch(InterruptedException e){throw new AssertionError(e);}});
            Thread y=new Thread(()->{try{go.await();b.set(f.program.recordOwnedIntegrityFailure(new IOException("b")));}catch(InterruptedException e){throw new AssertionError(e);}});
            x.start();y.start();go.countDown();x.join(2000);y.join(2000);
            OwnedFixture.check(a.get()!=null && a.get()==b.get(),"atomic first publication");
        }
        try(OwnedFixture f=new OwnedFixture()) {
            Data data=f.data(null);f.manager.dispose();
            f.program.checkOwnedIntegrity();
            OwnedFixture.fails(OwnedProgramIntegrityException.class,()->f.observe(data));
        }
        try(OwnedFixture f=new OwnedFixture()) {
            Data data=f.data(null);long before=f.manager.ownedGeneration();
            f.manager.setProgramArchitecture(f.program,f.program.getSymbolTable().getVariableStorageManager(),false,TaskMonitor.DUMMY);
            OwnedFixture.check(f.manager.ownedGeneration()==before+1,"store=false architecture revokes");
            OwnedFixture.check(f.observe(data).generation()==before+1,"fresh target after architecture");
        }
        try(OwnedFixture f=new OwnedFixture()) {
            f.data(null);f.commit();OwnedPointerSettingsTest.field(f.manager,DataTypeManagerDB.class,"ownedGeneration",Long.MAX_VALUE-1);
            f.manager.invalidateCache();OwnedFixture.check(f.manager.ownedGeneration()==Long.MAX_VALUE,"last generation");
            OwnedFixture.fails(OwnedProgramIntegrityException.class,()->f.manager.invalidateCache());
            OwnedFixture.check(f.manager.ownedGeneration()==Long.MAX_VALUE,"never wraps");
        }
        try(OwnedFixture f=new OwnedFixture()) {
            StructureDataType structure=new StructureDataType("renamed_child",0);structure.add(IntegerDataType.dataType);
            Data data=f.data(structure);PointerDB pointer=(PointerDB)data.getDataType();DataType child=pointer.getDataType();
            child.setName("renamed_again");child.setCategoryPath(new CategoryPath("/moved"));
            OwnedFixture.check(f.program.getListing().getDataAt(f.address)==data,"ordinary cache refresh retains selected identity");
            OwnedFixture.check(f.observe(data).childID()==f.manager.getID(child),"rename/category move current edge");
        }
        try(OwnedFixture f=new OwnedFixture()) {
            Data data=f.data(IntegerDataType.dataType);PointerDB pointer=(PointerDB)data.getDataType();
            int[] writes={0};
            PointerDBAdapterV2 fault=new PointerDBAdapterV2(f.program.getDBHandle(),"",false) {
                @Override void updateRecord(DBRecord row) throws IOException {writes[0]++;throw new IOException("injected pointer write");}
            };
            OwnedPointerSettingsTest.field(pointer,PointerDB.class,"adapter",fault);
            OwnedFixture.fails(OwnedProgramIntegrityException.class,()->pointer.dataTypeReplaced(pointer.getDataType(),LongDataType.dataType));
            OwnedFixture.check(writes[0]==1,"actual failing write executed");
            OwnedFixture.fails(OwnedProgramIntegrityException.class,()->f.observe(data));
        }
        try(OwnedFixture f=new OwnedFixture()) {
            Data data=f.data(IntegerDataType.dataType);PointerDB pointer=(PointerDB)data.getDataType();f.commit();
            f.transaction=f.program.startTransaction("changed pointer rollback");
            pointer.dataTypeReplaced(pointer.getDataType(),LongDataType.dataType);
            f.program.endTransaction(f.transaction,false);f.transaction=-1;
            OwnedFixture.fails(OwnedProgramIntegrityException.class,()->pointer.getDataType());
        }
        try(OwnedFixture f=new OwnedFixture()) {
            Data data=f.data(null);f.commit();
            f.transaction=f.program.startTransaction("unrelated change");f.program.setName("undo-redo");f.commit();
            f.program.undo();data=f.program.getListing().getDataAt(f.address);f.observe(data);
            f.program.redo();data=f.program.getListing().getDataAt(f.address);f.observe(data);
            f.program.checkOwnedIntegrity();
        }
        try(OwnedFixture f=new OwnedFixture()) {
            Data data=f.data(null);PointerDB pointer=(PointerDB)data.getDataType();DBRecord old=pointer.record.copy();
            f.manager.remove(pointer,TaskMonitor.DUMMY);OwnedFixture.check(pointer.isDeleted(),"deleted pointer");
            f.program.getDBHandle().getTable("Pointers").putRecord(old);
            DataType resurrected=f.manager.getDataType(old.getKey());
            OwnedFixture.check(resurrected!=pointer,"key resurrection creates new instance");
            OwnedFixture.fails(OwnedProgramIntegrityException.class,()->pointer.getDataType());
        }
        int settingCheckpoints;
        try(OwnedFixture f=new OwnedFixture()) {
            Data data=f.data(null);data.setLong("mutability",2);
            CancelAt monitor=new CancelAt(Integer.MAX_VALUE,false);
            f.manager.observePointerReference(data,monitor);settingCheckpoints=monitor.visits;
        }
        for(boolean thread:new boolean[]{false,true}) for(int at=1;at<=settingCheckpoints;at++) try(OwnedFixture f=new OwnedFixture()) {
            Data data=f.data(null);data.setLong("mutability",2);CancelAt monitor=new CancelAt(at,thread);
            try{OwnedFixture.fails(Exception.class,()->f.manager.observePointerReference(data,monitor));}
            finally{Thread.interrupted();}
            OwnedFixture.check(f.manager.lock.getOwner()==null,"setting cancellation releases lock");
            OwnedFixture.fails(OwnedProgramIntegrityException.class,f.program::checkOwnedIntegrity);
        }
        for(int at:new int[]{1,2,3,checkpoints}) try(OwnedFixture f=new OwnedFixture()) {
            Data data=f.data(null);TaskMonitor monitor=new TaskMonitorAdapter(){int calls;
                @Override public void checkCancelled(){if(++calls==at)throw new AssertionError("injected monitor Error");}};
            OwnedFixture.fails(AssertionError.class,()->f.manager.observePointerReference(data,monitor));
            OwnedFixture.check(f.manager.lock.getOwner()==null,"monitor Error releases lock");
            OwnedFixture.fails(OwnedProgramIntegrityException.class,f.program::checkOwnedIntegrity);
        }
        try(OwnedFixture f=new OwnedFixture()) {
            Data data=f.data(null);TaskMonitor monitor=new TaskMonitorAdapter(){int calls;
                @Override public void checkCancelled() throws CancelledException {
                    ++calls;
                    if(calls==checkpoints-1) f.manager.lock.release(); // inject broken lock cleanup
                    if(calls==checkpoints) throw new CancelledException();
                }};
            Throwable first=OwnedFixture.fails(IllegalStateException.class,()->f.manager.observePointerReference(data,monitor));
            OwnedFixture.check(first.getSuppressed().length==1 && first.getSuppressed()[0] instanceof CancelledException,
                "release failure retained; later cancellation suppressed");
            OwnedFixture.fails(OwnedProgramIntegrityException.class,f.program::checkOwnedIntegrity);
        }
        OwnedFixture errorClosed=new OwnedFixture();errorClosed.data(null);errorClosed.commit();
        OwnedProgramIntegrityException errorReceipt=errorClosed.program.recordOwnedIntegrityFailure(new IOException("before close"));
        errorClosed.close();
        OwnedFixture.check(OwnedFixture.fails(OwnedProgramIntegrityException.class,errorClosed.program::checkOwnedIntegrity)==errorReceipt,
            "same error-only receipt after real Program close");
        int componentCheckpoints;
        try(OwnedFixture f=new OwnedFixture()) {
            Data component=deepComponent(f);CancelAt monitor=new CancelAt(Integer.MAX_VALUE,false);
            OwnedFixture.fails(UnsupportedOperationException.class,()->f.manager.observePointerReference(component,monitor));
            componentCheckpoints=monitor.visits;f.program.checkOwnedIntegrity();
        }
        for(boolean thread:new boolean[]{false,true}) for(int at=1;at<=componentCheckpoints;at++) try(OwnedFixture f=new OwnedFixture()) {
            Data data=deepComponent(f);CancelAt monitor=new CancelAt(at,thread);
            try{OwnedFixture.fails(Exception.class,()->f.manager.observePointerReference(data,monitor));}
            finally{Thread.interrupted();}
            OwnedFixture.check(f.manager.lock.getOwner()==null,"component cancellation releases lock");
            OwnedFixture.fails(OwnedProgramIntegrityException.class,f.program::checkOwnedIntegrity);
        }
        System.out.println("PASS OwnedPointerLifecycleTest cancellation points="+checkpoints+"/"+settingCheckpoints+"/"+componentCheckpoints);
    }
}
