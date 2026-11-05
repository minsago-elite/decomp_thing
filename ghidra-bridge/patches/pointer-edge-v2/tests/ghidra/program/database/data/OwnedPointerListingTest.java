package ghidra.program.database.data;

import ghidra.program.model.data.*;
import ghidra.program.model.listing.Data;
import ghidra.framework.data.OwnedProgramIntegrityException;
import ghidra.util.task.TaskMonitor;
import java.lang.reflect.Proxy;

public final class OwnedPointerListingTest {
    public static void main(String[] args) throws Exception {
        OwnedFixture.boot(args[0]);
        try (OwnedFixture f = new OwnedFixture()) {
            Data root = f.data(null);
            OwnedFixture.check(f.observe(root).selected()==root,"top-level exact identity");
            OwnedFixture.check(f.program.getListing().getDataAt(f.address.add(1))==null,"interior has no primitive start");
        }
        try (OwnedFixture f = new OwnedFixture()) {
            Data root=f.program.getListing().createData(f.address,new ArrayDataType(new PointerDataType(),2,8));
            Data component=root.getComponent(1);
            OwnedFixture.check(component.getAddress().equals(f.address.add(8)),"actual addressed component");
            OwnedFixture.fails(UnsupportedOperationException.class,()->f.observe(component));
            f.program.checkOwnedIntegrity();
        }
        try (OwnedFixture f = new OwnedFixture()) {
            StructureDataType structure=new StructureDataType("root",0);
            structure.add(new PointerDataType());
            Data component=f.program.getListing().createData(f.address,structure).getComponent(0);
            OwnedFixture.fails(UnsupportedOperationException.class,()->f.observe(component));
        }
        try (OwnedFixture a=new OwnedFixture(); OwnedFixture b=new OwnedFixture()) {
            Data foreign=a.data(null);
            OwnedFixture.fails(java.io.IOException.class,()->b.observe(foreign));
            a.program.checkOwnedIntegrity();
        }
        try (OwnedFixture f=new OwnedFixture()) {
            Data forged=(Data)Proxy.newProxyInstance(Data.class.getClassLoader(),new Class<?>[]{Data.class},
                (o,m,a)->{throw new AssertionError("Unknown Data getter invoked: "+m);});
            OwnedFixture.fails(OwnedProgramIntegrityException.class,()->f.observe(forged));
        }
        for (boolean replace : new boolean[]{false,true}) try (OwnedFixture f=new OwnedFixture()) {
            Data stale=f.data(null);
            f.program.getListing().clearCodeUnits(f.address,f.address.add(7),false);
            if(replace) f.data(null);
            OwnedFixture.fails(Exception.class,()->f.observe(stale));
            OwnedFixture.fails(OwnedProgramIntegrityException.class,f.program::checkOwnedIntegrity);
        }
        for (int depth : new int[]{32,33}) try (OwnedFixture f=new OwnedFixture()) {
            DataType type=new PointerDataType();
            for (int i=0;i<depth;i++) type=new ArrayDataType(type,1,type.getLength());
            Data data=f.program.getListing().createData(f.address,type);
            for(int i=0;i<depth;i++) data=data.getComponent(0);
            Data selected=data;
            OwnedFixture.fails(UnsupportedOperationException.class,()->f.observe(selected));
        }
        for(String fault:new String[]{"cycle","ordinal","offset","reused-parent"}) try(OwnedFixture f=new OwnedFixture()) {
            Data root=f.program.getListing().createData(f.address,new ArrayDataType(new PointerDataType(),2,8));
            Data component=root.getComponent(0);
            if(fault.equals("cycle")) {
                OwnedPointerSettingsTest.field(component,component.getClass(),"parent",component);
                OwnedPointerSettingsTest.field(component,component.getClass().getSuperclass(),"componentCache",
                    OwnedPointerSettingsTest.field(root,root.getClass(),"componentCache"));
            }
            if(fault.equals("ordinal")) OwnedPointerSettingsTest.field(component,component.getClass(),"indexInParent",1);
            if(fault.equals("offset")) {
                OwnedPointerSettingsTest.field(component,component.getClass(),"offset",Integer.MAX_VALUE);
                OwnedPointerSettingsTest.field(component,component.getClass().getSuperclass().getSuperclass(),"address",f.address.add(Integer.MAX_VALUE));
            }
            if(fault.equals("reused-parent")) OwnedPointerSettingsTest.field(component,component.getClass(),"parent",root.getComponent(1));
            OwnedFixture.fails(java.io.IOException.class,()->f.observe(component));
            OwnedFixture.fails(OwnedProgramIntegrityException.class,f.program::checkOwnedIntegrity);
        }
        for(String fault:new String[]{"missing-row","changed-type","interior"}) try(OwnedFixture f=new OwnedFixture()) {
            Data data=f.data(null);long key=f.program.getAddressMap().getKey(f.address,false);
            db.Table table=f.program.getDBHandle().getTable("Data");
            if(fault.equals("missing-row")) table.deleteRecord(key);
            if(fault.equals("changed-type")) {db.DBRecord row=table.getRecord(key);row.setLongValue(0,0);table.putRecord(row);}
            if(fault.equals("interior")) OwnedPointerSettingsTest.field(data,data.getClass().getSuperclass(),"address",f.address.add(1));
            OwnedFixture.fails(Exception.class,()->f.observe(data));
            OwnedFixture.fails(OwnedProgramIntegrityException.class,f.program::checkOwnedIntegrity);
        }
        System.out.println("PASS OwnedPointerListingTest");
    }
}
