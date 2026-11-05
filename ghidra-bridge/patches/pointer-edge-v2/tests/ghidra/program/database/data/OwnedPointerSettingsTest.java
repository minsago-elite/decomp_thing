package ghidra.program.database.data;

import db.*;
import java.io.IOException;
import java.lang.reflect.Field;
import ghidra.program.model.listing.Data;
import ghidra.program.model.data.*;
import ghidra.framework.data.OwnedProgramIntegrityException;

public final class OwnedPointerSettingsTest {
    // Reflection is confined to fault installation/counter inspection in tests, never an observation.
    static Object field(Object target, Class<?> owner, String name) throws Exception {
        Field field=owner.getDeclaredField(name);field.setAccessible(true);return field.get(target);
    }
    static void field(Object target, Class<?> owner, String name, Object value) throws Exception {
        Field field=owner.getDeclaredField(name);field.setAccessible(true);field.set(target,value);
    }
    static final class Counted extends SettingsDBAdapterV1 {
        int next, direct, ranges;
        String fault;
        RuntimeException originFault;
        void failOrigin(String site) { if (site.equals(fault) && originFault != null) throw originFault; }
        Counted(String name, DBHandle db) throws Exception { super(name,db,false); }
        @Override RecordIterator getRecords(long min,long max) throws IOException {
            ranges++;
            failOrigin("range");
            if ("range".equals(fault)) throw new IOException("injected range failure");
            RecordIterator actual=super.getRecords(min,max);
            return new RecordIterator() {
                public boolean hasNext() throws IOException { failOrigin("hasNext"); return actual.hasNext(); }
                public DBRecord next() throws IOException {
                    next++;
                    failOrigin("next");
                    if ("next".equals(fault)) throw new IOException("injected next failure");
                    DBRecord row=actual.next();
                    if("association".equals(fault)) row.setLongValue(0,min+1);
                    if("schema".equals(fault)) return new Schema(0,"key",new db.Field[0],new String[0]).createRecord(row.getKey());
                    return row;
                }
                public boolean hasPrevious(){throw new AssertionError("reverse scan");}
                public DBRecord previous(){throw new AssertionError("reverse scan");}
                public boolean delete(){throw new AssertionError("mutation during observation");}
            };
        }
        @Override String readSettingNameDirect(short index) throws IOException {
            direct++;
            failOrigin("name");
            if("name".equals(fault)) throw new IOException("injected direct name failure");
            return super.readSettingNameDirect(index);
        }
        @Override void invalidateNameCache() { failOrigin("invalidate"); super.invalidateNameCache(); }
        @Override RecordIterator getRecords() {throw new AssertionError("whole table scan");}
        @Override String getSettingName(DBRecord r) {throw new AssertionError("global name map");}
    }
    static Counted install(OwnedFixture f, boolean defaults) throws Exception {
        Class<?> owner=defaults?DataTypeManagerDB.class:ProgramBasedDataTypeManagerDB.class;
        String field=defaults?"settingsAdapter":"instanceSettingsAdapter";
        SettingsDBAdapter old=(SettingsDBAdapter)field(f.manager,owner,field);
        Counted counted=new Counted(old.getTableName(),f.program.getDBHandle());
        field(f.manager,owner,field,counted);return counted;
    }
    static long addressKey(OwnedFixture f) {return f.program.getAddressMap().getKey(f.address,false);}
    static void assertCold(Counted c) throws Exception {
        OwnedFixture.check(field(c,SettingsDBAdapterV1.class,"nameIndexMap")==null &&
            field(c,SettingsDBAdapterV1.class,"nameStringMap")==null,"observation never initializes name maps");
    }
    public static void main(String[] args) throws Exception {
        OwnedFixture.boot(args[0]);
        for (boolean defaults : new boolean[]{false, true})
        for (String site : new String[]{"range", "hasNext", "next", "name", "invalidate"}) {
            if (defaults && site.equals("name")) continue; // defaults never read names
            for (boolean savedPolicy : new boolean[]{false, true}) try (OwnedFixture f = new OwnedFixture()) {
                Data data = f.data(null); Counted c = install(f, defaults);
                c.createSettingsRecord(defaults ? f.manager.getID(data.getDataType()) : addressKey(f), "mutability", null, 2);
                c.invalidateNameCache();
                UnsupportedOperationException original = savedPolicy ? OwnedPointerOriginControls.savedPolicy() :
                    new UnsupportedOperationException("adapter origin");
                c.originFault = original; c.fault = site;
                Throwable thrown;
                try {
                    thrown = OwnedFixture.fails(UnsupportedOperationException.class, () -> {
                        if (site.equals("invalidate")) f.manager.invalidateCache();
                        else f.observe(data);
                    });
                }
                finally { c.fault = null; }
                OwnedFixture.check(thrown == original, "adapter throws exact original");
                OwnedProgramIntegrityException receipt = OwnedPointerOriginControls.receipt(f, original);
                OwnedFixture.check(f.manager.lock.getOwner() == null, "adapter origin releases lock");
                OwnedFixture.check(OwnedFixture.fails(OwnedProgramIntegrityException.class, () -> f.observe(data)) == receipt,
                    "adapter retry returns same receipt");
            }
        }
        for(int count:new int[]{0,1,2,3}) try(OwnedFixture f=new OwnedFixture()) {
            Data data=f.data(null);
            Counted defaults=install(f,true), instances=install(f,false);
            for(int i=0;i<10000;i++) instances.createSettingsRecord(addressKey(f)+100+i,"unrelated"+i,null,9);
            for(int i=0;i<count;i++) instances.createSettingsRecord(addressKey(f),"mutability",null,2);
            instances.invalidateNameCache();
            if(count<2) OwnedFixture.check(f.observe(data).constantInstance()==(count==1),"zero/one setting");
            else OwnedFixture.fails(UnsupportedOperationException.class,()->f.observe(data));
            OwnedFixture.check(defaults.next==0 && instances.next==Math.min(count,2) &&
                instances.direct==(count==1?1:0),"honest bounded visits");
            assertCold(instances);assertCold(defaults);
            OwnedPointerOriginControls.cleanReceipt(f);
        }
        try(OwnedFixture f=new OwnedFixture()) {
            Data data=f.data(null);Counted defaults=install(f,true),instances=install(f,false);
            defaults.createSettingsRecord(f.manager.getID(data.getDataType()),"mutability",null,2);
            defaults.invalidateNameCache();
            OwnedFixture.fails(UnsupportedOperationException.class,()->f.observe(data));
            OwnedFixture.check(defaults.next==1 && defaults.direct==0 && instances.ranges==0,"first default refuses");
        }
        for(String name:new String[]{"other","a".repeat(64),"a".repeat(65),"é".repeat(32),"é".repeat(33)})
        try(OwnedFixture f=new OwnedFixture()) {
            Data data=f.data(null);Counted c=install(f,false);
            c.createSettingsRecord(addressKey(f),name,null,2);c.invalidateNameCache();
            OwnedFixture.fails(UnsupportedOperationException.class,()->f.observe(data));
            OwnedFixture.check(c.next==1 && c.direct==1,"name limits one direct visit");assertCold(c);
            OwnedPointerOriginControls.cleanReceipt(f);
        }
        for(String value:new String[]{"", "a".repeat(100000)}) try(OwnedFixture f=new OwnedFixture()) {
            Data data=f.data(null);Counted c=install(f,false);
            c.createSettingsRecord(addressKey(f),"mutability",value,2);c.invalidateNameCache();
            OwnedFixture.fails(UnsupportedOperationException.class,()->f.observe(data));
            OwnedPointerOriginControls.cleanReceipt(f);
        }
        for(String fault:new String[]{"range","next","name","association","schema"})
        try(OwnedFixture f=new OwnedFixture()) {
            Data data=f.data(null);Counted c=install(f,false);
            c.createSettingsRecord(addressKey(f),"mutability",null,2);c.invalidateNameCache();c.fault=fault;
            OwnedFixture.fails(Exception.class,()->f.observe(data));
            OwnedFixture.fails(OwnedProgramIntegrityException.class,f.program::checkOwnedIntegrity);
        }
        for(int index:new int[]{0,-1,32767,32766}) try(OwnedFixture f=new OwnedFixture()) {
            Data data=f.data(null);Counted c=install(f,false);
            DBRecord row=c.createSettingsRecord(addressKey(f),"mutability",null,2);
            row.setShortValue(SettingsDBAdapter.SETTINGS_NAME_INDEX_COL,(short)index);
            f.program.getDBHandle().getTable(c.getTableName()).putRecord(row);c.invalidateNameCache();
            OwnedFixture.fails(IOException.class,()->f.observe(data));
            OwnedFixture.fails(OwnedProgramIntegrityException.class,f.program::checkOwnedIntegrity);
        }
        try(OwnedFixture f=new OwnedFixture()) {
            Data component=f.program.getListing().createData(f.address,new ArrayDataType(new PointerDataType(),2,8)).getComponent(0);
            Counted d=install(f,true),i=install(f,false);
            OwnedFixture.fails(UnsupportedOperationException.class,()->f.observe(component));
            OwnedFixture.check(d.ranges==0 && i.ranges==0,"zero inherited settings reads");
        }
        for(long raw:new long[]{0,1,3}) try(OwnedFixture f=new OwnedFixture()) {
            Data data=f.data(null);Counted c=install(f,false);
            c.createSettingsRecord(addressKey(f),"mutability",null,raw);c.invalidateNameCache();
            OwnedFixture.fails(UnsupportedOperationException.class,()->f.observe(data));
        }
        for(String fault:new String[]{"missing-name","null-name","malformed-utf16","valid-max-index"})
        try(OwnedFixture f=new OwnedFixture()) {
            Data data=f.data(null);Counted c=install(f,false);DBRecord setting=c.createSettingsRecord(addressKey(f),"mutability",null,2);
            Table names=f.program.getDBHandle().getTable(c.getTableName()+" Names");
            short index=setting.getShortValue(SettingsDBAdapter.SETTINGS_NAME_INDEX_COL);
            DBRecord name=names.getRecord(index);
            if(fault.equals("missing-name")) names.deleteRecord(index);
            if(fault.equals("null-name")) {name.setString(0,null);names.putRecord(name);}
            if(fault.equals("malformed-utf16")) {name.setString(0,"\uD800");names.putRecord(name);}
            if(fault.equals("valid-max-index")) {
                name=SettingsDBAdapterV1.V1_NAME_TABLE_SCHEMA.createRecord(32766);name.setString(0,"mutability");names.putRecord(name);
                setting.setShortValue(SettingsDBAdapter.SETTINGS_NAME_INDEX_COL,(short)32766);
                f.program.getDBHandle().getTable(c.getTableName()).putRecord(setting);
            }
            c.invalidateNameCache();
            if(fault.equals("valid-max-index")) OwnedFixture.check(f.observe(data).constantInstance(),"maximum direct index");
            else OwnedFixture.fails(Exception.class,()->f.observe(data));
            OwnedFixture.check(c.next==1 && c.direct==1,"one direct name allocation");assertCold(c);
        }
        System.out.println("PASS OwnedPointerSettingsTest");
    }
}
