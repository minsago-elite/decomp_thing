package ghidra.program.database.data;

import ghidra.program.model.data.*;
import ghidra.program.model.listing.Data;

public final class OwnedPointerObservationTest {
    public static void main(String[] args) throws Exception {
        OwnedFixture.boot(args[0]);
        DataType[] children = {null, DataType.DEFAULT, BadDataType.dataType, VoidDataType.dataType,
            IntegerDataType.dataType, new FunctionDefinitionDataType("function_child")};
        for (DataType child : children) try (OwnedFixture f = new OwnedFixture()) {
            Data selected = f.data(child);
            PointerReferenceObservation o = f.observe(selected);
            OwnedFixture.check(o.selected() == selected && o.program() == f.program && o.manager() == f.manager,
                "actual listing/Program/manager");
            OwnedFixture.check(o.pointer() == selected.getDataType() && o.length() == 8 && o.alignment() == 8,
                "exact PointerDB and layout");
            if (child == null) OwnedFixture.check(o.childID() == -1, "explicit unspecified");
            else if (child == DataType.DEFAULT) OwnedFixture.check(o.childID() == 0, "DEFAULT distinct");
            else if (child == BadDataType.dataType) OwnedFixture.check(o.childID() == -2, "BAD distinct");
            else OwnedFixture.check(o.childID() != -1 && o.childID() != -2 && o.childID() != 0, "typed child distinct");
            f.program.checkOwnedIntegrity();
            System.out.println("PASS actual edge " + o.childID());
        }
        for (int length : new int[]{1,2,3,4,5,6,7,8,9,127}) try (OwnedFixture f=new OwnedFixture()) {
            if(length>8) {
                OwnedFixture.fails(ghidra.framework.data.OwnedProgramIntegrityException.class,
                    ()->f.program.getListing().createData(f.address,new PointerDataType(null,length)));
                OwnedFixture.fails(ghidra.framework.data.OwnedProgramIntegrityException.class,f.program::checkOwnedIntegrity);
                continue; // upstream value conversion rejects these sizes before observation
            }
            Data selected=f.program.getListing().createData(f.address,new PointerDataType(null,length));
            if(length==8) OwnedFixture.check(!f.observe(selected).dynamic(),"fixed8");
            else OwnedFixture.fails(UnsupportedOperationException.class,()->f.observe(selected));
            f.program.checkOwnedIntegrity();
        }
        for(long edge:new long[]{-3,Long.MAX_VALUE,DataTypeManagerDB.createKey(DataTypeManagerDB.POINTER,99999)})
        try(OwnedFixture f=new OwnedFixture()) {
            Data selected=f.data(null);PointerDB pointer=(PointerDB)selected.getDataType();
            pointer.record.setLongValue(PointerDBAdapter.PTR_DT_ID_COL,edge);
            f.program.getDBHandle().getTable("Pointers").putRecord(pointer.record);
            OwnedFixture.fails(ghidra.framework.data.OwnedProgramIntegrityException.class,()->f.observe(selected));
        }
        try(OwnedFixture f=new OwnedFixture()) {
            Data selected=f.program.getListing().createData(f.address,new TypedefDataType("wrapped",new PointerDataType()));
            OwnedFixture.fails(UnsupportedOperationException.class,()->f.observe(selected));
        }
        try(OwnedFixture f=new OwnedFixture()) {
            Data selected=f.data(null);PointerDB pointer=(PointerDB)selected.getDataType();
            pointer.record.setByteValue(PointerDBAdapter.PTR_LENGTH_COL,(byte)0);
            f.program.getDBHandle().getTable("Pointers").putRecord(pointer.record);
            OwnedFixture.fails(UnsupportedOperationException.class,()->f.observe(selected));
        }
        try(OwnedFixture f=new OwnedFixture()) {
            Data selected=f.data(null);DataOrganizationImpl organization=(DataOrganizationImpl)f.manager.getDataOrganization();
            int old=organization.getPointerSize();organization.setPointerSize(4);
            try {OwnedFixture.fails(UnsupportedOperationException.class,()->f.observe(selected));}
            finally {organization.setPointerSize(old);}
            organization.setSizeAlignment(8,4);
            try {OwnedFixture.fails(UnsupportedOperationException.class,()->f.observe(selected));}
            finally {organization.setSizeAlignment(8,8);}
        }
        try(OwnedFixture f=new OwnedFixture(OwnedFixture.language,"windows")) {
            Data data=f.data(null);OwnedFixture.fails(UnsupportedOperationException.class,()->f.observe(data));
        }
        ghidra.program.model.lang.Language x86_32=ghidra.program.util.DefaultLanguageService.getLanguageService().getLanguage(new ghidra.program.model.lang.LanguageID("x86:LE:32:default"));
        try(OwnedFixture f=new OwnedFixture(x86_32,"gcc")) {
            Data data=f.data(null);OwnedFixture.fails(UnsupportedOperationException.class,()->f.observe(data));
        }
        System.out.println("PASS OwnedPointerObservationTest");
    }
}
