import java.lang.reflect.*;
import java.util.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.Reference;
import ghidra.util.task.TaskMonitor;

/** Runs against the actual bundled public APIs without requiring a database or external Ghidra. */
public class ReferencedBytesProbe {
    interface Call { Object apply(Method method, Object[] arguments) throws Throwable; }
    static <T> T proxy(Class<T> type, Call call) {
        return type.cast(Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[]{type}, (p,m,a) -> {
            Object value = call.apply(m, a);
            if (value != null) return value;
            if (m.getReturnType() == boolean.class) return false;
            if (m.getReturnType() == int.class) return 0;
            if (m.getReturnType() == long.class) return 0L;
            return null;
        }));
    }
    static void field(Object object, String name, Object value) throws Exception {
        Class<?> type = object.getClass();
        while (type != null) {
            try { Field field = type.getDeclaredField(name); field.setAccessible(true); field.set(object,value); return; }
            catch (NoSuchFieldException ignored) { type = type.getSuperclass(); }
        }
        throw new AssertionError(name);
    }
    static Object invoke(Object exporter, String name, Class<?>[] types, Object... args) throws Exception {
        Method method = exporter.getClass().getDeclaredMethod(name, types); method.setAccessible(true);
        return method.invoke(exporter,args);
    }
    static void check(boolean condition, Object detail) { if (!condition) throw new AssertionError(detail); }
    static void boundedPrepass(Object exporter, AddressSpace ram, AddressSpace constant, AddressSpace unique,
        AddressFactory addresses, int count, int width, int lastWidth, boolean candidateOnly, String expectedFailure) throws Exception {
        ghidra.program.model.symbol.SymbolTable symbols=proxy(ghidra.program.model.symbol.SymbolTable.class,(m,a)->null);
        FunctionManager manager=proxy(FunctionManager.class,(m,a)->null);
        Listing listing=proxy(Listing.class,(m,a)-> {
            if (!m.getName().equals("getInstructions")) return null;
            int[] cursor={0};
            return proxy(InstructionIterator.class,(im,ia)-> {
                if(im.getName().equals("hasNext")) return cursor[0] < (candidateOnly ? 1 : count);
                if(!im.getName().equals("next")) return null;
                final int index=cursor[0]++;
                Address target=candidateOnly ? constant.getAddress(7) : ram.getAddress(0x10000L+index*512L);
                Reference ref=proxy(Reference.class,(rm,ra)-> {
                    if(rm.getName().equals("getToAddress")) return target;
                    if(rm.getName().equals("getReferenceType")) return ghidra.program.model.symbol.RefType.DATA;
                    if(rm.getName().equals("getOperandIndex")) return 0;
                    return null;
                });
                int currentWidth=index == count-1 ? lastWidth : width;
                PcodeOp[] pcode=currentWidth == 0 ? new PcodeOp[0] : new PcodeOp[]{
                    new PcodeOp(ram.getAddress(0x2000L+index),0,PcodeOp.LOAD,
                        new Varnode[]{new Varnode(constant.getAddress(ram.getSpaceID()),4),new Varnode(constant.getAddress(target.getOffset()),8)},
                        new Varnode(unique.getAddress(1),currentWidth))};
                return proxy(Instruction.class,(nm,na)-> {
                    if(nm.getName().equals("getAddress")) return ram.getAddress(0x2000L+index);
                    if(nm.getName().equals("getPcode")) return pcode;
                    if(nm.getName().equals("getReferencesFrom")) {
                        Reference[] refs=new Reference[candidateOnly ? count : 1]; Arrays.fill(refs,ref); return refs;
                    }
                    return null;
                });
            });
        });
        // Every known-width byte is explicitly unmapped; budgets still count its requested span.
        Memory memory=proxy(Memory.class,(m,a)->null);
        field(exporter,"currentProgram",proxy(Program.class,(m,a)-> {
            if(m.getName().equals("getAddressFactory")) return addresses;
            if(m.getName().equals("getListing")) return listing;
            if(m.getName().equals("getSymbolTable")) return symbols;
            if(m.getName().equals("getFunctionManager")) return manager;
            if(m.getName().equals("getMemory")) return memory;
            return null;
        }));
        try {
            invoke(exporter,"collectReferencedByteEvidence",new Class<?>[]{List.class},List.of(proxy(Function.class,(m,a)->null)));
            check(expectedFailure == null,"expected bound diagnostic: "+expectedFailure);
        } catch(InvocationTargetException failure) {
            check(expectedFailure != null && failure.getCause().getMessage().contains(expectedFailure),failure.getCause());
        }
    }
    public static void main(String[] args) throws Exception {
        AddressSpace ram = new GenericAddressSpace("ram",64,AddressSpace.TYPE_RAM,0);
        AddressSpace constant = new GenericAddressSpace("const",64,AddressSpace.TYPE_CONSTANT,1);
        AddressSpace unique = new GenericAddressSpace("unique",64,AddressSpace.TYPE_UNIQUE,2);
        Address target = ram.getAddress(0x1000);
        AddressFactory addresses = new DefaultAddressFactory(new AddressSpace[]{ram}, ram);
        Object exporter = Class.forName("ExportProgramModel").getConstructor().newInstance();
        field(exporter,"monitor",TaskMonitor.DUMMY);
        // 0.5's leading zero bytes must not terminate an eight-byte read.
        byte[] bytes = {0,0,0,0,0,0,(byte)0xe0,0x3f};
        int[] mode = {0};
        MemoryBlock block = proxy(MemoryBlock.class,(m,a) -> {
            if (m.getName().equals("isRead")) return mode[0] != 2;
            if (m.getName().equals("isInitialized")) return mode[0] != 3;
            return null;
        });
        Memory memory = proxy(Memory.class,(m,a) -> {
            if (m.getName().equals("getBlock")) {
                long offset = ((Address)a[0]).getOffset() - target.getOffset();
                return mode[0] == 1 && offset >= 4 ? null : block;
            }
            if (m.getName().equals("getBytes")) {
                if (mode[0] == 4) return 0; // Deterministic short read must never become zero fill.
                if (mode[0] == 5) throw new MemoryAccessException("controlled read failure");
                ((byte[])a[1])[0] = bytes[(int)(((Address)a[0]).getOffset()-target.getOffset())];
                return 1;
            }
            return null;
        });
        field(exporter,"currentProgram",proxy(Program.class,(m,a) ->
            m.getName().equals("getMemory") ? memory : m.getName().equals("getAddressFactory") ? addresses : null));
        Class<?>[] readTypes = {Address.class,int.class};
        String available = (String)invoke(exporter,"readByteSegments",readTypes,target,8);
        check(available.equals("\"availability\":\"available\",\"segments\":[{\"offset\":0,\"length\":8,\"availability\":\"available\",\"hex\":\"000000000000e03f\",\"reason\":null}]"),available);
        mode[0]=1;
        String partial = (String)invoke(exporter,"readByteSegments",readTypes,target,8);
        check(partial.contains("\"availability\":\"partial\"") && partial.contains("\"hex\":\"00000000\"") &&
            partial.contains("\"offset\":4,\"length\":4,\"availability\":\"unavailable\",\"hex\":null,\"reason\":\"unmapped\""),partial);
        String[] reasons = {"unreadable","uninitialized","read_failed","read_failed"};
        for (int i=0;i<reasons.length;i++) {
            mode[0]=i+2;
            String unavailable=(String)invoke(exporter,"readByteSegments",readTypes,target,8);
            check(unavailable.equals("\"availability\":\"unavailable\",\"segments\":[{\"offset\":0,\"length\":8,\"availability\":\"unavailable\",\"hex\":null,\"reason\":\""+reasons[i]+"\"}]"),unavailable);
        }
        Varnode space=new Varnode(constant.getAddress(ram.getSpaceID()),4);
        Varnode pointer=new Varnode(constant.getAddress(target.getOffset()),8);
        PcodeOp load=new PcodeOp(target,0,PcodeOp.LOAD,new Varnode[]{space,pointer},new Varnode(unique.getAddress(1),8));
        PcodeOp store=new PcodeOp(target,1,PcodeOp.STORE,new Varnode[]{space,pointer,new Varnode(unique.getAddress(2),4)});
        Reference reference=proxy(Reference.class,(m,a) -> m.getName().equals("getToAddress") ? target : null);
        PcodeOp[][] ops={new PcodeOp[]{load}};
        Instruction instruction=proxy(Instruction.class,(m,a)->m.getName().equals("getPcode") ? ops[0] : null);
        Class<?>[] widthTypes={Instruction.class,Reference.class};
        check(Arrays.equals((int[])invoke(exporter,"referenceWidth",widthTypes,instruction,reference),new int[]{8,1}),"LOAD width");
        ops[0]=new PcodeOp[]{store};
        check(Arrays.equals((int[])invoke(exporter,"referenceWidth",widthTypes,instruction,reference),new int[]{4,2}),"STORE width");
        ops[0]=new PcodeOp[]{load,store};
        check(Arrays.equals((int[])invoke(exporter,"referenceWidth",widthTypes,instruction,reference),new int[]{0,0}),"ambiguous width");
        PcodeOp dynamic=new PcodeOp(target,2,PcodeOp.LOAD,new Varnode[]{space,new Varnode(unique.getAddress(3),8)},new Varnode(unique.getAddress(4),8));
        ops[0]=new PcodeOp[]{dynamic};
        check(Arrays.equals((int[])invoke(exporter,"referenceWidth",widthTypes,instruction,reference),new int[]{0,0}),"dynamic width");
        // Exercise the actual prepass: duplicate work is charged before deterministic deduplication.
        Reference repeated=proxy(Reference.class,(m,a) -> {
            if (m.getName().equals("getToAddress")) return target;
            if (m.getName().equals("getReferenceType")) return ghidra.program.model.symbol.RefType.DATA;
            if (m.getName().equals("getOperandIndex")) return -1;
            return null;
        });
        int[] occurrenceCount={32};
        Instruction repeatedInstruction=proxy(Instruction.class,(m,a)-> {
            if(m.getName().equals("getAddress")) return ram.getAddress(0x2000);
            if(m.getName().equals("getReferencesFrom")) {
                Reference[] refs=new Reference[occurrenceCount[0]]; Arrays.fill(refs,repeated); return refs;
            }
            if(m.getName().equals("getPcode")) return new PcodeOp[]{dynamic};
            return null;
        });
        Listing listing=proxy(Listing.class,(m,a)-> {
            if(m.getName().equals("getInstructions")) {
                boolean[] consumed={false};
                return proxy(InstructionIterator.class,(im,ia)-> {
                    if(im.getName().equals("hasNext")) return !consumed[0];
                    if(im.getName().equals("next")) { consumed[0]=true; return repeatedInstruction; }
                    return null;
                });
            }
            return null;
        });
        ghidra.program.model.symbol.SymbolTable symbols=proxy(ghidra.program.model.symbol.SymbolTable.class,(m,a)->null);
        FunctionManager manager=proxy(FunctionManager.class,(m,a)->null);
        Program prepassProgram=proxy(Program.class,(m,a)-> {
            if(m.getName().equals("getAddressFactory")) return addresses;
            if(m.getName().equals("getListing")) return listing;
            if(m.getName().equals("getSymbolTable")) return symbols;
            if(m.getName().equals("getFunctionManager")) return manager;
            return null;
        });
        field(exporter,"currentProgram",prepassProgram);
        Function function=proxy(Function.class,(m,a)->null);
        invoke(exporter,"collectReferencedByteEvidence",new Class<?>[]{List.class},List.of(function));
        Field evidenceField=exporter.getClass().getDeclaredField("referencedByteEvidence"); evidenceField.setAccessible(true);
        String evidence=((Map<?,?>)evidenceField.get(exporter)).values().iterator().next().toString();
        check(evidence.contains("\"omissionReason\":\"unknown_access_width\"") &&
            evidence.indexOf("\"requestedLength\"")==evidence.lastIndexOf("\"requestedLength\""),evidence);
        occurrenceCount[0]=33;
        try { invoke(exporter,"collectReferencedByteEvidence",new Class<?>[]{List.class},List.of(function)); throw new AssertionError("global work bound ignored"); }
        catch(InvocationTargetException expected) { check(expected.getCause().getMessage().contains("global bound"),expected.getCause()); }
        boundedPrepass(exporter,ram,constant,unique,addresses,65536,0,0,true,null);
        boundedPrepass(exporter,ram,constant,unique,addresses,65537,0,0,true,"candidate bound");
        boundedPrepass(exporter,ram,constant,unique,addresses,4096,0,0,false,null);
        boundedPrepass(exporter,ram,constant,unique,addresses,4097,0,0,false,"window model bound");
        boundedPrepass(exporter,ram,constant,unique,addresses,1,256,256,false,null);
        boundedPrepass(exporter,ram,constant,unique,addresses,1,257,257,false,"window requested-byte bound");
        boundedPrepass(exporter,ram,constant,unique,addresses,256,256,256,false,null);
        boundedPrepass(exporter,ram,constant,unique,addresses,257,256,1,false,"model requested-byte bound");
        System.out.println("exact/one-over candidate65536 windows4096 windowBytes256 requestedBytes65536 bounds passed");
        field(exporter,"currentProgram",proxy(Program.class,(m,a) ->
            m.getName().equals("getMemory") ? memory : m.getName().equals("getAddressFactory") ? addresses : null));
        AddressSpace otherRam = new GenericAddressSpace("other_ram",64,AddressSpace.TYPE_RAM,3);
        try { invoke(exporter,"byteAddress",new Class<?>[]{Address.class},otherRam.getAddress(0x1000));
            throw new AssertionError("offset alias in another memory space accepted"); }
        catch(InvocationTargetException expected) { check(expected.getCause().getMessage().contains("unrepresentable"),expected.getCause()); }
        check(invoke(exporter,"byteAddress",new Class<?>[]{Address.class},target).equals("0x1000"),"default address space");
        field(exporter,"monitor",proxy(TaskMonitor.class,(m,a)->m.getName().equals("isCancelled")));
        try { invoke(exporter,"readByteSegments",readTypes,target,8); throw new AssertionError("cancellation ignored"); }
        catch (InvocationTargetException expected) { check(expected.getCause() instanceof InterruptedException,expected); }
        System.out.println("referenced byte API probe passed");
    }
}
