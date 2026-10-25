import java.lang.reflect.*;
import java.util.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.RefType;
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
    static Object get(Object object, String name) throws Exception {
        Field field=object.getClass().getDeclaredField(name); field.setAccessible(true); return field.get(object);
    }
    static int occurrences(String text, String needle) {
        int count=0, offset=0;
        while ((offset=text.indexOf(needle,offset))>=0) { count++; offset+=needle.length(); }
        return count;
    }
    /** Authored fixed-snapshot API fixture, not a binary-analysis result. */
    static class CollectionFixture {
        final AddressSpace ram, unique;
        final AddressFactory addresses;
        final List<Instruction> instructions=new ArrayList<>();
        final Map<Address,List<Reference>> references=new HashMap<>();
        boolean sharedGlobal, strings, reverse, conflicting, streamNextInstruction;
        long sharedBelow=Long.MAX_VALUE;
        int memoryQueries, widthQueries, referenceVisits;
        CollectionFixture(AddressSpace ram, AddressSpace unique, AddressFactory addresses) {
            this.ram=ram; this.unique=unique; this.addresses=addresses;
        }
        void add(int count, int width) {
            for (int i=0;i<count;i++) batch(new long[]{0x10000L+instructions.size()*512L},width,1);
        }
        void batch(long[] targets, int width, int repeats) {
            Address from=ram.getAddress(0x2000L+instructions.size());
            List<Reference> refs=new ArrayList<>();
            List<PcodeOp> ops=new ArrayList<>();
            for (long offset:targets) {
                Address target=ram.getAddress(offset);
                Reference ref=proxy(Reference.class,(m,a)-> {
                    if(m.getName().equals("getFromAddress")) return from;
                    if(m.getName().equals("getToAddress")) return target;
                    if(m.getName().equals("getReferenceType")) return RefType.DATA;
                    if(m.getName().equals("getOperandIndex")) return -2; // normalized to wire null
                    return null;
                });
                for(int n=0;n<repeats;n++) refs.add(ref);
                if(width>0) ops.add(new PcodeOp(from,ops.size(),PcodeOp.COPY,
                    new Varnode[]{new Varnode(target,width)},new Varnode(unique.getAddress(1),width)));
            }
            references.put(from,refs);
            instructions.add(proxy(Instruction.class,(m,a)-> {
                if(m.getName().equals("getAddress")) return from;
                if(m.getName().equals("getReferencesFrom")) throw new AssertionError("prepass must use streaming ReferenceManager");
                if(m.getName().equals("getPcode")) {
                    widthQueries++;
                    if(conflicting) return new PcodeOp[]{new PcodeOp(from,0,PcodeOp.COPY,
                        new Varnode[]{new Varnode(ram.getAddress(targets[0]),widthQueries%2==1 ? 1 : 2)},
                        new Varnode(unique.getAddress(1),widthQueries%2==1 ? 1 : 2))};
                    return ops.toArray(new PcodeOp[0]);
                }
                return null;
            }));
        }
        Program program() {
            Data data=proxy(Data.class,(m,a)-> {
                if(m.getName().equals("getAddress")) return ram.getAddress(0x1000);
                if(m.getName().equals("hasStringValue")) return strings;
                if(m.getName().equals("getValue") && strings) return "synthetic string";
                if(m.getName().equals("getDataType")) return ghidra.program.model.data.Undefined8DataType.dataType;
                if(m.getName().equals("getDefaultValueRepresentation")) return "00h";
                return null;
            });
            Listing listing=proxy(Listing.class,(m,a)-> {
                if(m.getName().equals("getDataContaining")) return strings || (sharedGlobal && ((Address)a[0]).getOffset()<sharedBelow) ? data : null;
                if(!m.getName().equals("getInstructions")) return null;
                Iterator<Instruction> it=instructions.iterator();
                return proxy(InstructionIterator.class,(im,ia)->im.getName().equals("hasNext") ? it.hasNext() : im.getName().equals("next") ? it.next() : null);
            });
            ReferenceManager manager=proxy(ReferenceManager.class,(m,a)-> {
                if(!m.getName().equals("getReferenceIterator")) return null;
                List<Reference> refs=new ArrayList<>(references.get((Address)a[0]));
                if(reverse) Collections.reverse(refs);
                if(streamNextInstruction) {
                    List<Reference> next=references.get(((Address)a[0]).add(1));
                    if(next!=null && !next.isEmpty()) refs.add(next.get(0));
                }
                Iterator<Reference> it=refs.iterator();
                return proxy(ReferenceIterator.class,(im,ia)-> {
                    if(im.getName().equals("hasNext")) return it.hasNext();
                    if(im.getName().equals("next")) { referenceVisits++; return it.next(); }
                    return null;
                });
            });
            return proxy(Program.class,(m,a)-> {
                if(m.getName().equals("getAddressFactory")) return addresses;
                if(m.getName().equals("getListing")) return listing;
                if(m.getName().equals("getReferenceManager")) return manager;
                if(m.getName().equals("getSymbolTable")) return proxy(ghidra.program.model.symbol.SymbolTable.class,(sm,sa)->null);
                if(m.getName().equals("getFunctionManager")) return proxy(FunctionManager.class,(fm,fa)->null);
                if(m.getName().equals("getMemory")) return proxy(Memory.class,(mm,ma)-> {
                    if(mm.getName().equals("getBlock")) memoryQueries++;
                    return null; // known widths are explicitly unmapped, never fabricated bytes
                });
                return null;
            });
        }
        Map<String,String> run(Object exporter) throws Exception {
            memoryQueries=widthQueries=referenceVisits=0;
            field(exporter,"currentProgram",program());
            invoke(exporter,"collectReferencedByteEvidence",new Class<?>[]{List.class},List.of(proxy(Function.class,(m,a)->null)));
            return new TreeMap<>((Map<String,String>)get(exporter,"referencedByteEvidence"));
        }
        String only(Object exporter) throws Exception { return run(exporter).values().iterator().next(); }
    }
    static void omissionControls(Object exporter, AddressSpace ram, AddressSpace unique, AddressFactory addresses) throws Exception {
        CollectionFixture f=new CollectionFixture(ram,unique,addresses);
        f.sharedGlobal=true; f.add(32,1);
        String exact=f.only(exporter);
        check(occurrences(exact,"\"requestedLength\":")==32 && exact.contains("\"collectionOmissions\":[]"),"32 distinct origins complete");
        f.add(1,1);
        String capped=f.only(exporter);
        check(occurrences(capped,"\"requestedLength\":")==32 && capped.contains("[\"global_window_limit\"]") && f.memoryQueries==32,"33rd origin has no byte read");
        f=new CollectionFixture(ram,unique,addresses); f.batch(new long[]{0x1000},1,33);
        String duplicate=f.only(exporter);
        check(occurrences(duplicate,"\"requestedLength\":")==1 && duplicate.contains("\"collectionOmissions\":[]") && f.memoryQueries==1 && f.widthQueries==33,"duplicates charge work not payload");
        f.conflicting=true;
        try { f.run(exporter); throw new AssertionError("conflicting origin accepted"); }
        catch(InvocationTargetException failure) { check(failure.getCause().getMessage().contains("conflicting reference"),failure.getCause()); }
        f=new CollectionFixture(ram,unique,addresses); f.sharedGlobal=true;
        long[] targets=new long[33]; for(int n=0;n<33;n++) targets[n]=0x1000+n;
        f.batch(targets,1,1); Map<String,String> forward=f.run(exporter); f.reverse=true;
        check(forward.equals(f.run(exporter)),"reference API reversal must not change retained selection");
        // A capped hot global must not consume the cold global's slot or requested bytes.
        f=new CollectionFixture(ram,unique,addresses); f.sharedGlobal=true; f.sharedBelow=0x800000; f.add(40,0);
        f.batch(new long[]{0x900000},2,1);
        Map<String,String> hotCold=f.run(exporter);
        check(hotCold.size()==2 && f.memoryQueries==2 && hotCold.values().stream().anyMatch(v->v.contains("\"requestedLength\":2") && v.contains("\"collectionOmissions\":[]")),"hot omissions leave cold payload capacity");
        f=new CollectionFixture(ram,unique,addresses); f.sharedGlobal=true;
        f.batch(new long[]{0x1000},8,1); f.batch(new long[]{0x1000},4,1); f.batch(new long[]{0x1002},2,1);
        String interior=f.only(exporter);
        check(occurrences(interior,"\"requestedLength\":")==3 && interior.contains("\"requestedLength\":8") && interior.contains("\"requestedLength\":4") && interior.contains("\"requestedLength\":2") && interior.contains("0x1002"),"shared global retains distinct origin widths and interior addresses");
        // Separate globals exercise the aggregate window cap and a later uncached fallback.
        f=new CollectionFixture(ram,unique,addresses); f.add(4096,0);
        check(f.run(exporter).size()==4096 && get(exporter,"referenceCollectionCutoff")==null,"4096 exact windows");
        f.add(1,0); Map<String,String> model=f.run(exporter);
        check(model.size()==4096 && model.values().stream().allMatch(v->v.contains("[\"model_window_limit\"]")),"4097 marks all retained globals");
        Object later=invoke(exporter,"globalAt",new Class<?>[]{Address.class},ram.getAddress(0x900000));
        Field evidence=later.getClass().getDeclaredField("byteEvidence"); evidence.setAccessible(true);
        check(evidence.get(later).equals("{\"schemaVersion\":2,\"windows\":[],\"omissionReason\":null,\"collectionOmissions\":[\"model_window_limit\"]}"),"true stop gives exact empty fallback");
        check(((Map<?,?>)get(exporter,"referencedByteEvidence")).size()==4096,"fallback never caches unseen IDs");
        field(exporter,"referenceCollectionCutoff",null);
        try { invoke(exporter,"globalAt",new Class<?>[]{Address.class},ram.getAddress(0x900000)); throw new AssertionError("missing origin accepted without cutoff"); }
        catch(InvocationTargetException failure) { check(failure.getCause().getMessage().startsWith("missing reference byte-evidence origin: "),failure.getCause()); }
        f=new CollectionFixture(ram,unique,addresses); f.add(256,256);
        check(f.run(exporter).size()==256 && f.memoryQueries==65536,"65536 exact requested bytes");
        f.add(1,1); model=f.run(exporter);
        check(model.size()==256 && f.memoryQueries==65536 && model.values().stream().allMatch(v->v.contains("model_requested_byte_limit")),"crossing window is wholly unread");
        f=new CollectionFixture(ram,unique,addresses); f.sharedGlobal=true; f.sharedBelow=0x800000; f.add(33,0);
        for(int n=0;n<256;n++) f.batch(new long[]{0x900000L+n*512L},256,1);
        f.batch(new long[]{0xa00000},1,1); model=f.run(exporter);
        check(model.size()==257 && f.memoryQueries==65536 && model.values().stream().anyMatch(v->v.contains("\"omissionReason\":\"unknown_access_width\"") && v.contains("[\"global_window_limit\",\"model_requested_byte_limit\"]")),"local plus actual aggregate reason stays ordered and separate from unknown width");
        f=new CollectionFixture(ram,unique,addresses); f.add(255,256); f.add(1,255); f.add(1,2);
        check(f.run(exporter).size()==256 && f.memoryQueries==65535,"65535 plus two does not take a partial byte");
        f=new CollectionFixture(ram,unique,addresses); f.add(1,257);
        try { f.run(exporter); throw new AssertionError("width257 accepted"); }
        catch(InvocationTargetException failure) { check(failure.getCause().getMessage().contains("requested-byte bound"),failure.getCause()); }
        f=new CollectionFixture(ram,unique,addresses); f.batch(new long[]{0x1000},0,65536);
        check(f.run(exporter).size()==1 && f.widthQueries==65536 && get(exporter,"referenceCollectionCutoff")==null,"work65536 exact with duplicate dedup");
        f=new CollectionFixture(ram,unique,addresses); f.batch(new long[]{0x1000},0,65537);
        check(f.run(exporter).isEmpty() && f.referenceVisits==65537 && f.widthQueries==0 && f.memoryQueries==0 && get(exporter,"referenceCollectionCutoff").equals("reference_work_limit"),"whole oversized batch unadmitted with one lookahead");
        f=new CollectionFixture(ram,unique,addresses); f.batch(new long[]{0x1000},0,65535); f.batch(new long[]{0x2000,0x2001},1,1);
        check(f.run(exporter).size()==1 && f.widthQueries==65535 && f.memoryQueries==0 && f.referenceVisits==65537 && get(exporter,"referenceCollectionCutoff").equals("reference_work_limit"),"remaining work rejects whole next batch before width/read");
        f.reverse=true;
        check(f.run(exporter).size()==1 && f.widthQueries==65535,"oversized batch reversal retains no partial batch");
        f=new CollectionFixture(ram,unique,addresses); f.add(2,1); f.streamNextInstruction=true;
        check(f.run(exporter).size()==2 && f.widthQueries==2 && f.referenceVisits==3,"stream iterator stops when fromAddress leaves current instruction");
        f=new CollectionFixture(ram,unique,addresses); f.sharedGlobal=true; f.add(33,0);
        String unknown=f.only(exporter);
        check(unknown.contains("\"omissionReason\":\"unknown_access_width\"") && unknown.contains("global_window_limit"),"width unknown is separate from collection omission");
        f=new CollectionFixture(ram,unique,addresses);
        check(f.run(exporter).isEmpty() && get(exporter,"referenceCollectionCutoff")==null,"no refs invent no globals/cutoff");
        f.add(1,1); f.strings=true;
        check(f.run(exporter).isEmpty() && f.widthQueries==0,"recognized nonnull strings invent no byte globals");
        cancellationControls(exporter,ram,unique,addresses);
        System.out.println("omission controls passed: local32 model4096 bytes65536 work65536 deterministic dedup true-cutoff fallback");
    }

    static void interruptedCollection(Object exporter, CollectionFixture fixture, TaskMonitor monitor, String detail) throws Exception {
        field(exporter,"monitor",monitor);
        try { fixture.run(exporter); throw new AssertionError("cancellation ignored: "+detail); }
        catch(InvocationTargetException failure) { check(failure.getCause() instanceof InterruptedException,detail+": "+failure.getCause()); }
        finally { field(exporter,"monitor",TaskMonitor.DUMMY); }
    }
    static void cancellationControls(Object exporter, AddressSpace ram, AddressSpace unique, AddressFactory addresses) throws Exception {
        for(int boundary:new int[]{32,33}) {
            CollectionFixture fixture=new CollectionFixture(ram,unique,addresses); fixture.sharedGlobal=true; fixture.add(33,0);
            interruptedCollection(exporter,fixture,proxy(TaskMonitor.class,(m,a)->m.getName().equals("isCancelled") && fixture.widthQueries>=boundary),"local boundary"+boundary);
        }
        CollectionFixture fixture=new CollectionFixture(ram,unique,addresses); fixture.batch(new long[]{0x1000},0,65537);
        interruptedCollection(exporter,fixture,proxy(TaskMonitor.class,(m,a)->m.getName().equals("isCancelled") && get(exporter,"referenceCollectionCutoff")!=null),"immediately after true work stop");
        fixture=new CollectionFixture(ram,unique,addresses); fixture.add(4097,0);
        interruptedCollection(exporter,fixture,proxy(TaskMonitor.class,(m,a)->m.getName().equals("isCancelled") && get(exporter,"referenceCollectionCutoff")!=null),"immediately after aggregate window stop");
        fixture=new CollectionFixture(ram,unique,addresses); fixture.add(257,256);
        interruptedCollection(exporter,fixture,proxy(TaskMonitor.class,(m,a)->m.getName().equals("isCancelled") && get(exporter,"referenceCollectionCutoff")!=null),"immediately after aggregate byte stop");
        fixture=new CollectionFixture(ram,unique,addresses); fixture.add(2,0);
        interruptedCollection(exporter,fixture,proxy(TaskMonitor.class,(m,a)->m.getName().equals("isCancelled") && !((Map<?,?>)get(exporter,"referencedByteEvidence")).isEmpty()),"retained rendering");
        fixture=new CollectionFixture(ram,unique,addresses); fixture.batch(new long[]{0x1000,0x1001},0,1);
        interruptedCollection(exporter,fixture,proxy(TaskMonitor.class,(m,a)-> {
            if(!m.getName().equals("isCancelled")) return null;
            for(StackTraceElement frame:Thread.currentThread().getStackTrace())
                if(frame.getMethodName().equals("checkByteSortCancellation")) return true;
            return false;
        }),"bounded reference sort");
        field(exporter,"referenceCollectionCutoff","model_window_limit");
        field(exporter,"monitor",proxy(TaskMonitor.class,(m,a)->m.getName().equals("isCancelled")));
        try { invoke(exporter,"globalAt",new Class<?>[]{Address.class},ram.getAddress(0x900000)); throw new AssertionError("cancelled fallback accepted"); }
        catch(InvocationTargetException failure) { check(failure.getCause() instanceof InterruptedException,failure.getCause()); }
        finally { field(exporter,"monitor",TaskMonitor.DUMMY); }
    }

    /** Exercise the actual production recovery catch, not only the private cancellation helper. */
    static void threadOnlyProductionCatchControl(Object exporter, AddressSpace ram, AddressFactory addresses) throws Exception {
        check(!Thread.currentThread().isInterrupted(),"thread-only control starts without inherited interruption");
        boolean[] enteredDataReference={false};
        Reference reference=proxy(Reference.class,(m,a)-> {
            if(m.getName().equals("getToAddress")) return ram.getAddress(0x1000);
            if(m.getName().equals("getReferenceType")) return RefType.DATA;
            return null;
        });
        Instruction instruction=proxy(Instruction.class,(m,a)-> {
            if(m.getName().equals("getAddress")) return ram.getAddress(0x2000);
            if(m.getName().equals("getReferencesFrom")) {
                enteredDataReference[0]=true;
                Thread.currentThread().interrupt(); // monitor stays false; globalAt throws.
                return new Reference[]{reference};
            }
            return null;
        });
        Listing listing=proxy(Listing.class,(m,a)-> {
            if(!m.getName().equals("getInstructions")) return null;
            Iterator<Instruction> it=List.of(instruction).iterator();
            return proxy(InstructionIterator.class,(im,ia)->im.getName().equals("hasNext") ? it.hasNext() : im.getName().equals("next") ? it.next() : null);
        });
        field(exporter,"currentProgram",proxy(Program.class,(m,a)-> {
            if(m.getName().equals("getAddressFactory")) return addresses;
            if(m.getName().equals("getListing")) return listing;
            if(m.getName().equals("getFunctionManager")) return proxy(FunctionManager.class,(fm,fa)->null);
            return null;
        }));
        TaskMonitor uncancelled=proxy(TaskMonitor.class,(m,a)->false);
        field(exporter,"monitor",uncancelled);
        Function function=proxy(Function.class,(m,a)-> {
            if(m.getName().equals("getCalledFunctions")) return Collections.emptySet();
            if(m.getName().equals("getReturnType")) throw new AssertionError("interruption was downgraded to function recovery");
            return null;
        });
        Class<?> planningEvidence=Arrays.stream(exporter.getClass().getDeclaredClasses())
            .filter(c->c.getSimpleName().equals("PlanningBatchEvidence")).findFirst().orElseThrow();
        try {
            invoke(exporter,"exportFunction",new Class<?>[]{Function.class,ghidra.app.decompiler.DecompInterface.class,
                java.nio.file.Path.class,java.nio.file.Path.class,planningEvidence,boolean.class,int.class},
                function,null,null,null,null,false,60);
            throw new AssertionError("thread-only interrupted export returned a FunctionExport");
        } catch(InvocationTargetException failure) {
            check(enteredDataReference[0] && failure.getCause() instanceof InterruptedException,failure.getCause());
            check(!uncancelled.isCancelled() && Thread.currentThread().isInterrupted(),"production catch must preserve thread-only cancellation and flag");
        } finally {
            Thread.interrupted(); // Clear only this authored control's interrupt, never production state.
            field(exporter,"monitor",TaskMonitor.DUMMY);
        }
        // Also preserve an InterruptedException whose originating API cleared the thread flag.
        InterruptedException clearedFlag=new InterruptedException("authored cleared-flag interruption");
        try {
            invoke(exporter,"rethrowInfrastructureFailure",new Class<?>[]{Exception.class},clearedFlag);
            throw new AssertionError("cleared-flag InterruptedException was classified as recovery");
        } catch(InvocationTargetException failure) {
            check(failure.getCause()==clearedFlag && Thread.currentThread().isInterrupted(),"typed interruption identity and flag restored");
        } finally { Thread.interrupted(); }
        // A current interrupt must also keep an unrelated recovery exception out of partial output.
        IllegalStateException flaggedFailure=new IllegalStateException("authored flagged recovery failure");
        try {
            Thread.currentThread().interrupt();
            invoke(exporter,"rethrowInfrastructureFailure",new Class<?>[]{Exception.class},flaggedFailure);
            throw new AssertionError("current interrupt flag was classified as recovery");
        } catch(InvocationTargetException failure) {
            check(failure.getCause()==flaggedFailure && Thread.currentThread().isInterrupted(),"flagged infrastructure failure preserves identity and flag");
        } finally { Thread.interrupted(); }
        // Existing infrastructure and monitor boundaries still propagate the original failure.
        Constructor<?> integrity=Arrays.stream(exporter.getClass().getDeclaredClasses())
            .filter(c->c.getSimpleName().equals("PlanningIntegrityException")).findFirst().orElseThrow().getDeclaredConstructor(String.class);
        integrity.setAccessible(true);
        for(Exception original:new Exception[]{new java.io.IOException("authored IO"),(Exception)integrity.newInstance("authored integrity")}) {
            try {
                invoke(exporter,"rethrowInfrastructureFailure",new Class<?>[]{Exception.class},original);
                throw new AssertionError("existing infrastructure failure swallowed");
            } catch(InvocationTargetException failure) { check(failure.getCause()==original,"infrastructure failure identity retained"); }
        }
        Exception ordinary=new Exception("authored ordinary recovery failure");
        invoke(exporter,"rethrowInfrastructureFailure",new Class<?>[]{Exception.class},ordinary);
        field(exporter,"monitor",proxy(TaskMonitor.class,(m,a)->m.getName().equals("isCancelled")));
        try {
            invoke(exporter,"rethrowInfrastructureFailure",new Class<?>[]{Exception.class},ordinary);
            throw new AssertionError("existing monitor cancellation swallowed");
        } catch(InvocationTargetException failure) { check(failure.getCause()==ordinary,"monitor cancellation preserves original failure"); }
        finally { field(exporter,"monitor",TaskMonitor.DUMMY); }
        System.out.println("production catch thread-only interruption controls passed");
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
        PcodeOp directRead=new PcodeOp(target,3,PcodeOp.COPY,new Varnode[]{new Varnode(target,8)},new Varnode(unique.getAddress(5),8));
        PcodeOp directWrite=new PcodeOp(target,4,PcodeOp.COPY,new Varnode[]{new Varnode(unique.getAddress(6),4)},new Varnode(target,4));
        ops[0]=new PcodeOp[]{directRead};
        check(Arrays.equals((int[])invoke(exporter,"referenceWidth",widthTypes,instruction,reference),new int[]{8,3}),"direct read width and distinct origin");
        ops[0]=new PcodeOp[]{directWrite};
        check(Arrays.equals((int[])invoke(exporter,"referenceWidth",widthTypes,instruction,reference),new int[]{4,4}),"direct write width and distinct origin");
        ops[0]=new PcodeOp[]{directRead,directWrite};
        check(Arrays.equals((int[])invoke(exporter,"referenceWidth",widthTypes,instruction,reference),new int[]{0,0}),"conflicting direct widths/origins stay unknown");
        ops[0]=new PcodeOp[]{new PcodeOp(target,5,PcodeOp.INT_ADD,new Varnode[]{new Varnode(target,8),pointer},new Varnode(unique.getAddress(7),8))};
        check(Arrays.equals((int[])invoke(exporter,"referenceWidth",widthTypes,instruction,reference),new int[]{0,0}),"unsupported direct operation stays unknown");
        AddressSpace arithmeticOtherRam = new GenericAddressSpace("arithmeticOtherRam",64,AddressSpace.TYPE_RAM,7);
        for (int opcode : new int[]{PcodeOp.FLOAT_ADD,PcodeOp.FLOAT_MULT}) {
            Varnode register = new Varnode(unique.getAddress(10),8);
            PcodeOp arithmetic = new PcodeOp(target,6,opcode,new Varnode[]{register,new Varnode(target,8)},register);
            ops[0]=new PcodeOp[]{arithmetic};
            check(Arrays.equals((int[])invoke(exporter,"referenceWidth",widthTypes,instruction,reference),new int[]{8,3}),"finite floating arithmetic direct read");
            ops[0]=new PcodeOp[]{new PcodeOp(target,7,opcode,new Varnode[]{new Varnode(target,8),register},register)};
            check(Arrays.equals((int[])invoke(exporter,"referenceWidth",widthTypes,instruction,reference),new int[]{8,3}),"either semantic value input is a read");
            for (Address different : new Address[]{target.add(1),arithmeticOtherRam.getAddress(target.getOffset()),constant.getAddress(target.getOffset())}) {
                ops[0]=new PcodeOp[]{new PcodeOp(target,8,opcode,new Varnode[]{register,new Varnode(different,8)},register)};
                check(Arrays.equals((int[])invoke(exporter,"referenceWidth",widthTypes,instruction,reference),new int[]{0,0}),"floating input must match exact address and RAM space");
            }
            ops[0]=new PcodeOp[]{new PcodeOp(target,9,opcode,new Varnode[]{register,new Varnode(target,4)},register)};
            check(Arrays.equals((int[])invoke(exporter,"referenceWidth",widthTypes,instruction,reference),new int[]{0,0}),"floating width mismatch stays unknown");
            ops[0]=new PcodeOp[]{new PcodeOp(target,10,opcode,new Varnode[]{new Varnode(target,8),new Varnode(target,8)},register)};
            check(Arrays.equals((int[])invoke(exporter,"referenceWidth",widthTypes,instruction,reference),new int[]{0,0}),"multiple floating associations stay unknown");
            ops[0]=new PcodeOp[]{new PcodeOp(target,11,opcode,new Varnode[]{register,new Varnode(target,8)},new Varnode(target,8))};
            check(Arrays.equals((int[])invoke(exporter,"referenceWidth",widthTypes,instruction,reference),new int[]{0,0}),"floating read write alias stays unknown");
            ops[0]=new PcodeOp[]{arithmetic,directRead};
            check(Arrays.equals((int[])invoke(exporter,"referenceWidth",widthTypes,instruction,reference),new int[]{0,0}),"multiple operation associations stay unknown");
        }
        for (int opcode : new int[]{PcodeOp.FLOAT_SUB,PcodeOp.FLOAT_DIV,PcodeOp.INT_MULT,PcodeOp.BRANCH,PcodeOp.CALL}) {
            ops[0]=new PcodeOp[]{new PcodeOp(target,12,opcode,new Varnode[]{new Varnode(target,8),pointer},new Varnode(unique.getAddress(11),8))};
            check(Arrays.equals((int[])invoke(exporter,"referenceWidth",widthTypes,instruction,reference),new int[]{0,0}),"unreviewed arithmetic/control flow stays unknown");
        }
        ops[0]=new PcodeOp[]{store};
        check(Arrays.equals((int[])invoke(exporter,"referenceWidth",widthTypes,instruction,reference),new int[]{4,2}),"STORE width");
        ops[0]=new PcodeOp[]{load,store};
        check(Arrays.equals((int[])invoke(exporter,"referenceWidth",widthTypes,instruction,reference),new int[]{0,0}),"ambiguous width");
        PcodeOp dynamic=new PcodeOp(target,2,PcodeOp.LOAD,new Varnode[]{space,new Varnode(unique.getAddress(3),8)},new Varnode(unique.getAddress(4),8));
        ops[0]=new PcodeOp[]{dynamic};
        check(Arrays.equals((int[])invoke(exporter,"referenceWidth",widthTypes,instruction,reference),new int[]{0,0}),"dynamic width");
        omissionControls(exporter,ram,unique,addresses);
        threadOnlyProductionCatchControl(exporter,ram,addresses);
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
