import java.io.*;
import java.nio.*;
import java.nio.channels.*;
import java.nio.file.*;
import java.nio.file.attribute.*;
import java.security.*;
import java.util.*;
import org.jetbrains.org.objectweb.asm.*;
import org.jetbrains.org.objectweb.asm.tree.*;

/** Offline class DATA only. No product loading, hierarchy lookup or execution authority.
 * The fixed recipes intentionally refuse compiler layouts not described here. Work counts
 * explicit visits in this auditor, not ASM/JDK internals, physical IO or transaction CPU.
 */
public final class SnapshotCapsuleAudit implements Opcodes {
    static final int CLASS=1048576, CP=8192, INSNS=8192, HANDLERS=256, EDGES=131072;
    static final String HOOK="SnapshotCopyHooks", BOUNDARY="decompengine/acp/LinuxBubblewrapBoundary";
    static final String LAUNCH="decompengine/acp/AcpSandboxLaunch", PURPOSE="decompengine/acp/AcpSandboxLaunchPurpose";
    static final String STOP_DESC="(L"+LAUNCH+";Ljava/lang/String;)V";
    static final class Work {
        long visits;
        void take(long n){need(n>=0&&n<=4000000-visits,"explicit proof work bound");visits+=n;}
    }
    static void need(boolean b,String why){if(!b)throw new IllegalArgumentException(why);}
    static String sha(byte[] b)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b));}
    static byte[] capture(Path p,int maximum)throws Exception{
        need(maximum>0,"capture remaining bound");
        var before=Files.readAttributes(p,BasicFileAttributes.class,LinkOption.NOFOLLOW_LINKS);
        need(before.isRegularFile()&&!before.isSymbolicLink()&&before.size()>0&&before.size()<=maximum,"regular bounded input");
        byte[] bytes;
        try(var fd=Files.newByteChannel(p,Set.of(StandardOpenOption.READ,LinkOption.NOFOLLOW_LINKS))){
            need(fd.size()==before.size(),"capture size changed");
            var out=new ByteArrayOutputStream((int)before.size());var page=ByteBuffer.allocate(65536);int total=0;
            for(;;){page.clear();page.limit(Math.min(page.capacity(),maximum-total+1));int n=fd.read(page);need(n!=0,"nonprogress input");if(n<0)break;need(n<=maximum-total,"capture overflow");out.write(page.array(),0,n);total+=n;}
            need(total==before.size()&&fd.size()==total,"capture size drift");bytes=out.toByteArray();
        }
        var after=Files.readAttributes(p,BasicFileAttributes.class,LinkOption.NOFOLLOW_LINKS);
        need(after.isRegularFile()&&Objects.equals(before.fileKey(),after.fileKey())&&before.size()==after.size()&&before.lastModifiedTime().equals(after.lastModifiedTime()),"capture name drift");
        return bytes; // consistency of this capture; not exclusive filesystem ownership or freshness caching
    }
    static final class Cursor {
        final byte[] b; int at;
        Cursor(byte[] b){this.b=b;}
        int u1(){need(at<b.length,"truncated class");return b[at++]&255;}
        int u2(){return(u1()<<8)|u1();}
        long u4(){return((long)u2()<<16)|u2();}
        void skip(long n){need(n>=0&&n<=b.length-at,"truncated attribute");at+=(int)n;}
        int end(long n){need(n>=0&&n<=b.length-at,"attribute size");return at+(int)n;}
    }
    static boolean tag(int[] tags,int i,int... allowed){if(i<=0||i>=tags.length)return false;for(int t:allowed)if(tags[i]==t)return true;return false;}
    static int s4(byte[] b,int i){need(i>=0&&i<=b.length-4,"truncated operand");return ByteBuffer.wrap(b,i,4).getInt();}
    static int branch(int pc,int offset){long target=(long)pc+offset;need(target>=0&&target<=65535,"branch arithmetic range");return(int)target;}
    static int u2(byte[] b,int i){need(i>=0&&i<=b.length-2,"truncated operand");return((b[i]&255)<<8)|(b[i+1]&255);}
    /** Admission before ClassReader creates its pool/Code nodes. Each switch always advances. */
    static void rawAdmission(byte[] bytes,Work work)throws Exception{
        need(bytes.length>=10&&bytes.length<=CLASS,"class bytes");var c=new Cursor(bytes);
        need(c.u4()==0xcafebabeL,"class magic");c.u2();int major=c.u2();need(major>=45&&major<=70,"class version");
        int count=c.u2();need(count>=1&&count<=CP,"CP before allocation");
        int[] tags=new int[count],a=new int[count],b=new int[count];String[] utf=new String[count];
        for(int i=1;i<count;i++){work.take(1);int t=tags[i]=c.u1();switch(t){
            case 1 -> {int start=c.at;int n=c.u2();c.skip(n);try(var in=new DataInputStream(new ByteArrayInputStream(bytes,start,n+2))){utf[i]=in.readUTF();}}
            case 3,4 -> c.skip(4);
            case 5,6 -> {c.skip(8);need(i+1<count,"wide CP slot");i++;}
            case 7,8,16,19,20 -> a[i]=c.u2();
            case 9,10,11,12,17,18 -> {a[i]=c.u2();b[i]=c.u2();}
            case 15 -> {a[i]=c.u1();b[i]=c.u2();}
            default -> throw new IllegalArgumentException("unsupported CP tag");
        }}
        for(int i=1;i<count;i++){work.take(1);switch(tags[i]){
            case 7,8,16,19,20 -> need(tag(tags,a[i],1),"CP UTF type");
            case 9,10,11 -> need(tag(tags,a[i],7)&&tag(tags,b[i],12),"CP member type");
            case 12 -> need(tag(tags,a[i],1)&&tag(tags,b[i],1),"CP name/type");
            case 17,18 -> need(tag(tags,b[i],12),"CP dynamic name/type");
            case 15 -> {int k=a[i];need(k>=1&&k<=9,"method handle kind");need(k<=4?tag(tags,b[i],9):k==9?tag(tags,b[i],11):k==5||k==8?tag(tags,b[i],10):tag(tags,b[i],10,11),"method handle type");}
            default -> {}
        }}
        c.u2();need(tag(tags,c.u2(),7),"this_class type");int sup=c.u2();need(sup==0||tag(tags,sup,7),"super type");
        int ni=c.u2();for(int i=0;i<ni;i++){work.take(1);need(tag(tags,c.u2(),7),"interface type");}
        for(int group=0;group<2;group++){
            int nm=c.u2();for(int i=0;i<nm;i++){
                work.take(1);c.u2();need(tag(tags,c.u2(),1)&&tag(tags,c.u2(),1),"member name/type");int na=c.u2();boolean code=false;
                for(int j=0;j<na;j++){
                    work.take(1);int name=c.u2();need(tag(tags,name,1),"attribute name");int end=c.end(c.u4());
                    if(group==1&&"Code".equals(utf[name])){
                        need(!code,"duplicate Code");code=true;c.u2();int locals=c.u2();long length=c.u4();need(length>0&&length<=65535,"Code length");int start=c.at;c.skip(length);
                        boolean[] boundary=new boolean[(int)length+1];var jumps=new ArrayList<Integer>();int pc=0,n=0;
                        while(pc<length){work.take(1);need(++n<=INSNS,"instruction bound");boundary[pc]=true;int op=bytes[start+pc]&255,step=1;
                            need(op<=201&&op!=168&&op!=169&&op!=201,"unsupported opcode/subroutine");
                            if(op==170||op==171){int q=pc+1;while((q&3)!=0)q++;need(q<=length-8,"switch header");jumps.add(branch(pc,s4(bytes,start+q)));q+=4;
                                if(op==170){need(q<=length-8,"table header");int lo=s4(bytes,start+q),hi=s4(bytes,start+q+4);q+=8;long entries=(long)hi-lo+1;need(entries>=1&&entries<=EDGES&&entries<=((long)length-q)/4,"table size");for(int k=0;k<entries;k++){work.take(1);jumps.add(branch(pc,s4(bytes,start+q)));q+=4;}}
                                else{int entries=s4(bytes,start+q);q+=4;need(entries>=0&&entries<=EDGES&&entries<=((long)length-q)/8,"lookup size");int previous=0;for(int k=0;k<entries;k++){work.take(1);int key=s4(bytes,start+q);need(k==0||key>previous,"lookup key order");previous=key;jumps.add(branch(pc,s4(bytes,start+q+4)));q+=8;}}
                                step=q-pc;
                            }else if(op==196){need(pc+1<length,"wide opcode");int w=bytes[start+pc+1]&255;need((w>=21&&w<=25)||(w>=54&&w<=58)||w==132,"wide subopcode");step=w==132?6:4;need(pc+step<=length,"wide operand");need(u2(bytes,start+pc+2)<locals,"wide local");}
                            else if(op==16||op==18||op==188||(op>=21&&op<=25)||(op>=54&&op<=58))step=2;
                            else if(op==17||op==19||op==20||op==132||(op>=153&&op<=167)||(op>=178&&op<=184)||op==187||op==189||op==192||op==193||op==198||op==199)step=3;
                            else if(op==197)step=4;else if(op==185||op==186||op==200)step=5;
                            need(step>0&&pc+step<=length,"instruction progress/operand bound");
                            if((op>=153&&op<=167)||op==198||op==199)jumps.add(branch(pc,(short)u2(bytes,start+pc+1)));
                            if(op==200)jumps.add(branch(pc,s4(bytes,start+pc+1)));
                            if((op>=21&&op<=25)||(op>=54&&op<=58)||op==132){int slot=bytes[start+pc+1]&255;need(slot<locals&&(!(op==22||op==24||op==55||op==57)||slot+1<locals),"local operand bound");}
                            if(op==188)need((bytes[start+pc+1]&255)>=4&&(bytes[start+pc+1]&255)<=11,"newarray type");
                            if(op==197)need((bytes[start+pc+3]&255)>0,"array dimensions");
                            if(op==18||op==19||op==20){int cp=op==18?bytes[start+pc+1]&255:u2(bytes,start+pc+1);need(tag(tags,cp,3,4,5,6,7,8,15,16),"LDC type/dynamic unsupported");need(op==20?tag(tags,cp,5,6):!tag(tags,cp,5,6),"LDC category");}
                            if(op>=178&&op<=181)need(tag(tags,u2(bytes,start+pc+1),9),"field operand type");
                            if(op>=182&&op<=185){int cp=u2(bytes,start+pc+1);need(op==185?tag(tags,cp,11):op==182?tag(tags,cp,10):tag(tags,cp,10,11),"invoke operand type");if(op==185)need(bytes[start+pc+3]!=0&&bytes[start+pc+4]==0,"invokeinterface bytes");}
                            if(op==186)need(tag(tags,u2(bytes,start+pc+1),18)&&bytes[start+pc+3]==0&&bytes[start+pc+4]==0,"indy operand");
                            if(op==187||op==189||op==192||op==193||op==197)need(tag(tags,u2(bytes,start+pc+1),7),"type operand");
                            pc+=step;need(jumps.size()<=EDGES,"raw branch bound");
                        }
                        boundary[(int)length]=true;for(int target:jumps){work.take(1);need(target>=0&&target<length&&boundary[target],"branch into operand/outside Code");}
                        int nh=c.u2();need(nh<=HANDLERS,"handler bound before ASM");for(int k=0;k<nh;k++){work.take(1);int from=c.u2(),to=c.u2(),handler=c.u2(),type=c.u2();need(from<to&&to<=length&&handler<length&&boundary[from]&&boundary[to]&&boundary[handler]&&(type==0||tag(tags,type,7)),"handler range/type");}
                        int nested=c.u2();for(int k=0;k<nested;k++){work.take(1);need(tag(tags,c.u2(),1),"Code attribute name");c.skip(c.u4());}
                    }else c.at=end;
                    need(c.at==end,"attribute exact consumption");
                }
            }
        }
        int attrs=c.u2();for(int i=0;i<attrs;i++){work.take(1);need(tag(tags,c.u2(),1),"class attribute name");c.skip(c.u4());}need(c.at==bytes.length,"class trailing bytes");
    }
    static final class Image {
        final byte[] bytes;final ClassNode node;final String digest;
        Image(byte[] bytes,Work work)throws Exception{
            need(bytes.length>=10&&bytes.length<=CLASS,"image size before clone");this.bytes=bytes.clone();rawAdmission(this.bytes,work);digest=sha(this.bytes);node=new ClassNode();new ClassReader(this.bytes).accept(node,0);
            need(node.attrs==null||node.attrs.isEmpty(),"unknown class attribute");var names=new HashSet<String>();
            for(var m:node.methods){work.take(1);need(names.add(m.name+m.desc),"duplicate method");need((m.access&(ACC_NATIVE|ACC_ABSTRACT))!=0||m.instructions.size()>0,"missing body");need(m.attrs==null||m.attrs.isEmpty(),"unknown method attribute");}
        }
    }
    static List<AbstractInsnNode> code(MethodNode m,Work work){return new MethodLayout(m,work).instructions;}
    /** Charged raw-node layout. Labels resolve by bounded, charged identity probes;
     * metadata is included in both layout passes rather than hidden in a forward walk.
     */
    static final class MethodLayout {
        final List<AbstractInsnNode> instructions;
        final AbstractInsnNode[] rawNodes;
        final int[] rawPositions;
        final LabelNode[] labels;
        final int[] targets;
        MethodLayout(MethodNode method,Work work){
            int rawCount=0,instructionCount=0,labelCount=0;
            for(var node=method.instructions.getFirst();node!=null;node=node.getNext()){
                work.take(1);rawCount++;
                if(node.getOpcode()>=0)need(++instructionCount<=INSNS,"instruction count");
                if(node instanceof LabelNode)labelCount++;
            }
            rawNodes=new AbstractInsnNode[rawCount];var raw=rawNodes;
            rawPositions=new int[instructionCount];
            instructions=new ArrayList<AbstractInsnNode>(instructionCount);
            int slots=1;
            while(slots<2L*labelCount){work.take(1);slots*=2;}
            work.take(slots); // Explicit slot initialization reservation, before allocation.
            labels=new LabelNode[slots];targets=new int[slots];int at=0;
            for(var node=method.instructions.getFirst();node!=null;node=node.getNext()){
                work.take(1);need(at<raw.length,"raw layout changed");int position=at;raw[at++]=node;
                if(node.getOpcode()>=0){need(instructions.size()<rawPositions.length,"instruction layout changed");rawPositions[instructions.size()]=position;instructions.add(node);}
            }
            need(at==raw.length&&instructions.size()==instructionCount,"raw layout changed");
            int next=instructionCount,labelAt=0;
            for(int i=raw.length-1;i>=0;i--){
                work.take(1);var node=raw[i];
                if(node.getOpcode()>=0)next--;
                if(node instanceof LabelNode label){
                    put(label,next,work);labelAt++;
                }
            }
            need(next==0&&labelAt==labelCount,"label layout changed");
        }
        void put(LabelNode label,int target,Work work){
            int slot=System.identityHashCode(label)&(labels.length-1);
            for(int probes=0;probes<labels.length;probes++){
                work.take(1);
                if(labels[slot]==null){labels[slot]=label;targets[slot]=target;return;}
                need(labels[slot]!=label,"duplicate label identity");slot=(slot+1)&(labels.length-1);
            }
            throw new IllegalArgumentException("label table full");
        }
        int target(LabelNode label,Work work){
            need(label!=null,"null label");
            int slot=System.identityHashCode(label)&(labels.length-1);
            for(int probes=0;probes<labels.length;probes++){
                work.take(1);if(labels[slot]==label)return targets[slot];
                if(labels[slot]==null)break;slot=(slot+1)&(labels.length-1);
            }
            throw new IllegalArgumentException("unbound label");
        }
    }
    /** One fixed-size primitive scratch row and stamps shared across all CFG rows. */
    static final class EdgeRow {
        final int[] targets,stamps;int epoch,count;
        EdgeRow(int size){targets=new int[size];stamps=new int[size];}
        void begin(int row){epoch=row+1;count=0;}
        void add(int target){
            need(target>=0&&target<stamps.length,"CFG falloff");
            if(stamps[target]!=epoch){stamps[target]=epoch;targets[count++]=target;}
        }
        void normal(int target,Work work){work.take(1);add(target);}
        int[] copy(Work work){work.take(count);return Arrays.copyOf(targets,count);}
    }
    static MethodNode method(ClassNode c,String name,String desc,Work work){MethodNode found=null;for(var m:c.methods){work.take(1);if(m.name.equals(name)&&m.desc.equals(desc)){need(found==null,"ambiguous method");found=m;}}need(found!=null,"missing method "+name);return found;}
    static List<FieldNode> matchingFields(ClassNode owner,java.util.function.Predicate<FieldNode> selected,Work work){
        var result=new ArrayList<FieldNode>();
        for(var field:owner.fields){work.take(1);if(selected.test(field)){work.take(1);result.add(field);}}
        return result;
    }
    static String atom(AbstractInsnNode n,MethodLayout layout,Work work){
        int op=n.getOpcode();String s=Integer.toString(op);
        if(n instanceof VarInsnNode x)s+=" v="+x.var;
        else if(n instanceof IntInsnNode x)s+=" i="+x.operand;
        else if(n instanceof FieldInsnNode x)s+=" f="+x.owner+"#"+x.name+"#"+x.desc;
        else if(n instanceof MethodInsnNode x)s+=" m="+x.owner+"#"+x.name+"#"+x.desc+"#"+x.itf;
        else if(n instanceof TypeInsnNode x)s+=" t="+x.desc;
        else if(n instanceof JumpInsnNode x)s+=" j="+layout.target(x.label,work);
        else if(n instanceof LdcInsnNode x){need(x.cst instanceof String||x.cst instanceof Long||x.cst instanceof Integer,"recipe constant");s+=" c="+x.cst.getClass().getName()+":"+x.cst;}
        else need(n instanceof InsnNode,"unsupported recipe instruction");
        need(n.visibleTypeAnnotations==null&&n.invisibleTypeAnnotations==null,"instruction annotations");return s;
    }
    static String originalConstant(Object value,Work work){
        work.take(1);
        need(value instanceof String||value instanceof Integer||value instanceof Long||value instanceof Float||value instanceof Double||value instanceof Type||value instanceof Handle,"unsupported original constant");
        return String.valueOf(value);
    }
    /** Independently render the captured original operand, never an overlay-selected shape. */
    static String originalShape(AbstractInsnNode node,MethodLayout layout,Work work){
        work.take(1);String text=Integer.toString(node.getOpcode());
        if(node instanceof VarInsnNode n)text+=" V "+n.var;
        else if(node instanceof IntInsnNode n)text+=" I "+n.operand;
        else if(node instanceof TypeInsnNode n)text+=" T "+n.desc;
        else if(node instanceof FieldInsnNode n)text+=" F "+n.owner+" "+n.name+" "+n.desc;
        else if(node instanceof MethodInsnNode n)text+=" M "+n.owner+" "+n.name+" "+n.desc+" "+n.itf;
        else if(node instanceof InvokeDynamicInsnNode n){
            var args=new StringBuilder("[");
            for(int i=0;i<n.bsmArgs.length;i++){work.take(1);if(i!=0)args.append(", ");args.append(originalConstant(n.bsmArgs[i],work));}
            text+=" D "+n.name+" "+n.desc+" "+n.bsm+" "+args.append(']');
        }
        else if(node instanceof JumpInsnNode n)text+=" J "+layout.target(n.label,work);
        else if(node instanceof LdcInsnNode n)text+=" C "+originalConstant(n.cst,work);
        else if(node instanceof IincInsnNode n)text+=" N "+n.var+" "+n.incr;
        else if(node instanceof TableSwitchInsnNode n){
            need((long)n.max-n.min+1==n.labels.size(),"table cardinality");
            var value=new StringBuilder(text).append(" S ").append(n.min).append(' ').append(n.max).append(' ').append(layout.target(n.dflt,work));
            for(var label:n.labels){work.take(1);value.append(' ').append(layout.target(label,work));}text=value.toString();
        }
        else if(node instanceof LookupSwitchInsnNode n){
            need(n.keys.size()==n.labels.size(),"lookup cardinality");var keys=new StringBuilder("[");
            for(int i=0;i<n.keys.size();i++){work.take(1);if(i!=0)keys.append(", ");keys.append(n.keys.get(i));}
            var value=new StringBuilder(text).append(" L ").append(keys.append(']')).append(' ').append(layout.target(n.dflt,work));
            for(var label:n.labels){work.take(1);value.append(' ').append(layout.target(label,work));}text=value.toString();
        }
        else if(node instanceof MultiANewArrayInsnNode n)text+=" A "+n.desc+" "+n.dims;
        else need(node instanceof InsnNode,"unsupported original instruction");
        need(node.visibleTypeAnnotations==null&&node.invisibleTypeAnnotations==null,"original instruction annotations");return text;
    }
    /** Fixed recipe DSL is an audited narrow form, not discovery or compiler fallback. */
    static MethodNode recipe(String body,Work work){
        MethodNode m=new MethodNode();Map<String,LabelNode> labels=new HashMap<>();
        for(String row:body.split("\\|")){work.take(1);String[] x=row.trim().split(" ",2);if(x[0].equals(":")){labels.put(x[1],new LabelNode());}}
        for(String row:body.split("\\|")){
            work.take(1);String[] x=row.trim().split(" ",2);String arg=x.length==2?x[1]:"";int op;
            switch(x[0]){
                case ":" -> m.instructions.add(labels.get(arg));
                case "V" -> {var q=arg.split(" ");m.instructions.add(new VarInsnNode(Integer.parseInt(q[0]),Integer.parseInt(q[1])));}
                case "I" -> {var q=arg.split(" ");m.instructions.add(new IntInsnNode(Integer.parseInt(q[0]),Integer.parseInt(q[1])));}
                case "J" -> {var q=arg.split(" ");need(labels.containsKey(q[1]),"recipe label");m.instructions.add(new JumpInsnNode(Integer.parseInt(q[0]),labels.get(q[1])));}
                case "F" -> {var q=arg.split(" ");m.instructions.add(new FieldInsnNode(Integer.parseInt(q[0]),q[1],q[2],q[3]));}
                case "M" -> {var q=arg.split(" ");m.instructions.add(new MethodInsnNode(Integer.parseInt(q[0]),q[1],q[2],q[3],false));}
                case "T" -> m.instructions.add(new TypeInsnNode(NEW,arg));
                case "S" -> m.instructions.add(new LdcInsnNode(arg));
                case "L" -> m.instructions.add(new LdcInsnNode(Long.parseLong(arg)));
                default -> {op=Integer.parseInt(x[0]);m.instructions.add(new InsnNode(op));}
            }
        }return m;
    }
    static void exact(MethodNode actual,int access,String body,Work work){
        need(actual.access==access&&actual.tryCatchBlocks.isEmpty(),"fixed method flags/handlers");
        var left=new MethodLayout(actual,work);var right=new MethodLayout(recipe(body,work),work);
        var a=left.instructions;var b=right.instructions;need(a.size()==b.size(),"fixed recipe length");
        for(int i=0;i<a.size();i++){work.take(1);need(atom(a.get(i),left,work).equals(atom(b.get(i),right,work)),"fixed operand/guard/CFG recipe "+actual.name+"@"+i);}
        graph(actual,-1,work); // validates actual edges as well as recipe targets
    }
    static final String F="SnapshotCopyHooks", PUT="M 182 java/nio/ByteBuffer putLong (IJ)Ljava/nio/ByteBuffer;|87";
    static final String ACTIVE="F 178 SnapshotCopyHooks enabled Z|J 154 yes|3|172|: yes|M 184 java/lang/Thread currentThread ()Ljava/lang/Thread;|F 178 SnapshotCopyHooks owner Ljava/lang/Thread;|J 165 good|M 184 SnapshotCopyHooks bad ()V|3|172|: good|4|172";
    static final String BAD="4|F 179 SnapshotCopyHooks invalid Z|F 178 SnapshotCopyHooks page Ljava/nio/ByteBuffer;|J 198 end|F 178 SnapshotCopyHooks page Ljava/nio/ByteBuffer;|I 16 24|10|"+PUT+"|: end|177";
    static final String ADD="V 21 0|J 155 bad|V 21 0|I 17 128|J 162 bad|V 22 1|9|148|J 155 bad|V 22 1|L 9223372036854775807|F 178 SnapshotCopyHooks counters [J|V 21 0|47|101|148|J 158 good|: bad|M 184 SnapshotCopyHooks bad ()V|177|: good|F 178 SnapshotCopyHooks counters [J|V 21 0|92|47|V 22 1|97|80|F 178 SnapshotCopyHooks page Ljava/nio/ByteBuffer;|I 17 128|V 21 0|I 16 8|104|96|F 178 SnapshotCopyHooks counters [J|V 21 0|47|"+PUT+"|177";
    static final String EVENT="F 178 SnapshotCopyHooks sequence J|L 9223372036854775807|148|J 154 good|M 184 SnapshotCopyHooks bad ()V|177|: good|I 17 2048|F 178 SnapshotCopyHooks sequence J|L 512|113|136|I 16 24|104|96|V 54 1|F 178 SnapshotCopyHooks page Ljava/nio/ByteBuffer;|V 21 1|F 178 SnapshotCopyHooks sequence J|"+PUT+"|F 178 SnapshotCopyHooks page Ljava/nio/ByteBuffer;|V 21 1|I 16 8|96|V 21 0|133|"+PUT+"|F 178 SnapshotCopyHooks page Ljava/nio/ByteBuffer;|V 21 1|I 16 16|96|M 184 java/lang/System nanoTime ()J|"+PUT+"|F 178 SnapshotCopyHooks page Ljava/nio/ByteBuffer;|I 16 32|F 178 SnapshotCopyHooks sequence J|10|97|92|F 179 SnapshotCopyHooks sequence J|"+PUT+"|177";
    static final String STOP="M 184 SnapshotCopyHooks active ()Z|J 153 bad|F 178 SnapshotCopyHooks invalid Z|J 154 bad|F 178 SnapshotCopyHooks stopped Z|J 154 bad|F 178 SnapshotCopyHooks token Ljava/lang/String;|V 25 1|M 184 java/util/Objects equals (Ljava/lang/Object;Ljava/lang/Object;)Z|J 153 bad|V 25 0|J 198 bad|V 25 0|M 182 decompengine/acp/AcpSandboxLaunch getPurpose ()Ldecompengine/acp/AcpSandboxLaunchPurpose;|F 178 decompengine/acp/AcpSandboxLaunchPurpose OUTER_AGENT Ldecompengine/acp/AcpSandboxLaunchPurpose;|J 165 good|: bad|M 184 SnapshotCopyHooks bad ()V|T SnapshotCopyHooks$InvalidStop|89|M 183 SnapshotCopyHooks$InvalidStop <init> ()V|191|: good|4|F 179 SnapshotCopyHooks stopped Z|I 16 97|10|M 184 SnapshotCopyHooks add (IJ)V|F 178 SnapshotCopyHooks page Ljava/nio/ByteBuffer;|I 16 40|10|"+PUT+"|I 17 300|M 184 SnapshotCopyHooks event (I)V|T SnapshotCopyHooks$Stop|89|M 183 SnapshotCopyHooks$Stop <init> ()V|191";
    static void auditHelpers(Map<String,Image> images,Image launch,Image purpose,Work work){
        Image hooks=images.get(HOOK);need(hooks!=null,"missing Hooks");ClassNode c=hooks.node;
        need(c.name.equals(HOOK)&&(c.access&(ACC_FINAL|ACC_PUBLIC))==(ACC_FINAL|ACC_PUBLIC)&&c.superName.equals("java/lang/Object")&&c.interfaces.isEmpty(),"fixed Hooks class");
        exact(method(c,"active","()Z",work),ACC_PRIVATE|ACC_STATIC,ACTIVE,work);
        exact(method(c,"bad","()V",work),ACC_PRIVATE|ACC_STATIC,BAD,work);
        exact(method(c,"add","(IJ)V",work),ACC_PRIVATE|ACC_STATIC,ADD,work);
        exact(method(c,"event","(I)V",work),ACC_PRIVATE|ACC_STATIC,EVENT,work);
        exact(method(c,"stopBeforeOuterStart",STOP_DESC,work),ACC_PUBLIC|ACC_STATIC,STOP,work);
        // javac uses LDC Integer for capacity65536, handled separately below; no guessed local alias.
        var prepared=recipe("F 178 SnapshotCopyHooks page Ljava/nio/ByteBuffer;|J 199 bad|V 25 0|M 182 java/nio/ByteBuffer capacity ()I|L 65536|J 160 bad|V 25 1|S [0-9a-f]{64}|M 182 java/lang/String matches (Ljava/lang/String;)Z|J 154 good|: bad|T SnapshotCopyHooks$InvalidStop|89|M 183 SnapshotCopyHooks$InvalidStop <init> ()V|191|: good|V 25 0|F 178 java/nio/ByteOrder BIG_ENDIAN Ljava/nio/ByteOrder;|M 182 java/nio/ByteBuffer order (Ljava/nio/ByteOrder;)Ljava/nio/ByteBuffer;|F 179 SnapshotCopyHooks page Ljava/nio/ByteBuffer;|V 25 1|F 179 SnapshotCopyHooks token Ljava/lang/String;|M 184 java/lang/Thread currentThread ()Ljava/lang/Thread;|F 179 SnapshotCopyHooks owner Ljava/lang/Thread;|F 178 SnapshotCopyHooks page Ljava/nio/ByteBuffer;|3|L 5999726335099940913|"+PUT+"|F 178 SnapshotCopyHooks page Ljava/nio/ByteBuffer;|I 16 8|10|"+PUT+"|4|F 179 SnapshotCopyHooks enabled Z|F 178 SnapshotCopyHooks page Ljava/nio/ByteBuffer;|I 16 16|10|"+PUT+"|177",work);
        ((LdcInsnNode)code(prepared,work).get(4)).cst=Integer.valueOf(65536);
        exactNodes(method(c,"prepare","(Ljava/nio/ByteBuffer;Ljava/lang/String;)V",work),ACC_PUBLIC|ACC_STATIC,prepared,work);
        exact(method(c,"<clinit>","()V",work),ACC_STATIC,"I 17 128|I 188 11|F 179 SnapshotCopyHooks counters [J|I 16 32|I 188 11|F 179 SnapshotCopyHooks times [J|I 16 32|I 188 11|F 179 SnapshotCopyHooks starts [J|6|I 188 11|F 179 SnapshotCopyHooks ioStart [J|I 16 32|I 188 10|F 179 SnapshotCopyHooks stack [I|177",work);
        exact(method(c,"<init>","()V",work),ACC_PRIVATE,"V 25 0|M 183 java/lang/Object <init> ()V|177",work);
        exact(method(c,"stopped","()Z",work),ACC_PUBLIC|ACC_STATIC,"F 178 SnapshotCopyHooks stopped Z|J 153 bad|F 178 SnapshotCopyHooks invalid Z|J 154 bad|4|J 167 end|: bad|3|: end|172",work);
        closedHookCalls(c,work);
        // All writers of first-use/identity state are closed, including otherwise unrelated hooks.
        Map<String,String> fields=Map.of("page","Ljava/nio/ByteBuffer;","token","Ljava/lang/String;","owner","Ljava/lang/Thread;","enabled","Z","invalid","Z","stopped","Z");
        for(var e:fields.entrySet()){
            work.take(1);var matches=matchingFields(c,f->f.name.equals(e.getKey()),work);need(matches.size()==1,"unique guard field");var f=matches.get(0);need(f.desc.equals(e.getValue())&&f.access==(ACC_PRIVATE|ACC_STATIC|(Set.of("enabled","invalid","stopped").contains(f.name)?ACC_VOLATILE:0))&&f.value==null,"guard field type/default");
        }
        for(var m:c.methods){work.take(1);for(var n:m.instructions){work.take(1);if(n instanceof FieldInsnNode ref&&ref.owner.equals(HOOK))need(matchingFields(c,f->f.name.equals(ref.name)&&f.desc.equals(ref.desc),work).size()==1,"helper field declaration join");if(n instanceof FieldInsnNode f&&f.getOpcode()==PUTSTATIC&&f.owner.equals(HOOK)&&fields.containsKey(f.name)){
            boolean allowed=m.name.equals("prepare")&&m.desc.equals("(Ljava/nio/ByteBuffer;Ljava/lang/String;)V")&&(Set.of("page","token","owner","enabled").contains(f.name))||m.name.equals("bad")&&m.desc.equals("()V")&&f.name.equals("invalid")||m.name.equals("stopBeforeOuterStart")&&m.desc.equals(STOP_DESC)&&f.name.equals("stopped");
            // finish is checked as a fixed false-store only, never a preparation or clearing capability.
            if(m.name.equals("finish")&&m.desc.equals("(Ljava/nio/file/Path;)V")&&f.name.equals("enabled")){var q=previous(n,work);allowed=q!=null&&q.getOpcode()==ICONST_0;}
            need(allowed,"unproved guard-state writer");
        }}}
        for(String name:List.of("Stop","InvalidStop")){
            work.take(1);
            var image=images.get(HOOK+"$"+name);need(image!=null,"missing fixed exception");var e=image.node;
            need(e.name.equals(HOOK+"$"+name)&&e.superName.equals("java/lang/RuntimeException")&&(e.access&ACC_FINAL)!=0&&e.fields.isEmpty()&&e.interfaces.isEmpty()&&e.methods.size()==1,"fixed exception closure");
            exact(method(e,"<init>","()V",work),ACC_PRIVATE,"V 25 0|S "+(name.equals("Stop")?"SNAPSHOT_COPY_STOP_OBSERVATION":"SNAPSHOT_COPY_STOP_INVALID")+"|1|3|3|M 183 java/lang/RuntimeException <init> (Ljava/lang/String;Ljava/lang/Throwable;ZZ)V|177",work);
        }
        need(launch!=null&&purpose!=null&&launch.node.name.equals(LAUNCH)&&(launch.node.access&ACC_FINAL)!=0&&purpose.node.name.equals(PURPOSE)&&purpose.node.superName.equals("java/lang/Enum")&&(purpose.node.access&(ACC_ENUM|ACC_FINAL))==(ACC_ENUM|ACC_FINAL),"closed final launch/purpose dependency");
        var getter=method(launch.node,"getPurpose","()L"+PURPOSE+";",work);need((getter.access&(ACC_STATIC|ACC_ABSTRACT|ACC_NATIVE))==0&&getter.tryCatchBlocks.isEmpty(),"purpose getter kind");var g=code(getter,work);
        need(g.size()==3&&g.get(0) instanceof VarInsnNode v&&v.getOpcode()==ALOAD&&v.var==0&&g.get(1) instanceof FieldInsnNode f&&f.getOpcode()==GETFIELD&&f.owner.equals(LAUNCH)&&f.desc.equals("L"+PURPOSE+";")&&g.get(2).getOpcode()==ARETURN,"purpose direct field accessor");
        var field=(FieldInsnNode)g.get(1);need(!matchingFields(launch.node,f->f.name.equals(field.name)&&f.desc.equals(field.desc)&&(f.access&(ACC_FINAL|ACC_STATIC))==ACC_FINAL,work).isEmpty(),"purpose final field");
        need(!matchingFields(purpose.node,f->f.name.equals("OUTER_AGENT")&&f.desc.equals("L"+PURPOSE+";")&&(f.access&(ACC_STATIC|ACC_FINAL|ACC_ENUM))==(ACC_STATIC|ACC_FINAL|ACC_ENUM),work).isEmpty(),"purpose enum constant");
        exact(method(purpose.node,"<init>","(Ljava/lang/String;I)V",work),ACC_PRIVATE,"V 25 0|V 25 1|V 21 2|M 183 java/lang/Enum <init> (Ljava/lang/String;I)V|177",work);
        var enumInit=method(purpose.node,"<clinit>","()V",work);var clinit=code(enumInit,work);int writes=0,write=-1;
        for(int i=0;i<clinit.size();i++){work.take(1);if(clinit.get(i) instanceof FieldInsnNode f&&f.owner.equals(PURPOSE)&&f.name.equals("OUTER_AGENT")&&f.getOpcode()==PUTSTATIC){
            writes++;write=i;need(i>=5&&clinit.get(i-5) instanceof TypeInsnNode t&&t.getOpcode()==NEW&&t.desc.equals(PURPOSE)&&clinit.get(i-4).getOpcode()==DUP&&clinit.get(i-3) instanceof LdcInsnNode l&&l.cst.equals("OUTER_AGENT")&&smallInteger(clinit.get(i-2))>=0&&clinit.get(i-1) instanceof MethodInsnNode call&&call.getOpcode()==INVOKESPECIAL&&call.owner.equals(PURPOSE)&&call.name.equals("<init>")&&call.desc.equals("(Ljava/lang/String;I)V"),"actual nonnull enum producer");
        }}
        need(writes==1,"unique enum constant producer");
        for(var n:enumInit.instructions){work.take(1);need(!(n instanceof InvokeDynamicInsnNode),"enum dynamic bootstrap unsupported");if(n instanceof MethodInsnNode call)need(!call.itf&&(call.owner.equals(PURPOSE)&&call.name.equals("<init>")&&call.desc.equals("(Ljava/lang/String;I)V")&&call.getOpcode()==INVOKESPECIAL||call.owner.equals(PURPOSE)&&call.name.equals("$values")&&call.desc.equals("()[L"+PURPOSE+";")&&call.getOpcode()==INVOKESTATIC||call.owner.equals("kotlin/enums/EnumEntriesKt")&&call.name.equals("enumEntries")&&call.desc.equals("([Ljava/lang/Enum;)Lkotlin/enums/EnumEntries;")&&call.getOpcode()==INVOKESTATIC),"enum initializer dispatch unsupported");}
        // No opaque internal $values implementation or loop/always-throw initializer can
        // erase the feasible good state. Unknown enum compiler layouts are refused.
        for(var n:clinit){work.take(1);int op=n.getOpcode();
            if(n instanceof MethodInsnNode call){if(call.owner.equals(PURPOSE)&&call.name.equals("$values"))auditEnumValues(purpose.node,work);}
            else if(n instanceof FieldInsnNode f)need(f.owner.equals(PURPOSE)&&(op==GETSTATIC||op==PUTSTATIC)&&!matchingFields(purpose.node,d->d.name.equals(f.name)&&d.desc.equals(f.desc)&&(d.access&ACC_STATIC)!=0,work).isEmpty(),"enum static field join");
            else if(n instanceof TypeInsnNode t)need(op==NEW&&t.desc.equals(PURPOSE),"enum allocation layout");
            else if(n instanceof LdcInsnNode l)need(l.cst instanceof String||l.cst instanceof Integer,"enum constant layout");
            else if(n instanceof IntInsnNode)need(op==BIPUSH||op==SIPUSH,"enum integer layout");
            else need(n instanceof InsnNode&&(op==DUP||op==RETURN||op>=ICONST_0&&op<=ICONST_5),"enum branching/throw/dispatch layout unsupported");
        }
        var enumEdges=graph(enumInit,-1,work);
        for(int from=0;from<enumEdges.size();from++){work.take(1);for(int to:enumEdges.get(from)){work.take(1);if(to>write-5&&to<=write)need(from==to-1,"enum producer interior entry");}}
        var enumWithoutProducer=reachable(graph(enumInit,write,work),0,work);
        for(int i=0;i<clinit.size();i++){work.take(1);need(!enumWithoutProducer[i]||clinit.get(i).getOpcode()!=RETURN,"enum producer bypass");}
        for(var m:purpose.node.methods){work.take(1);for(var n:m.instructions){work.take(1);if(n instanceof FieldInsnNode f&&f.owner.equals(PURPOSE)&&f.name.equals("OUTER_AGENT")&&f.getOpcode()==PUTSTATIC)need(m==enumInit,"enum constant rewritten");}}
        // Exact recipes contain a feasible good branch AND all seven invalid guards, not just no-return.
        noReturn(method(c,"stopBeforeOuterStart",STOP_DESC,work),work);
    }
    static void pushInteger(InsnList list,int value){if(value>=0&&value<=5)list.add(new InsnNode(ICONST_0+value));else if(value<=127)list.add(new IntInsnNode(BIPUSH,value));else if(value<=32767)list.add(new IntInsnNode(SIPUSH,value));else list.add(new LdcInsnNode(value));}
    static void auditEnumValues(ClassNode c,Work work){
        var constants=matchingFields(c,f->(f.access&ACC_ENUM)!=0,work);MethodNode actual=method(c,"$values","()[L"+PURPOSE+";",work);
        need(constants.size()<=(INSNS-3)/4,"enum values instruction bound before recipe");
        need((actual.access&(ACC_PRIVATE|ACC_STATIC))==(ACC_PRIVATE|ACC_STATIC)&&(actual.access&~(ACC_PRIVATE|ACC_STATIC|ACC_FINAL|ACC_SYNTHETIC))==0,"enum values flags");
        MethodNode expected=new MethodNode();pushInteger(expected.instructions,constants.size());expected.instructions.add(new TypeInsnNode(ANEWARRAY,PURPOSE));
        for(int i=0;i<constants.size();i++){work.take(1);var f=constants.get(i);need(f.desc.equals("L"+PURPOSE+";")&&(f.access&(ACC_STATIC|ACC_FINAL))==(ACC_STATIC|ACC_FINAL),"enum values field");expected.instructions.add(new InsnNode(DUP));pushInteger(expected.instructions,i);expected.instructions.add(new FieldInsnNode(GETSTATIC,PURPOSE,f.name,f.desc));expected.instructions.add(new InsnNode(AASTORE));}
        expected.instructions.add(new InsnNode(ARETURN));exactNodes(actual,actual.access,expected,work);
    }
    static void closedHookCalls(ClassNode c,Work work){
        Map<String,String> signatures=Map.ofEntries(
            Map.entry("<init>","()V"),Map.entry("<clinit>","()V"),Map.entry("prepare","(Ljava/nio/ByteBuffer;Ljava/lang/String;)V"),
            Map.entry("active","()Z"),Map.entry("bad","()V"),Map.entry("add","(IJ)V"),Map.entry("duration","(IJ)V"),Map.entry("event","(I)V"),
            Map.entry("enter","(I)V"),Map.entry("exit","(I)V"),Map.entry("grouped","(IJ)V"),Map.entry("note","(I)V"),Map.entry("ioBegin","(I)V"),
            Map.entry("readResult","(J)V"),Map.entry("writeResult","(JJ)V"),Map.entry("errno","(I)V"),Map.entry("fsyncComplete","()V"),
            Map.entry("copyAllocated","()V"),Map.entry("copyClosed","(Ljava/lang/Throwable;)V"),Map.entry("stopBeforeOuterStart",STOP_DESC),
            Map.entry("finish","(Ljava/nio/file/Path;)V"),Map.entry("stopped","()Z"));
        need(c.methods.size()==signatures.size(),"Hooks method closure");
        Set<String> external=Set.of(
            "java/lang/Object#<init>#()V", "java/lang/Thread#currentThread#()Ljava/lang/Thread;", "java/lang/System#nanoTime#()J",
            "java/util/Objects#equals#(Ljava/lang/Object;Ljava/lang/Object;)Z", "java/lang/String#matches#(Ljava/lang/String;)Z",
            "java/nio/ByteBuffer#capacity#()I", "java/nio/ByteBuffer#order#(Ljava/nio/ByteOrder;)Ljava/nio/ByteBuffer;", "java/nio/ByteBuffer#putLong#(IJ)Ljava/nio/ByteBuffer;",
            "decompengine/acp/AcpSandboxLaunch#getPurpose#()Ldecompengine/acp/AcpSandboxLaunchPurpose;",
            "SnapshotCopyHooks$InvalidStop#<init>#()V", "SnapshotCopyHooks$Stop#<init>#()V",
            "java/util/Properties#<init>#()V", "java/util/Properties#setProperty#(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/Object;",
            "java/util/Properties#store#(Ljava/io/OutputStream;Ljava/lang/String;)V", "java/lang/Boolean#toString#(Z)Ljava/lang/String;",
            "java/lang/Integer#toString#(I)Ljava/lang/String;", "java/lang/Long#toString#(J)Ljava/lang/String;",
            "java/io/ByteArrayOutputStream#<init>#()V", "java/io/ByteArrayOutputStream#size#()I", "java/io/ByteArrayOutputStream#toByteArray#()[B",
            "java/nio/file/Files#write#(Ljava/nio/file/Path;[B[Ljava/nio/file/OpenOption;)Ljava/nio/file/Path;");
        for(var m:c.methods){work.take(1);need(m.desc.equals(signatures.get(m.name)),"unknown Hook method/overload");
            int flags=m.name.equals("<init>")?ACC_PRIVATE:m.name.equals("<clinit>")?ACC_STATIC:ACC_STATIC|(Set.of("active","bad","add","duration","event","grouped").contains(m.name)?ACC_PRIVATE:ACC_PUBLIC);
            need(m.access==flags,"Hook native/abstract/monitor/dispatch flags unsupported");
            for(var n:m.instructions){work.take(1);
                if(n instanceof InvokeDynamicInsnNode d)need(m.name.equals("finish")&&m.desc.equals("(Ljava/nio/file/Path;)V")&&d.name.equals("makeConcatWithConstants")&&d.desc.equals("(I)Ljava/lang/String;")&&d.bsm.getTag()==H_INVOKESTATIC&&d.bsm.getOwner().equals("java/lang/invoke/StringConcatFactory")&&d.bsm.getName().equals("makeConcatWithConstants")&&d.bsm.getDesc().equals("(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/invoke/CallSite;")&&d.bsmArgs.length==1&&(d.bsmArgs[0].equals("counter.\u0001")||d.bsmArgs[0].equals("inclusiveNs.\u0001")),"Hooks dynamic dispatch unsupported");
                if(n instanceof MethodInsnNode call){need(!call.itf,"Hooks interface dispatch unsupported");
                    if(call.owner.equals(HOOK))need(call.getOpcode()==INVOKESTATIC&&call.desc.equals(signatures.get(call.name)),"internal helper dependency");
                    else need(external.contains(call.owner+"#"+call.name+"#"+call.desc),"unproved external helper dependency");
                }
            }
        }
    }
    static int smallInteger(AbstractInsnNode n){int op=n.getOpcode();if(op>=ICONST_0&&op<=ICONST_5)return op-ICONST_0;if(n instanceof IntInsnNode i&&(op==BIPUSH||op==SIPUSH))return i.operand;if(n instanceof LdcInsnNode l&&l.cst instanceof Integer i)return i;throw new IllegalArgumentException("enum ordinal form unsupported");}
    static AbstractInsnNode previous(AbstractInsnNode n,Work work){while(n!=null){work.take(1);n=n.getPrevious();if(n==null||n.getOpcode()>=0)return n;}return null;}
    static void exactNodes(MethodNode a,int flags,MethodNode b,Work work){var left=new MethodLayout(a,work);var right=new MethodLayout(b,work);var x=left.instructions;var y=right.instructions;need(a.access==flags&&a.tryCatchBlocks.isEmpty()&&x.size()==y.size(),"fixed preparation shape");for(int i=0;i<x.size();i++){work.take(1);need(atom(x.get(i),left,work).equals(atom(y.get(i),right,work)),"preparation operands/CFG");}graph(a,-1,work);}
    /** Conservative exception graph: every protected instruction can throw to every handler.
     * No catch-type inference. stopIndex removes ONLY its normal return, never handler edges.
     */
    static List<int[]> graph(MethodNode m,int stopIndex,Work work){
        var layout=new MethodLayout(m,work);var c=layout.instructions;
        need(!c.isEmpty()&&m.tryCatchBlocks.size()<=HANDLERS,"CFG shape");
        int handlers=m.tryCatchBlocks.size();int[] from=new int[handlers],to=new int[handlers],handler=new int[handlers];
        for(int h=0;h<handlers;h++){
            work.take(1);var block=m.tryCatchBlocks.get(h);
            from[h]=layout.target(block.start,work);to[h]=layout.target(block.end,work);handler[h]=layout.target(block.handler,work);
            need(from[h]<to[h]&&to[h]<=c.size()&&handler[h]<c.size(),"handler labels");
        }
        var out=new ArrayList<int[]>(c.size());var next=new EdgeRow(c.size());long edges=0;
        for(int i=0;i<c.size();i++){
            work.take(1);var n=c.get(i);int op=n.getOpcode();next.begin(i);
            if(n instanceof JumpInsnNode j){need(op!=JSR,"subroutine");next.normal(layout.target(j.label,work),work);if(op!=GOTO)next.normal(i+1,work);}
            else if(n instanceof TableSwitchInsnNode s){need((long)s.max-s.min+1==s.labels.size(),"table cardinality");next.normal(layout.target(s.dflt,work),work);for(var l:s.labels){work.take(1);next.normal(layout.target(l,work),work);}}
            else if(n instanceof LookupSwitchInsnNode s){need(s.keys.size()==s.labels.size(),"lookup cardinality");next.normal(layout.target(s.dflt,work),work);for(var l:s.labels){work.take(1);next.normal(layout.target(l,work),work);}}
            else if(op!=ATHROW&&!(op>=IRETURN&&op<=RETURN)&&i!=stopIndex)next.normal(i+1,work);
            // Exactly one debit per handler cell, including uncovered/duplicate cells.
            // Its constant range check and stamp insertion share that debit.
            for(int h=0;h<handlers;h++){work.take(1);if(i>=from[h]&&i<to[h])next.add(handler[h]);}
            edges+=next.count;need(edges<=EDGES,"CFG edge bound");out.add(next.copy(work));
        }return out;
    }
    static boolean[] reachable(List<int[]> edges,int start,Work work){boolean[] seen=new boolean[edges.size()];int[] queue=new int[edges.size()];int at=0,end=0;seen[start]=true;queue[end++]=start;while(at<end){int i=queue[at++];work.take(1);for(int n:edges.get(i)){work.take(1);if(!seen[n]){seen[n]=true;queue[end++]=n;}}}return seen;}
    static void noReturn(MethodNode m,Work work){
        var c=code(m,work);var edges=graph(m,-1,work);var seen=reachable(edges,0,work);int[] degree=new int[c.size()];int reachable=0,throwsSeen=0;
        for(int i=0;i<c.size();i++){work.take(1);if(seen[i]){reachable++;int op=c.get(i).getOpcode();need(!(op>=IRETURN&&op<=RETURN),"reachable return");if(edges.get(i).length==0){need(op==ATHROW,"nonthrow terminal");throwsSeen++;}for(int j:edges.get(i)){work.take(1);degree[j]++;}}}
        int[] queue=new int[c.size()];int at=0,end=0;for(int i=0;i<c.size();i++){work.take(1);if(seen[i]&&degree[i]==0)queue[end++]=i;}int visited=0;
        while(at<end){int i=queue[at++];visited++;work.take(1);for(int j:edges.get(i)){work.take(1);if(--degree[j]==0)queue[end++]=j;}}
        need(visited==reachable&&throwsSeen==2,"loop-only/disconnected/throw terminals");
    }
    static boolean isStart(AbstractInsnNode n){return n instanceof MethodInsnNode m&&m.owner.equals("java/lang/ProcessBuilder")&&m.name.equals("start");}
    static String auditCaller(ClassNode boundary,Work work){
        need(boundary.name.equals(BOUNDARY)&&(boundary.access&ACC_FINAL)!=0,"final outer owner");MethodNode selected=null;int starts=0,stops=0;String token=null;
        for(var m:boundary.methods){work.take(1);var c=code(m,work);for(int i=0;i<c.size();i++){
            work.take(1);var n=c.get(i);
            { // Entire declared outer-owner class, including non-launch-named fallback methods.
                need(!(n instanceof InvokeDynamicInsnNode),"caller dynamic dispatch unsupported");
                if(n instanceof MethodInsnNode call)need(!call.owner.startsWith("java/lang/reflect/")&&!call.owner.startsWith("java/lang/invoke/")&&!call.owner.equals("java/lang/Runtime")&&!call.owner.equals("java/lang/ProcessImpl")&&!call.owner.equals("java/lang/Class"),"caller reflective/alternate launch unsupported");
            }
            if(n instanceof MethodInsnNode call&&call.owner.equals(HOOK)&&call.name.equals("stopBeforeOuterStart")){
                stops++;need(m.name.equals("launch")&&(m.access&ACC_STATIC)==0&&Type.getArgumentTypes(m.desc).length>0&&Type.getArgumentTypes(m.desc)[0].getDescriptor().equals("L"+LAUNCH+";")&&call.getOpcode()==INVOKESTATIC&&!call.itf&&call.desc.equals(STOP_DESC),"closed caller/stop ABI");
                need(i>=2&&c.get(i-2) instanceof VarInsnNode v&&v.getOpcode()==ALOAD&&v.var==1&&c.get(i-1) instanceof LdcInsnNode l&&l.cst instanceof String t&&t.matches("[0-9a-f]{64}"),"actual launch local and literal token");token=(String)((LdcInsnNode)c.get(i-1)).cst;selected=m;
            }
            if(isStart(n)){starts++;need(m.name.equals("launch")&&n instanceof MethodInsnNode call&&call.getOpcode()==INVOKEVIRTUAL&&!call.itf&&call.desc.equals("()Ljava/lang/Process;"),"default/fallback start");}
        }}
        need(selected!=null&&starts==1&&stops==1,"one stopped outer start");var c=code(selected,work);int stop=-1,start=-1;
        for(int i=0;i<c.size();i++){work.take(1);if(c.get(i) instanceof MethodInsnNode m&&m.owner.equals(HOOK)&&m.name.equals("stopBeforeOuterStart"))stop=i;if(isStart(c.get(i)))start=i;}
        need(start>=0&&stop>=0,"selected outer start");
        for(var n:c){work.take(1);if(n instanceof VarInsnNode v&&v.getOpcode()>=ISTORE&&v.getOpcode()<=ASTORE)need(v.var!=1,"launch parameter overwritten");if(n instanceof IincInsnNode v)need(v.var!=1,"launch parameter incremented");}
        // Validate operands via the actual predecessor graph, including branch/switch/handler interior entries.
        var ordinary=graph(selected,-1,work);for(int from=0;from<ordinary.size();from++){work.take(1);for(int to:ordinary.get(from)){work.take(1);if(to==stop-1||to==stop)need(from==to-1,"interior stop operand bypass");}}
        var before=reachable(ordinary,0,work);need(before[stop],"disconnected mandatory stop");
        var guarded=reachable(graph(selected,stop,work),0,work);need(!guarded[start],"normal/exception outer start bypass");
        // No normal return from the fixed helper; exceptional edges remain conservative above.
        return token; // OBSERVED binding data only; seven arguments provide no independently approved token.
    }
    static final Set<String> OVERLAY_OWNERS=Set.of(BOUNDARY,BOUNDARY+"$Companion","decompengine/acp/PinnedReadOnlyMount$Companion","decompengine/acp/LinuxBubblewrapBoundaryKt","decompengine/acp/RuntimePrivateControlScope","decompengine/acp/LinuxFilesystemSyscalls");
    static record OverlayRule(String kind,String owner,String name,String desc,String[] extra){}
    static record ParsedAllowlist(Map<String,String> classes,List<OverlayRule> rules,String[] stop){}
    /** Preserve producer CLASS and rule order; never infer a recipe from overlay contents. */
    static ParsedAllowlist parseAllowlist(byte[] allowlist,Map<String,Image> originals,Map<String,Image> overlays,Work work){
        need(allowlist.length<=65536,"allowlist byte bound");
        String text=new String(allowlist,java.nio.charset.StandardCharsets.UTF_8);
        need(Arrays.equals(allowlist,text.getBytes(java.nio.charset.StandardCharsets.UTF_8)),"strict allowlist UTF8");
        Map<String,String> classes=new LinkedHashMap<>();Set<String> rows=new HashSet<>();
        var rules=new ArrayList<OverlayRule>();String[] stop=null;
        for(String row:text.split("\r\n|[\r\n]")){
            work.take(1);if(row.isBlank()||row.startsWith("#"))continue;
            need(rows.add(row),"duplicate allowlist row");String[] f=row.split("\t",-1);
            if(f[0].equals("CLASS")){
                need(f.length==3&&OVERLAY_OWNERS.contains(f[1])&&originals.containsKey(f[1])&&f[2].equals(originals.get(f[1]).digest)&&classes.putIfAbsent(f[1],f[2])==null,"captured original/class pin join");
            }else{
                need(rules.size()<128&&(f[0].equals("TIME")&&f.length==5||f[0].equals("SITE")&&f.length==9),"allowlist rule bounds/schema");
                need(OVERLAY_OWNERS.contains(f[1]),"allowlist rule owner");
                work.take(f.length-4);rules.add(new OverlayRule(f[0],f[1],f[2],f[3],Arrays.copyOfRange(f,4,f.length)));
                if(f[0].equals("SITE")&&f[6].equals("STOP")){need(stop==null,"multiple declared stops");stop=f;}
            }
        }
        need(classes.keySet().equals(OVERLAY_OWNERS)&&overlays.keySet().equals(OVERLAY_OWNERS)&&stop!=null,"exact original/overlay six and STOP declaration");
        work.take(rules.size());return new ParsedAllowlist(Collections.unmodifiableMap(classes),List.copyOf(rules),stop);
    }
    static void declaredStop(byte[] allowlist,Map<String,Image> originals,Map<String,Image> overlays,Work work){declaredStop(parseAllowlist(allowlist,originals,overlays,work),originals,overlays,work);}
    static boolean matches(OverlayRule rule,String owner,MethodNode method){return rule.owner().equals(owner)&&rule.name().equals(method.name)&&rule.desc().equals(method.desc);}
    static int observedBlocks(Map<String,Image> overlays,Work work){
        int begin=0,end=0;
        for(var image:overlays.values()){
            work.take(1);
            for(var method:image.node.methods){
                work.take(1);
                for(var node:method.instructions){
                    work.take(1);
                    if(node instanceof LdcInsnNode constant&&constant.cst instanceof String text&&text.startsWith("SCOPY001/")){
                        if(text.endsWith("/BEGIN"))begin++;
                        else if(text.endsWith("/END"))end++;
                        else throw new IllegalArgumentException("unpaired marker");
                    }
                }
            }
        }
        need(begin==end,"marker population mismatch");return begin;
    }
    static int countedBlock(int count,int observed,Work work){work.take(1);need(count<observed,"expected blocks exceed observed population");return count+1;}
    /** Count declared records before allocating expected block bodies or gap lists. */
    static int expectedBlocks(ParsedAllowlist allowlist,Map<String,Image> originals,int observed,Work work){
        work.take(allowlist.rules().size());boolean[] used=new boolean[allowlist.rules().size()];int count=0;
        for(String owner:allowlist.classes().keySet()){
            work.take(1);
            for(var method:originals.get(owner).node.methods){
                work.take(1);boolean timer=false;
                for(int i=0;i<allowlist.rules().size();i++){
                    work.take(1);var rule=allowlist.rules().get(i);if(!matches(rule,owner,method))continue;
                    need(!used[i],"duplicate method rule");used[i]=true;
                    if(rule.kind().equals("TIME")){need(!timer,"duplicate timer rule");timer=true;}
                    else count=countedBlock(count,observed,work);
                }
                for(var node:method.instructions){
                    work.take(1);
                    if(node instanceof LdcInsnNode constant&&constant.cst instanceof String text)need(!text.startsWith("SCOPY001/"),"original marker collision");
                }
                if(timer){
                    need((method.access&(ACC_NATIVE|ACC_ABSTRACT))==0&&!method.name.startsWith("<"),"timer method");
                    count=countedBlock(count,observed,work);int returns=0;
                    for(var node:method.instructions){work.take(1);int opcode=node.getOpcode();if(opcode>=IRETURN&&opcode<=RETURN){count=countedBlock(count,observed,work);returns++;}}
                    need(returns>0,"normal return required");
                }
            }
        }
        for(boolean present:used){work.take(1);need(present,"unused/missing rule");}
        need(count==observed,"expected/observed block coverage mismatch");return count;
    }
    static record ExpectedBlock(String key,List<AbstractInsnNode> nodes){}
    static final class MethodExpectation {
        final MethodNode original;final MethodLayout layout;
        final List<List<ExpectedBlock>> gaps;
        MethodExpectation(MethodNode original,Work work){
            this.original=original;layout=new MethodLayout(original,work);
            work.take((long)layout.rawNodes.length+1);gaps=new ArrayList<>(layout.rawNodes.length+1);
            for(int i=0;i<=layout.rawNodes.length;i++)gaps.add(null);
        }
        void insert(int gap,ExpectedBlock block,boolean first,Work work){
            work.take(1);need(gap>=0&&gap<gaps.size(),"expected raw gap");
            var blocks=gaps.get(gap);
            if(blocks==null){blocks=new ArrayList<>();gaps.set(gap,blocks);}
            if(first){work.take(blocks.size());blocks.add(0,block);}else blocks.add(block);
        }
    }
    static List<AbstractInsnNode> integerCall(String name,int value,Work work){
        work.take(2);return List.of(new LdcInsnNode(value),new MethodInsnNode(INVOKESTATIC,HOOK,name,"(I)V",false));
    }
    static List<AbstractInsnNode> emptyCall(String name,Work work){work.take(1);return List.of(new MethodInsnNode(INVOKESTATIC,HOOK,name,"()V",false));}
    static void longLocal(int slot,MethodNode method){need(slot>=0&&(long)slot+1<method.maxLocals,"declared long local range");}
    static List<AbstractInsnNode> siteBody(OverlayRule rule,MethodExpectation expected,int ordinal,String token,Work work){
        String[] extra=rule.extra();var code=expected.layout.instructions;
        need(ordinal>=0&&ordinal<code.size(),"site index");var node=code.get(ordinal);
        need(originalShape(node,expected.layout,work).equals(extra[1]),"site shape mismatch");
        String mode=extra[2],placement=extra[4];need(placement.equals("BEFORE")||placement.equals("AFTER"),"placement");
        String[] words=extra[3].split(",",-1);need(words.length==(mode.equals("WRITE")?3:1),"site value arity");
        int value=Integer.parseInt(words[0]);
        switch(mode){
            case "NOTE" -> {need(value>=0&&value<128,"note counter range");return integerCall("note",value,work);}
            case "IOSTART" -> {need(value>=0&&value<3,"IO lane range");return integerCall("ioBegin",value,work);}
            case "PHASEENTER","PHASEEXIT" -> {
                need(node instanceof MethodInsnNode&&value>=4&&value<=8&&placement.equals(mode.equals("PHASEENTER")?"BEFORE":"AFTER"),"phase call placement");
                return integerCall(mode.equals("PHASEENTER")?"enter":"exit",value,work);
            }
            case "ERRNO" -> {
                need(node instanceof VarInsnNode store&&store.getOpcode()==ISTORE&&store.var==value&&placement.equals("AFTER"),"captured errno store");
                work.take(2);return List.of(new VarInsnNode(ILOAD,value),new MethodInsnNode(INVOKESTATIC,HOOK,"errno","(I)V",false));
            }
            case "READ","WRITE" -> {
                need(node instanceof VarInsnNode store&&store.getOpcode()==LSTORE&&store.var==value&&placement.equals("AFTER"),"safe long result store");longLocal(value,expected.original);
                if(mode.equals("READ")){work.take(2);return List.of(new VarInsnNode(LLOAD,value),new MethodInsnNode(INVOKESTATIC,HOOK,"readResult","(J)V",false));}
                int count=Integer.parseInt(words[1]),offset=Integer.parseInt(words[2]);longLocal(count,expected.original);longLocal(offset,expected.original);
                work.take(5);return List.of(new VarInsnNode(LLOAD,value),new VarInsnNode(LLOAD,count),new VarInsnNode(LLOAD,offset),new InsnNode(LSUB),new MethodInsnNode(INVOKESTATIC,HOOK,"writeResult","(JJ)V",false));
            }
            case "FSYNCEND" -> {return emptyCall("fsyncComplete",work);}
            case "ALLOC" -> {need(node instanceof VarInsnNode store&&store.getOpcode()==ASTORE&&placement.equals("AFTER"),"allocation completion store");return emptyCall("copyAllocated",work);}
            case "CLOSE" -> {
                need(node instanceof MethodInsnNode call&&call.getOpcode()==INVOKESTATIC&&!call.itf&&call.name.equals("closeFinally")&&Set.of("kotlin/jdk7/AutoCloseableKt","kotlin/AutoCloseableKt","kotlin/io/CloseableKt").contains(call.owner)&&Set.of("(Ljava/lang/AutoCloseable;Ljava/lang/Throwable;)V","(Ljava/io/Closeable;Ljava/lang/Throwable;)V").contains(call.desc)&&placement.equals("AFTER"),"actual close helper completion");
                need(ordinal>=2&&code.get(ordinal-2) instanceof VarInsnNode resource&&resource.getOpcode()==ALOAD&&code.get(ordinal-1) instanceof VarInsnNode primary&&primary.getOpcode()==ALOAD&&primary.var==value,"original close resource and primary operands");
                work.take(2);return List.of(new VarInsnNode(ALOAD,value),new MethodInsnNode(INVOKESTATIC,HOOK,"copyClosed","(Ljava/lang/Throwable;)V",false));
            }
            case "STOP" -> {
                var method=expected.original;var arguments=Type.getArgumentTypes(method.desc);
                need(rule.owner().equals(BOUNDARY)&&method.name.equals("launch")&&(method.access&ACC_STATIC)==0&&value==1&&arguments.length>0&&arguments[0].getDescriptor().equals("L"+LAUNCH+";")&&node instanceof MethodInsnNode call&&call.getOpcode()==INVOKEVIRTUAL&&!call.itf&&call.owner.equals("java/lang/ProcessBuilder")&&call.name.equals("start")&&call.desc.equals("()Ljava/lang/Process;")&&placement.equals("BEFORE"),"exact mandatory stop site");
                int starts=0;for(var instruction:code){work.take(1);if(isStart(instruction))starts++;}need(starts==1,"unique original start");need(token.matches("[0-9a-f]{64}"),"observed stop token");
                work.take(3);return List.of(new VarInsnNode(ALOAD,1),new LdcInsnNode(token),new MethodInsnNode(INVOKESTATIC,HOOK,"stopBeforeOuterStart",STOP_DESC,false));
            }
            default -> throw new IllegalArgumentException("unsupported mode");
        }
    }
    static ExpectedBlock expectedBlock(int serial,String label,List<AbstractInsnNode> body,Work work){
        String key="SCOPY001/"+serial+"/"+label;work.take((long)body.size()+4);
        var nodes=new ArrayList<AbstractInsnNode>(body.size()+4);nodes.add(new LdcInsnNode(key+"/BEGIN"));nodes.add(new InsnNode(POP));
        for(var node:body){work.take(1);nodes.add(node);}nodes.add(new LdcInsnNode(key+"/END"));nodes.add(new InsnNode(POP));
        return new ExpectedBlock(key,List.copyOf(nodes));
    }
    static Map<String,Map<String,MethodExpectation>> expectedEmission(ParsedAllowlist allowlist,Map<String,Image> originals,int observed,String token,Work work){
        int count=expectedBlocks(allowlist,originals,observed,work),serial=0;
        Map<String,Map<String,MethodExpectation>> result=new LinkedHashMap<>();
        for(String owner:allowlist.classes().keySet()){
            work.take(1);Map<String,MethodExpectation> methods=new LinkedHashMap<>();result.put(owner,methods);
            for(var method:originals.get(owner).node.methods){
                work.take(1);var expected=new MethodExpectation(method,work);methods.put(method.name+method.desc,expected);Integer timer=null;
                for(var rule:allowlist.rules()){
                    work.take(1);if(!matches(rule,owner,method))continue;
                    if(rule.kind().equals("TIME")){need(timer==null,"duplicate timer rule");timer=Integer.valueOf(rule.extra()[0]);need(timer>=0&&timer<32,"timer range");continue;}
                    int ordinal=Integer.parseInt(rule.extra()[0]);var body=siteBody(rule,expected,ordinal,token,work);
                    var block=expectedBlock(serial++,owner+"/"+method.name+"/"+ordinal+"/"+rule.extra()[2],body,work);
                    boolean after=rule.extra()[4].equals("AFTER");expected.insert(expected.layout.rawPositions[ordinal]+(after?1:0),block,after,work);
                }
                if(timer!=null){
                    expected.insert(0,expectedBlock(serial++,owner+"/"+method.name+"/ENTER",integerCall("enter",timer,work),work),true,work);
                    var code=expected.layout.instructions;
                    for(int i=0;i<code.size();i++){work.take(1);int opcode=code.get(i).getOpcode();if(opcode>=IRETURN&&opcode<=RETURN)expected.insert(expected.layout.rawPositions[i],expectedBlock(serial++,owner+"/"+method.name+"/RETURN",integerCall("exit",timer,work),work),false,work);}
                }
            }
        }
        need(serial==count,"expected emission population drift");return result;
    }
    static void declaredStop(ParsedAllowlist allowlist,Map<String,Image> originals,Map<String,Image> overlays,Work work){
        String[] stop=allowlist.stop();
        need(stop[1].equals(BOUNDARY)&&stop[2].equals("launch")&&stop[7].equals("1")&&stop[8].equals("BEFORE")&&stop[4].matches("0|[1-9][0-9]{0,4}"),"STOP scope/local/ordinal");
        var original=method(originals.get(BOUNDARY).node,stop[2],stop[3],work);var code=code(original,work);int ordinal=Integer.parseInt(stop[4]);need(ordinal<code.size()&&isStart(code.get(ordinal))&&stop[5].equals("182 M java/lang/ProcessBuilder start ()Ljava/lang/Process; false"),"original declared start shape/ordinal");
        MethodNode caller=method(overlays.get(BOUNDARY).node,stop[2],stop[3],work);var c=code(caller,work);int marked=0;
        String suffix="/"+BOUNDARY+"/launch/"+ordinal+"/STOP/BEGIN";
        for(int i=0;i<c.size();i++){work.take(1);if(c.get(i) instanceof MethodInsnNode call&&call.owner.equals(HOOK)&&call.name.equals("stopBeforeOuterStart")){
            need(i>=4&&c.get(i-4) instanceof LdcInsnNode begin&&begin.cst instanceof String text&&text.startsWith("SCOPY001/")&&text.endsWith(suffix)&&c.get(i-3).getOpcode()==POP,"actual STOP block/declaration join");marked++;
        }}
        need(marked==1,"declared stop missing/disconnected");
    }
    static int remainingCombined(long used){need(used>=0&&used<CLASS,"combined helper/overlay admission exhausted");return(int)(CLASS-used);}
    static Map<String,Image> directory(Path root,Work work,long[] combined)throws Exception{
        need(Files.isDirectory(root,LinkOption.NOFOLLOW_LINKS)&&!Files.isSymbolicLink(root),"class root");Map<String,Image> out=new TreeMap<>();
        try(var stream=Files.walk(root)){for(Path p:(Iterable<Path>)stream::iterator){work.take(1);need(!Files.isSymbolicLink(p),"class tree symlink");if(Files.isDirectory(p,LinkOption.NOFOLLOW_LINKS))continue;String relative=root.relativize(p).toString().replace(java.io.File.separatorChar,'/');need(relative.endsWith(".class"),"nonclass output");byte[] bytes=capture(p,remainingCombined(combined[0]));combined[0]+=bytes.length;var image=new Image(bytes,work);String name=relative.substring(0,relative.length()-6);need(name.equals(image.node.name)&&out.put(name,image)==null,"class name/path/duplicate");}}
        return out;
    }
    static void helperClosure(Map<String,Image> images,Work work){
        Set<String> roots=Set.of("SnapshotCopyEntry","SnapshotCopyHooks","SnapshotOverlayBuilder","SnapshotCapsuleAudit");need(images.keySet().containsAll(roots),"missing helper root");
        for(var e:images.entrySet()){
            work.take(1);need(e.getKey().equals(e.getValue().node.name),"helper key/this_class join");String name=e.getKey(),root=name.contains("$")?name.substring(0,name.indexOf('$')):name;need(roots.contains(root),"unexpected helper/fixture output");
            if(!name.equals(root)){ClassNode child=e.getValue().node,parent=images.get(root).node;need(root.equals(child.nestHostClass)&&parent.nestMembers!=null&&memberPresent(parent.nestMembers,name,work),"actual emitted nest closure");}
            ClassReader reader=new ClassReader(e.getValue().bytes);char[] buffer=new char[reader.getMaxStringLength()];
            for(int i=1;i<reader.getItemCount();i++){work.take(1);int offset=reader.getItem(i);if(offset==0)continue;if(reader.readByte(offset-1)==7){String ref=reader.readUTF8(offset,buffer);if(ref!=null&&helperReference(roots,ref,work))need(images.containsKey(ref),"missing helper CP dependency");}}
            if(e.getValue().node.nestMembers!=null)for(String member:e.getValue().node.nestMembers){work.take(1);need(images.containsKey(member)&&root.equals(images.get(member).node.nestHostClass),"missing/foreign nest member");}
        }
    }
    static boolean memberPresent(List<String> members,String expected,Work work){for(String member:members){work.take(1);if(member.equals(expected))return true;}return false;}
    static boolean helperReference(Set<String> roots,String reference,Work work){for(String root:roots){work.take(1);if(reference.equals(root)||reference.startsWith(root+"$"))return true;}return false;}
    static record MethodRemoval(MethodNode method,int originalStack,List<AbstractInsnNode> nodes){}
    static record VerifiedOverlay(Image original,ClassNode stripped,List<MethodRemoval> removals){}
    static boolean marker(AbstractInsnNode node){return node instanceof LdcInsnNode constant&&constant.cst instanceof String text&&text.startsWith("SCOPY001/");}
    /** Validate every exact block and raw metadata gap without erasing any instruction. */
    static VerifiedOverlay verifyEmission(Image original,Image transformed,Map<String,MethodExpectation> expected,Work work){
        ClassNode copy=new ClassNode();new ClassReader(transformed.bytes).accept(copy,0);
        need(original.node.name.equals(copy.name)&&original.node.methods.size()==copy.methods.size(),"overlay original join");
        var removals=new ArrayList<MethodRemoval>();
        for(var method:copy.methods){
            work.take(1);var selected=expected.get(method.name+method.desc);need(selected!=null,"overlay method join");var old=selected.original;
            need(method.maxLocals==old.maxLocals&&((old.access&(ACC_NATIVE|ACC_ABSTRACT))!=0?method.maxStack==old.maxStack:old.maxStack<=65527&&method.maxStack==old.maxStack+8),"overlay stack/local scope");
            var remove=new ArrayList<AbstractInsnNode>();var node=method.instructions.getFirst();
            for(int gap=0;gap<=selected.layout.rawNodes.length;gap++){
                work.take(1);var blocks=selected.gaps.get(gap);
                if(blocks!=null)for(var block:blocks){
                    work.take(1);
                    for(var wanted:block.nodes()){
                        work.take(1);need(node!=null&&node.getClass()==wanted.getClass(),"exact inserted recipe");
                        need(atom(node,selected.layout,work).equals(atom(wanted,selected.layout,work)),"exact inserted operand/site/order");
                        remove.add(node);node=node.getNext();
                    }
                }
                if(gap<selected.layout.rawNodes.length){
                    need(node!=null&&!marker(node)&&node.getType()==selected.layout.rawNodes[gap].getType(),"original raw metadata gap or undeclared marker");
                    node=node.getNext();
                }
            }
            need(node==null,"extra overlay raw nodes");removals.add(new MethodRemoval(method,old.maxStack,remove));
        }
        return new VerifiedOverlay(original,copy,removals);
    }
    /** Only a globally validated emission plan can authorize erasure for equality checking. */
    static void stripEqual(Map<String,Image> originals,Map<String,Image> overlays,ParsedAllowlist allowlist,String token,Work work){
        int observed=observedBlocks(overlays,work);
        var expected=expectedEmission(allowlist,originals,observed,token,work);var verified=new ArrayList<VerifiedOverlay>();
        for(var entry:overlays.entrySet()){
            work.take(1);need(originals.containsKey(entry.getKey())&&expected.containsKey(entry.getKey()),"overlay absent from original/declared inventory");
            verified.add(verifyEmission(originals.get(entry.getKey()),entry.getValue(),expected.get(entry.getKey()),work));
        }
        // Every class/block/operand/anchor/order has passed. Nothing above mutates a copy.
        for(var image:verified){
            work.take(1);
            for(var removal:image.removals()){
                work.take(1);for(var node:removal.nodes()){work.take(1);removal.method().instructions.remove(node);}
                removal.method().maxStack=removal.originalStack();
            }
            ClassWriter a=new ClassWriter(0),b=new ClassWriter(0);image.original().node.accept(a);image.stripped().accept(b);
            need(Arrays.equals(a.toByteArray(),b.toByteArray()),"independent original instructions/CFG/handlers/frames/metadata equality");
        }
    }
    public static void main(String[] args)throws Exception{
        need(args.length==7,"audit args");Path helpers=Path.of(args[0]),overlay=Path.of(args[1]),origins=Path.of(args[2]),transform=Path.of(args[3]),receipt=Path.of(args[4]),allowlist=Path.of(args[5]),originalClasses=Path.of(args[6]);Work work=new Work();
        byte[] transformBytes=capture(transform,65536),allowlistBytes=capture(allowlist,65536);String report=new String(transformBytes,java.nio.charset.StandardCharsets.UTF_8);
        need(report.contains("originalInstructionsCfgHandlersFramesMetadataEqual=true\n")&&report.contains("allowlistSha256="+sha(allowlistBytes)+"\n"),"separate transform report binding prerequisite");
        long[] combined={0};var helperImages=directory(helpers,work,combined);var overlays=directory(overlay,work,combined);helperClosure(helperImages,work);
        Map<String,Image> originals=new HashMap<>();Set<String> named=new HashSet<>();StringBuilder pins=new StringBuilder();
        String text=new String(capture(origins,65536),java.nio.charset.StandardCharsets.UTF_8);
        for(String row:text.split("\n")){
            work.take(1);String[] fields=row.split("\t",-1);need(fields.length==2&&named.add(fields[0])&&named.size()<=32&&fields[0].matches("[A-Za-z_$][A-Za-z0-9_$.]*"),"origin schema/name bound");Path origin=Path.of(fields[1]);need(origin.isAbsolute(),"absolute origin");String member=fields[0].replace('.','/')+".class";
            if(fields[0].startsWith("decompengine.acp.")){
                Image original=new Image(capture(originalClasses.resolve(member),CLASS),work);need(original.node.name.equals(member.substring(0,member.length()-6)),"original this_class");originals.put(original.node.name,original);
                if(origin.equals(overlay)){need(overlays.containsKey(original.node.name),"missing overlay origin");}
                else{
                    byte[] bytes;if(Files.isDirectory(origin,LinkOption.NOFOLLOW_LINKS))bytes=capture(origin.resolve(member),CLASS);
                    else{need(Files.isRegularFile(origin,LinkOption.NOFOLLOW_LINKS)&&!Files.isSymbolicLink(origin),"regular runtime jar");try(var jar=new java.util.jar.JarFile(origin.toFile(),false)){need(!jar.isMultiRelease(),"multi-release origin unsupported");var entry=jar.getJarEntry(member);need(entry!=null&&!entry.isDirectory()&&entry.getSize()>0&&entry.getSize()<=CLASS,"jar class size");try(var in=jar.getInputStream(entry)){bytes=in.readNBytes(CLASS+1);need(bytes.length==entry.getSize()&&bytes.length<=CLASS,"jar capture exact");}}}
                    need(Arrays.equals(original.bytes,bytes),"runtime original byte origin join");
                }
            }else{Image image=helperImages.get(fields[0]);need(image!=null&&origin.equals(helpers),"helper origin shadow/unknown");}
        }
        need(named.containsAll(Set.of("SnapshotCopyEntry","SnapshotCopyHooks","decompengine.acp.LinuxBubblewrapBoundary","decompengine.acp.LinuxFilesystemSyscalls","decompengine.acp.RuntimePrivateControlScope","decompengine.acp.PinnedReadOnlyMount$Companion","decompengine.acp.LinuxBubblewrapBoundaryKt","decompengine.acp.AcpHarnessFactory","decompengine.acp.AcpAgentHarness","decompengine.acp.LinuxDescriptor","decompengine.acp.LinuxBubblewrapBoundary$Companion",LAUNCH.replace('/','.'),PURPOSE.replace('/','.'))),"critical original/operand dependency inventory missing");
        var parsedAllowlist=parseAllowlist(allowlistBytes,originals,overlays,work);
        declaredStop(parsedAllowlist,originals,overlays,work);
        auditHelpers(helperImages,originals.get(LAUNCH),originals.get(PURPOSE),work);need(overlays.containsKey(BOUNDARY),"outer overlay missing");String token=auditCaller(overlays.get(BOUNDARY).node,work);
        stripEqual(originals,overlays,parsedAllowlist,token,work);
        for(var e:helperImages.entrySet()){work.take(1);pins.append(e.getKey()).append('=').append(e.getValue().digest).append('\n');}
        Files.writeString(receipt,"schema=snapshot-stop-capsule-audit-v1\nqualified=false\nmandatoryStop=true\nhelperClosure=true\ncombinedBytes="+combined[0]+"\nexplicitProofVisits="+work.visits+"\nobservedStopTokenSha256="+sha(token.getBytes(java.nio.charset.StandardCharsets.US_ASCII))+"\nexpectedTokenAuthority=false\n"+pins,StandardOpenOption.CREATE_NEW);
    }
}
