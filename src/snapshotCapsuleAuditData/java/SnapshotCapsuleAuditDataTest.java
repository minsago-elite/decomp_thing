import java.io.*;
import java.util.*;
import java.util.function.*;
import org.jetbrains.org.objectweb.asm.*;
import org.jetbrains.org.objectweb.asm.tree.*;

/** Prospective inert Java class-DATA controls. NEVER defineClass/Class.forName/load product
 * classes. Compile/run this fixture only in a separate future fixture output directory,
 * never in the production helper classpath or origin inventory. All controls UNRUN.
 */
public final class SnapshotCapsuleAuditDataTest implements Opcodes {
    static final String H="SnapshotCopyHooks", L="decompengine/acp/AcpSandboxLaunch", P="decompengine/acp/AcpSandboxLaunchPurpose", B="decompengine/acp/LinuxBubblewrapBoundary";
    static final String D="(L"+L+";Ljava/lang/String;)V", TOKEN="0123456789abcdef".repeat(4);
    static int controls;
    interface Checked {void run()throws Exception;}
    static void yes(String label,Checked c)throws Exception{c.run();controls++;}
    static void no(String label,Checked c)throws Exception{try{c.run();}catch(IllegalArgumentException expected){controls++;return;}throw new AssertionError("accepted "+label);}
    static void noAt(String label,String reason,Checked c)throws Exception{try{c.run();}catch(IllegalArgumentException expected){if(!reason.equals(expected.getMessage()))throw new AssertionError("wrong refusal for "+label,expected);controls++;return;}throw new AssertionError("accepted "+label);}
    static MethodVisitor method(ClassWriter w,int access,String name,String desc){var m=w.visitMethod(access,name,desc,null,null);m.visitCode();return m;}
    static void end(MethodVisitor m){m.visitMaxs(16,8);m.visitEnd();}
    static void f(MethodVisitor m,int op,String name,String desc){m.visitFieldInsn(op,H,name,desc);}
    static void own(MethodVisitor m,String name,String desc){m.visitMethodInsn(INVOKESTATIC,H,name,desc,false);}
    static void put(MethodVisitor m){m.visitMethodInsn(INVOKEVIRTUAL,"java/nio/ByteBuffer","putLong","(IJ)Ljava/nio/ByteBuffer;",false);m.visitInsn(POP);}
    static ClassWriter writer(String name,String superName,int flags){var w=new ClassWriter(0);w.visit(V17,flags|ACC_SUPER,name,null,superName,null);return w;}
    static byte[] fixedException(String name){var w=writer(H+"$"+name,"java/lang/RuntimeException",ACC_PUBLIC|ACC_FINAL);w.visitNestHost(H);var m=method(w,ACC_PRIVATE,"<init>","()V");m.visitVarInsn(ALOAD,0);m.visitLdcInsn(name.equals("Stop")?"SNAPSHOT_COPY_STOP_OBSERVATION":"SNAPSHOT_COPY_STOP_INVALID");m.visitInsn(ACONST_NULL);m.visitInsn(ICONST_0);m.visitInsn(ICONST_0);m.visitMethodInsn(INVOKESPECIAL,"java/lang/RuntimeException","<init>","(Ljava/lang/String;Ljava/lang/Throwable;ZZ)V",false);m.visitInsn(RETURN);end(m);w.visitEnd();return w.toByteArray();}
    static byte[] hooks(){
        var w=writer(H,"java/lang/Object",ACC_PUBLIC|ACC_FINAL);w.visitNestMember(H+"$Stop");w.visitNestMember(H+"$InvalidStop");
        for(String field:List.of("counters","times","starts","ioStart"))w.visitField(ACC_PRIVATE|ACC_STATIC|ACC_FINAL,field,"[J",null,null).visitEnd();w.visitField(ACC_PRIVATE|ACC_STATIC|ACC_FINAL,"stack","[I",null,null).visitEnd();
        w.visitField(ACC_PRIVATE|ACC_STATIC,"page","Ljava/nio/ByteBuffer;",null,null).visitEnd();w.visitField(ACC_PRIVATE|ACC_STATIC,"owner","Ljava/lang/Thread;",null,null).visitEnd();w.visitField(ACC_PRIVATE|ACC_STATIC,"token","Ljava/lang/String;",null,null).visitEnd();
        for(String field:List.of("enabled","invalid","stopped"))w.visitField(ACC_PRIVATE|ACC_STATIC|ACC_VOLATILE,field,"Z",null,null).visitEnd();w.visitField(ACC_PRIVATE|ACC_STATIC,"sequence","J",null,null).visitEnd();
        var m=method(w,ACC_PRIVATE,"<init>","()V");m.visitVarInsn(ALOAD,0);m.visitMethodInsn(INVOKESPECIAL,"java/lang/Object","<init>","()V",false);m.visitInsn(RETURN);end(m);
        m=method(w,ACC_STATIC,"<clinit>","()V");m.visitIntInsn(SIPUSH,128);m.visitIntInsn(NEWARRAY,T_LONG);f(m,PUTSTATIC,"counters","[J");m.visitIntInsn(BIPUSH,32);m.visitIntInsn(NEWARRAY,T_LONG);f(m,PUTSTATIC,"times","[J");m.visitIntInsn(BIPUSH,32);m.visitIntInsn(NEWARRAY,T_LONG);f(m,PUTSTATIC,"starts","[J");m.visitInsn(ICONST_3);m.visitIntInsn(NEWARRAY,T_LONG);f(m,PUTSTATIC,"ioStart","[J");m.visitIntInsn(BIPUSH,32);m.visitIntInsn(NEWARRAY,T_INT);f(m,PUTSTATIC,"stack","[I");m.visitInsn(RETURN);end(m);
        m=method(w,ACC_PRIVATE|ACC_STATIC,"active","()Z");var enabled=new Label();var owner=new Label();f(m,GETSTATIC,"enabled","Z");m.visitJumpInsn(IFNE,enabled);m.visitInsn(ICONST_0);m.visitInsn(IRETURN);m.visitLabel(enabled);m.visitMethodInsn(INVOKESTATIC,"java/lang/Thread","currentThread","()Ljava/lang/Thread;",false);f(m,GETSTATIC,"owner","Ljava/lang/Thread;");m.visitJumpInsn(IF_ACMPEQ,owner);own(m,"bad","()V");m.visitInsn(ICONST_0);m.visitInsn(IRETURN);m.visitLabel(owner);m.visitInsn(ICONST_1);m.visitInsn(IRETURN);end(m);
        m=method(w,ACC_PRIVATE|ACC_STATIC,"bad","()V");var absent=new Label();m.visitInsn(ICONST_1);f(m,PUTSTATIC,"invalid","Z");f(m,GETSTATIC,"page","Ljava/nio/ByteBuffer;");m.visitJumpInsn(IFNULL,absent);f(m,GETSTATIC,"page","Ljava/nio/ByteBuffer;");m.visitIntInsn(BIPUSH,24);m.visitInsn(LCONST_1);put(m);m.visitLabel(absent);m.visitInsn(RETURN);end(m);
        m=method(w,ACC_PRIVATE|ACC_STATIC,"add","(IJ)V");var bad=new Label();var good=new Label();m.visitVarInsn(ILOAD,0);m.visitJumpInsn(IFLT,bad);m.visitVarInsn(ILOAD,0);m.visitIntInsn(SIPUSH,128);m.visitJumpInsn(IF_ICMPGE,bad);m.visitVarInsn(LLOAD,1);m.visitInsn(LCONST_0);m.visitInsn(LCMP);m.visitJumpInsn(IFLT,bad);m.visitVarInsn(LLOAD,1);m.visitLdcInsn(Long.MAX_VALUE);f(m,GETSTATIC,"counters","[J");m.visitVarInsn(ILOAD,0);m.visitInsn(LALOAD);m.visitInsn(LSUB);m.visitInsn(LCMP);m.visitJumpInsn(IFLE,good);m.visitLabel(bad);own(m,"bad","()V");m.visitInsn(RETURN);m.visitLabel(good);f(m,GETSTATIC,"counters","[J");m.visitVarInsn(ILOAD,0);m.visitInsn(DUP2);m.visitInsn(LALOAD);m.visitVarInsn(LLOAD,1);m.visitInsn(LADD);m.visitInsn(LASTORE);f(m,GETSTATIC,"page","Ljava/nio/ByteBuffer;");m.visitIntInsn(SIPUSH,128);m.visitVarInsn(ILOAD,0);m.visitIntInsn(BIPUSH,8);m.visitInsn(IMUL);m.visitInsn(IADD);f(m,GETSTATIC,"counters","[J");m.visitVarInsn(ILOAD,0);m.visitInsn(LALOAD);put(m);m.visitInsn(RETURN);end(m);
        m=method(w,ACC_PRIVATE|ACC_STATIC,"event","(I)V");good=new Label();f(m,GETSTATIC,"sequence","J");m.visitLdcInsn(Long.MAX_VALUE);m.visitInsn(LCMP);m.visitJumpInsn(IFNE,good);own(m,"bad","()V");m.visitInsn(RETURN);m.visitLabel(good);m.visitIntInsn(SIPUSH,2048);f(m,GETSTATIC,"sequence","J");m.visitLdcInsn(512L);m.visitInsn(LREM);m.visitInsn(L2I);m.visitIntInsn(BIPUSH,24);m.visitInsn(IMUL);m.visitInsn(IADD);m.visitVarInsn(ISTORE,1);f(m,GETSTATIC,"page","Ljava/nio/ByteBuffer;");m.visitVarInsn(ILOAD,1);f(m,GETSTATIC,"sequence","J");put(m);f(m,GETSTATIC,"page","Ljava/nio/ByteBuffer;");m.visitVarInsn(ILOAD,1);m.visitIntInsn(BIPUSH,8);m.visitInsn(IADD);m.visitVarInsn(ILOAD,0);m.visitInsn(I2L);put(m);f(m,GETSTATIC,"page","Ljava/nio/ByteBuffer;");m.visitVarInsn(ILOAD,1);m.visitIntInsn(BIPUSH,16);m.visitInsn(IADD);m.visitMethodInsn(INVOKESTATIC,"java/lang/System","nanoTime","()J",false);put(m);f(m,GETSTATIC,"page","Ljava/nio/ByteBuffer;");m.visitIntInsn(BIPUSH,32);f(m,GETSTATIC,"sequence","J");m.visitInsn(LCONST_1);m.visitInsn(LADD);m.visitInsn(DUP2);f(m,PUTSTATIC,"sequence","J");put(m);m.visitInsn(RETURN);end(m);
        m=method(w,ACC_PUBLIC|ACC_STATIC,"prepare","(Ljava/nio/ByteBuffer;Ljava/lang/String;)V");bad=new Label();good=new Label();f(m,GETSTATIC,"page","Ljava/nio/ByteBuffer;");m.visitJumpInsn(IFNONNULL,bad);m.visitVarInsn(ALOAD,0);m.visitMethodInsn(INVOKEVIRTUAL,"java/nio/ByteBuffer","capacity","()I",false);m.visitLdcInsn(65536);m.visitJumpInsn(IF_ICMPNE,bad);m.visitVarInsn(ALOAD,1);m.visitLdcInsn("[0-9a-f]{64}");m.visitMethodInsn(INVOKEVIRTUAL,"java/lang/String","matches","(Ljava/lang/String;)Z",false);m.visitJumpInsn(IFNE,good);m.visitLabel(bad);m.visitTypeInsn(NEW,H+"$InvalidStop");m.visitInsn(DUP);m.visitMethodInsn(INVOKESPECIAL,H+"$InvalidStop","<init>","()V",false);m.visitInsn(ATHROW);m.visitLabel(good);m.visitVarInsn(ALOAD,0);m.visitFieldInsn(GETSTATIC,"java/nio/ByteOrder","BIG_ENDIAN","Ljava/nio/ByteOrder;");m.visitMethodInsn(INVOKEVIRTUAL,"java/nio/ByteBuffer","order","(Ljava/nio/ByteOrder;)Ljava/nio/ByteBuffer;",false);f(m,PUTSTATIC,"page","Ljava/nio/ByteBuffer;");m.visitVarInsn(ALOAD,1);f(m,PUTSTATIC,"token","Ljava/lang/String;");m.visitMethodInsn(INVOKESTATIC,"java/lang/Thread","currentThread","()Ljava/lang/Thread;",false);f(m,PUTSTATIC,"owner","Ljava/lang/Thread;");f(m,GETSTATIC,"page","Ljava/nio/ByteBuffer;");m.visitInsn(ICONST_0);m.visitLdcInsn(0x53434f5059303031L);put(m);f(m,GETSTATIC,"page","Ljava/nio/ByteBuffer;");m.visitIntInsn(BIPUSH,8);m.visitInsn(LCONST_1);put(m);m.visitInsn(ICONST_1);f(m,PUTSTATIC,"enabled","Z");f(m,GETSTATIC,"page","Ljava/nio/ByteBuffer;");m.visitIntInsn(BIPUSH,16);m.visitInsn(LCONST_1);put(m);m.visitInsn(RETURN);end(m);
        m=method(w,ACC_PUBLIC|ACC_STATIC,"stopBeforeOuterStart",D);bad=new Label();good=new Label();own(m,"active","()Z");m.visitJumpInsn(IFEQ,bad);f(m,GETSTATIC,"invalid","Z");m.visitJumpInsn(IFNE,bad);f(m,GETSTATIC,"stopped","Z");m.visitJumpInsn(IFNE,bad);f(m,GETSTATIC,"token","Ljava/lang/String;");m.visitVarInsn(ALOAD,1);m.visitMethodInsn(INVOKESTATIC,"java/util/Objects","equals","(Ljava/lang/Object;Ljava/lang/Object;)Z",false);m.visitJumpInsn(IFEQ,bad);m.visitVarInsn(ALOAD,0);m.visitJumpInsn(IFNULL,bad);m.visitVarInsn(ALOAD,0);m.visitMethodInsn(INVOKEVIRTUAL,L,"getPurpose","()L"+P+";",false);m.visitFieldInsn(GETSTATIC,P,"OUTER_AGENT","L"+P+";");m.visitJumpInsn(IF_ACMPEQ,good);m.visitLabel(bad);own(m,"bad","()V");m.visitTypeInsn(NEW,H+"$InvalidStop");m.visitInsn(DUP);m.visitMethodInsn(INVOKESPECIAL,H+"$InvalidStop","<init>","()V",false);m.visitInsn(ATHROW);m.visitLabel(good);m.visitInsn(ICONST_1);f(m,PUTSTATIC,"stopped","Z");m.visitIntInsn(BIPUSH,97);m.visitInsn(LCONST_1);own(m,"add","(IJ)V");f(m,GETSTATIC,"page","Ljava/nio/ByteBuffer;");m.visitIntInsn(BIPUSH,40);m.visitInsn(LCONST_1);put(m);m.visitIntInsn(SIPUSH,300);own(m,"event","(I)V");m.visitTypeInsn(NEW,H+"$Stop");m.visitInsn(DUP);m.visitMethodInsn(INVOKESPECIAL,H+"$Stop","<init>","()V",false);m.visitInsn(ATHROW);end(m);
        m=method(w,ACC_PUBLIC|ACC_STATIC,"stopped","()Z");bad=new Label();good=new Label();f(m,GETSTATIC,"stopped","Z");m.visitJumpInsn(IFEQ,bad);f(m,GETSTATIC,"invalid","Z");m.visitJumpInsn(IFNE,bad);m.visitInsn(ICONST_1);m.visitJumpInsn(GOTO,good);m.visitLabel(bad);m.visitInsn(ICONST_0);m.visitLabel(good);m.visitInsn(IRETURN);end(m);
        // Unrelated methods are declared inert DATA bodies; no product fixture is loaded/executed.
        Map<String,String> rest=Map.ofEntries(Map.entry("duration","(IJ)V"),Map.entry("enter","(I)V"),Map.entry("exit","(I)V"),Map.entry("grouped","(IJ)V"),Map.entry("note","(I)V"),Map.entry("ioBegin","(I)V"),Map.entry("readResult","(J)V"),Map.entry("writeResult","(JJ)V"),Map.entry("errno","(I)V"),Map.entry("fsyncComplete","()V"),Map.entry("copyAllocated","()V"),Map.entry("copyClosed","(Ljava/lang/Throwable;)V"),Map.entry("finish","(Ljava/nio/file/Path;)V"));
        for(var e:rest.entrySet()){m=method(w,ACC_STATIC|((e.getKey().equals("duration")||e.getKey().equals("grouped"))?ACC_PRIVATE:ACC_PUBLIC),e.getKey(),e.getValue());m.visitInsn(RETURN);end(m);}w.visitEnd();return w.toByteArray();
    }
    static byte[] launch(){var w=writer(L,"java/lang/Object",ACC_PUBLIC|ACC_FINAL);w.visitField(ACC_PRIVATE|ACC_FINAL,"purpose","L"+P+";",null,null).visitEnd();var m=method(w,ACC_PUBLIC|ACC_FINAL,"getPurpose","()L"+P+";");m.visitVarInsn(ALOAD,0);m.visitFieldInsn(GETFIELD,L,"purpose","L"+P+";");m.visitInsn(ARETURN);end(m);w.visitEnd();return w.toByteArray();}
    static byte[] purpose(){var w=writer(P,"java/lang/Enum",ACC_PUBLIC|ACC_FINAL|ACC_ENUM);var init=method(w,ACC_PRIVATE,"<init>","(Ljava/lang/String;I)V");init.visitVarInsn(ALOAD,0);init.visitVarInsn(ALOAD,1);init.visitVarInsn(ILOAD,2);init.visitMethodInsn(INVOKESPECIAL,"java/lang/Enum","<init>","(Ljava/lang/String;I)V",false);init.visitInsn(RETURN);end(init);w.visitField(ACC_PUBLIC|ACC_STATIC|ACC_FINAL|ACC_ENUM,"OUTER_AGENT","L"+P+";",null,null).visitEnd();var m=method(w,ACC_STATIC,"<clinit>","()V");m.visitTypeInsn(NEW,P);m.visitInsn(DUP);m.visitLdcInsn("OUTER_AGENT");m.visitInsn(ICONST_0);m.visitMethodInsn(INVOKESPECIAL,P,"<init>","(Ljava/lang/String;I)V",false);m.visitFieldInsn(PUTSTATIC,P,"OUTER_AGENT","L"+P+";");m.visitInsn(RETURN);end(m);w.visitEnd();return w.toByteArray();}
    static SnapshotCapsuleAudit.Image image(byte[] b)throws Exception{return new SnapshotCapsuleAudit.Image(b,new SnapshotCapsuleAudit.Work());}
    static Map<String,byte[]> helperData(){var out=new TreeMap<String,byte[]>();out.put(H,hooks());out.put(H+"$Stop",fixedException("Stop"));out.put(H+"$InvalidStop",fixedException("InvalidStop"));return out;}
    static void checkHelpers(Map<String,byte[]> bytes)throws Exception{Map<String,SnapshotCapsuleAudit.Image> out=new TreeMap<>();for(var e:bytes.entrySet())out.put(e.getKey(),image(e.getValue()));SnapshotCapsuleAudit.auditHelpers(out,image(launch()),image(purpose()),new SnapshotCapsuleAudit.Work());}
    static byte[] changed(byte[] bytes,String name,Consumer<MethodNode> mutation){ClassNode c=new ClassNode();new ClassReader(bytes).accept(c,0);MethodNode selected=null;for(var m:c.methods)if(m.name.equals(name)){if(selected!=null)throw new AssertionError("fixture ambiguous");selected=m;}if(selected==null)throw new AssertionError("fixture missing");mutation.accept(selected);var w=new ClassWriter(0);c.accept(w);return w.toByteArray();}
    static List<AbstractInsnNode> real(MethodNode m){var out=new ArrayList<AbstractInsnNode>();for(var n:m.instructions)if(n.getOpcode()>=0)out.add(n);return out;}
    static void mutateHelper(String label,String method,Consumer<MethodNode> mutation)throws Exception{var bytes=helperData();bytes.put(H,changed(bytes.get(H),method,mutation));no(label,()->checkHelpers(bytes));}
    static byte[] caller(String variant){
        var w=writer(B,"java/lang/Object",ACC_PUBLIC|ACC_FINAL);var m=method(w,ACC_PUBLIC,"launch","(L"+L+";)Ljava/lang/Process;");Label entry=new Label(),stop=new Label(),start=new Label(),end=new Label(),handler=new Label(),operandInterior=new Label();
        m.visitLabel(entry);
        if(variant.equals("reflection")){m.visitInsn(ACONST_NULL);m.visitInsn(ACONST_NULL);m.visitInsn(ACONST_NULL);m.visitMethodInsn(INVOKEVIRTUAL,"java/lang/reflect/Method","invoke","(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;",false);m.visitInsn(POP);}
        switch(variant){case "direct"->m.visitJumpInsn(GOTO,start);case "conditional"->{m.visitInsn(ICONST_0);m.visitJumpInsn(IFEQ,start);}case "table"->{m.visitInsn(ICONST_0);m.visitTableSwitchInsn(0,0,start,stop);}case "lookup"->{m.visitInsn(ICONST_0);m.visitLookupSwitchInsn(start,new int[]{1},new Label[]{stop});}case "interior"->{m.visitVarInsn(ALOAD,1);m.visitJumpInsn(GOTO,operandInterior);}default->{}}
        if(variant.equals("overwrite")){m.visitInsn(ACONST_NULL);m.visitVarInsn(ASTORE,1);}
        m.visitLabel(stop);m.visitVarInsn(ALOAD,variant.equals("local")?0:1);if(variant.equals("interior"))m.visitLabel(operandInterior);m.visitLdcInsn(variant.equals("token")?"not-a-token":TOKEN);m.visitMethodInsn(INVOKESTATIC,H,"stopBeforeOuterStart",D,false);
        m.visitLabel(start);m.visitInsn(ACONST_NULL);m.visitMethodInsn(INVOKEVIRTUAL,"java/lang/ProcessBuilder","start","()Ljava/lang/Process;",false);m.visitLabel(end);m.visitInsn(ARETURN);
        m.visitLabel(handler);if(variant.equals("handler")){m.visitInsn(POP);m.visitJumpInsn(GOTO,start);}else m.visitInsn(ATHROW);
        m.visitTryCatchBlock(stop,end,handler,"java/lang/Throwable");end(m);
        if(variant.equals("default")||variant.equals("duplicate")||variant.equals("fallback")){m=method(w,ACC_PUBLIC|ACC_STATIC,variant.equals("default")?"launch$default":variant.equals("fallback")?"fallbackStart":"launch","()Ljava/lang/Process;");m.visitInsn(ACONST_NULL);m.visitMethodInsn(INVOKEVIRTUAL,"java/lang/ProcessBuilder","start","()Ljava/lang/Process;",false);m.visitInsn(ARETURN);end(m);}w.visitEnd();return w.toByteArray();
    }
    static void checkCaller(byte[] bytes)throws Exception{String token=SnapshotCapsuleAudit.auditCaller(image(bytes).node,new SnapshotCapsuleAudit.Work());if(!TOKEN.equals(token))throw new AssertionError("observed token");}
    static void checkEmission(Map<String,SnapshotCapsuleAudit.Image> originals,Map<String,SnapshotCapsuleAudit.Image> overlays,byte[] allow)throws Exception{
        var work=new SnapshotCapsuleAudit.Work();var parsed=SnapshotCapsuleAudit.parseAllowlist(allow,originals,overlays,work);
        SnapshotCapsuleAudit.stripEqual(originals,overlays,parsed,TOKEN,work);
    }
    /** Minimal raw class writer, not an alternative parser/proof. Code bytes remain DATA. */
    static byte[] raw(byte[] code,int cpCount,int handlers)throws Exception{
        var bytes=new ByteArrayOutputStream();var d=new DataOutputStream(bytes);d.writeInt(0xcafebabe);d.writeShort(0);d.writeShort(61);d.writeShort(cpCount);
        d.writeByte(1);d.writeUTF("C");d.writeByte(7);d.writeShort(1);d.writeByte(1);d.writeUTF("java/lang/Object");d.writeByte(7);d.writeShort(3);d.writeByte(1);d.writeUTF("m");d.writeByte(1);d.writeUTF("()V");d.writeByte(1);d.writeUTF("Code");
        for(int i=8;i<cpCount;i++){d.writeByte(1);d.writeUTF("unused"+i);}
        d.writeShort(ACC_PUBLIC|ACC_SUPER);d.writeShort(2);d.writeShort(4);d.writeShort(0);d.writeShort(0);d.writeShort(1);d.writeShort(ACC_PUBLIC|ACC_STATIC);d.writeShort(5);d.writeShort(6);d.writeShort(1);d.writeShort(7);d.writeInt(12+code.length+8*handlers);d.writeShort(8);d.writeShort(8);d.writeInt(code.length);d.write(code);d.writeShort(handlers);for(int i=0;i<handlers;i++){d.writeShort(0);d.writeShort(1);d.writeShort(1);d.writeShort(0);}d.writeShort(0);d.writeShort(0);return bytes.toByteArray();
    }
    static void admission(byte[] b)throws Exception{SnapshotCapsuleAudit.rawAdmission(b,new SnapshotCapsuleAudit.Work());}
    static void helperControls()throws Exception{
        yes("feasible prepared state fixed recipes",()->checkHelpers(helperData()));
        for(int guard=0;guard<6;guard++){final int selected=guard;mutateHelper("guard inverted "+guard,"stopBeforeOuterStart",m->{int seen=0;for(var n:m.instructions)if(n instanceof JumpInsnNode j&&seen++==selected){j.setOpcode(j.getOpcode()==IFEQ?IFNE:j.getOpcode()==IFNE?IFEQ:j.getOpcode()==IFNULL?IFNONNULL:IF_ACMPNE);break;}});}
        mutateHelper("enabled guard inverted","active",m->{for(var n:m.instructions)if(n instanceof JumpInsnNode j){j.setOpcode(IFEQ);break;}});
        mutateHelper("invalid flag cleared","bad",m->{m.instructions.set(real(m).get(0),new InsnNode(ICONST_0));});
        mutateHelper("owner comparison inverted","active",m->{for(var n:m.instructions)if(n instanceof JumpInsnNode j&&j.getOpcode()==IF_ACMPEQ){j.setOpcode(IF_ACMPNE);break;}});
        mutateHelper("always invalid trap","active",m->{m.instructions.clear();m.instructions.add(new InsnNode(ICONST_0));m.instructions.add(new InsnNode(IRETURN));});
        mutateHelper("site token self comparison","stopBeforeOuterStart",m->{for(var n:m.instructions)if(n instanceof FieldInsnNode f&&f.name.equals("token")){m.instructions.set(n,new VarInsnNode(ALOAD,1));break;}});
        mutateHelper("purpose getter ignored","stopBeforeOuterStart",m->{for(var n:m.instructions)if(n instanceof MethodInsnNode call&&call.name.equals("getPurpose")){call.name="otherPurpose";break;}});
        mutateHelper("first use reset","stopBeforeOuterStart",m->{var x=new InsnList();x.add(new InsnNode(ICONST_0));x.add(new FieldInsnNode(PUTSTATIC,H,"stopped","Z"));m.instructions.insert(x);});
        mutateHelper("clean predicate lies","stopped",m->{m.instructions.clear();m.instructions.add(new InsnNode(ICONST_1));m.instructions.add(new InsnNode(IRETURN));});
        mutateHelper("unknown internal call","stopBeforeOuterStart",m->{for(var n:m.instructions)if(n instanceof MethodInsnNode call&&call.name.equals("event")){call.name="unknown";break;}});
        mutateHelper("overflow event guard removed","event",m->{for(var n:m.instructions)if(n instanceof JumpInsnNode j){j.setOpcode(IFEQ);break;}});
        mutateHelper("counter operand wrong","stopBeforeOuterStart",m->{for(var n:m.instructions)if(n instanceof IntInsnNode i&&i.operand==97){i.operand=98;break;}});
        mutateHelper("prepare owner replaced","prepare",m->{for(var n:m.instructions)if(n instanceof MethodInsnNode call&&call.name.equals("currentThread")){call.name="otherThread";break;}});
        mutateHelper("return substitute","stopBeforeOuterStart",m->{m.instructions.clear();m.instructions.add(new InsnNode(RETURN));});
        mutateHelper("loop only","stopBeforeOuterStart",m->{m.instructions.clear();var l=new LabelNode();m.instructions.add(l);m.instructions.add(new JumpInsnNode(GOTO,l));});
        mutateHelper("disconnected fixed throws","stopBeforeOuterStart",m->{var first=m.instructions.getFirst();var l=new LabelNode();m.instructions.insertBefore(first,l);m.instructions.insertBefore(first,new JumpInsnNode(GOTO,l));});
        for(String which:List.of("Stop","InvalidStop")){var bytes=helperData();bytes.put(H+"$"+which,changed(bytes.get(H+"$"+which),"<init>",m->{for(var n:m.instructions)if(n instanceof LdcInsnNode l){l.cst="wrong";break;}}));no("fixed message "+which,()->checkHelpers(bytes));}
        var missing=helperData();missing.remove(H+"$Stop");no("missing sentinel",()->checkHelpers(missing));
        var flags=helperData();flags.put(H+"$Stop",changed(flags.get(H+"$Stop"),"<init>",m->{var c=real(m);m.instructions.set(c.get(3),new InsnNode(ICONST_1));}));no("suppression enabled",()->checkHelpers(flags));
    }
    static void callerControls()throws Exception{yes("exception cleanup rethrows; no normal stop edge",()->checkCaller(caller("valid")));for(String s:List.of("direct","conditional","table","lookup","handler","local","token","overwrite","default","duplicate","fallback","reflection"))no("caller "+s,()->checkCaller(caller(s)));noAt("caller interior","interior stop operand bypass",()->checkCaller(caller("interior")));}
    static void parserAndLifetimeControls()throws Exception{
        byte[] tiny={(byte)NOP,(byte)RETURN};yes("raw small",()->admission(raw(tiny,8,0)));yes("CP exact",()->admission(raw(tiny,8192,0)));no("CP plus one",()->admission(raw(tiny,8193,0)));
        byte[] exact=new byte[8192];exact[8191]=(byte)RETURN;yes("instructions exact",()->admission(raw(exact,8,0)));no("instructions plus one",()->admission(raw(new byte[8193],8,0)));
        yes("handlers exact",()->admission(raw(tiny,8,256)));no("handlers plus one",()->admission(raw(tiny,8,257)));
        no("Image before clone class bound",()->image(new byte[1048577]));
        no("class bytes plus one",()->admission(new byte[1048577]));no("truncated CP",()->admission(new byte[]{(byte)0xca,(byte)0xfe,(byte)0xba,(byte)0xbe,0,0,0,61,0,8}));
        no("unknown CP tag",()->{byte[] b=raw(tiny,8,0);b[10]=99;admission(b);});
        no("wrong CP reference type",()->{byte[] b=raw(tiny,8,0);b[15]=0;b[16]=2;admission(b);});
        for(byte[] broken:List.of(new byte[]{(byte)TABLESWITCH,0},new byte[]{(byte)LOOKUPSWITCH,0,0,0,0,0,0,0,-1,-1,-1,-1},new byte[]{(byte)GOTO,0,1,(byte)RETURN},new byte[]{(byte)196,(byte)RET,0,0},new byte[]{(byte)INVOKEVIRTUAL,0,1,(byte)RETURN}))no("malformed raw Code",()->admission(raw(broken,8,0)));
        no("handler empty range",()->{byte[] b=raw(tiny,8,1);b[b.length-11]=1;admission(b);});
        yes("combined final byte admitted",()->{if(SnapshotCapsuleAudit.remainingCombined(1048575)!=1)throw new AssertionError("remaining");});
        no("combined next file after exact cap",()->SnapshotCapsuleAudit.remainingCombined(1048576));
        yes("work exact",()->{var w=new SnapshotCapsuleAudit.Work();w.take(4000000);});no("work plus one",()->{var w=new SnapshotCapsuleAudit.Work();w.take(4000000);w.take(1);});
        yes("same captured bytes survive caller mutation",()->{byte[] b=hooks();var i=image(b);String digest=i.digest;Arrays.fill(b,(byte)0);if(!digest.equals(SnapshotCapsuleAudit.sha(i.bytes))||!i.node.name.equals(H))throw new AssertionError("snapshot alias");});
        no("missing launch dependency",()->{Map<String,SnapshotCapsuleAudit.Image> a=new HashMap<>();for(var e:helperData().entrySet())a.put(e.getKey(),image(e.getValue()));SnapshotCapsuleAudit.auditHelpers(a,null,image(purpose()),new SnapshotCapsuleAudit.Work());});
        no("shadowed launch this_class",()->{Map<String,SnapshotCapsuleAudit.Image> a=new HashMap<>();for(var e:helperData().entrySet())a.put(e.getKey(),image(e.getValue()));SnapshotCapsuleAudit.auditHelpers(a,image(purpose()),image(purpose()),new SnapshotCapsuleAudit.Work());});
        no("wrong getter field receiver",()->{Map<String,SnapshotCapsuleAudit.Image> a=new HashMap<>();for(var e:helperData().entrySet())a.put(e.getKey(),image(e.getValue()));byte[] b=changed(launch(),"getPurpose",m->{((VarInsnNode)real(m).get(0)).var=1;});SnapshotCapsuleAudit.auditHelpers(a,image(b),image(purpose()),new SnapshotCapsuleAudit.Work());});
    }
    static byte[] empty(String name){var w=writer(name,"java/lang/Object",ACC_PUBLIC|ACC_FINAL);w.visitEnd();return w.toByteArray();}
    static byte[] boundCaller(boolean transformed){var w=writer(B,"java/lang/Object",ACC_PUBLIC|ACC_FINAL);var m=method(w,ACC_PUBLIC,"launch","(L"+L+";)Ljava/lang/Process;");Label begin=new Label(),end=new Label(),handler=new Label();m.visitLabel(begin);
        m.visitInsn(ACONST_NULL);
        if(transformed){m.visitLdcInsn("SCOPY001/0/"+B+"/launch/1/STOP/BEGIN");m.visitInsn(POP);m.visitVarInsn(ALOAD,1);m.visitLdcInsn(TOKEN);m.visitMethodInsn(INVOKESTATIC,H,"stopBeforeOuterStart",D,false);m.visitLdcInsn("SCOPY001/0/"+B+"/launch/1/STOP/END");m.visitInsn(POP);}
        m.visitMethodInsn(INVOKEVIRTUAL,"java/lang/ProcessBuilder","start","()Ljava/lang/Process;",false);m.visitLabel(end);m.visitInsn(ARETURN);m.visitLabel(handler);m.visitInsn(ATHROW);m.visitTryCatchBlock(begin,end,handler,"java/lang/Throwable");m.visitMaxs(transformed?24:16,8);m.visitEnd();w.visitEnd();return w.toByteArray();
    }
    static Map<String,SnapshotCapsuleAudit.Image> six(boolean transformed)throws Exception{var out=new TreeMap<String,SnapshotCapsuleAudit.Image>();for(String n:List.of(B,B+"$Companion","decompengine/acp/PinnedReadOnlyMount$Companion","decompengine/acp/LinuxBubblewrapBoundaryKt","decompengine/acp/RuntimePrivateControlScope","decompengine/acp/LinuxFilesystemSyscalls"))out.put(n,image(n.equals(B)?boundCaller(transformed):empty(n)));return out;}
    static byte[] allowlist(Map<String,SnapshotCapsuleAudit.Image> original){StringBuilder s=new StringBuilder();for(var e:original.entrySet())s.append("CLASS\t").append(e.getKey()).append('\t').append(e.getValue().digest).append('\n');s.append("SITE\t").append(B).append("\tlaunch\t(L").append(L).append(";)Ljava/lang/Process;\t1\t182 M java/lang/ProcessBuilder start ()Ljava/lang/Process; false\tSTOP\t1\tBEFORE\n");return s.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8);}
    static byte[] edgeData(boolean plusOne){var w=writer("C","java/lang/Object",ACC_PUBLIC);var m=method(w,ACC_PUBLIC|ACC_STATIC,"m","()V");Label[] nodes=new Label[511];for(int i=0;i<nodes.length;i++)nodes[i]=new Label();Label end=new Label();for(Label l:nodes){m.visitLabel(l);m.visitInsn(NOP);}m.visitLabel(end);if(plusOne)m.visitInsn(NOP);m.visitInsn(RETURN);for(int i=0;i<256;i++)m.visitTryCatchBlock(nodes[0],end,nodes[i],null);end(m);w.visitEnd();return w.toByteArray();}
    static void dependencyControl(String label,String method,Consumer<MethodNode> mutation)throws Exception{no(label,()->{Map<String,SnapshotCapsuleAudit.Image> a=new HashMap<>();for(var e:helperData().entrySet())a.put(e.getKey(),image(e.getValue()));SnapshotCapsuleAudit.auditHelpers(a,image(launch()),image(changed(purpose(),method,mutation)),new SnapshotCapsuleAudit.Work());});}
    static void bindingControls()throws Exception{
        dependencyControl("enum producer bypass","<clinit>",m->{var last=m.instructions.getLast();var exit=new LabelNode();m.instructions.insertBefore(last,exit);m.instructions.insertBefore(m.instructions.getFirst(),new JumpInsnNode(GOTO,exit));});
        dependencyControl("enum always throw","<clinit>",m->{m.instructions.clear();m.instructions.add(new InsnNode(ACONST_NULL));m.instructions.add(new InsnNode(ATHROW));});
        dependencyControl("enum constructor foreign call","<init>",m->{for(var n:m.instructions)if(n instanceof MethodInsnNode call){call.owner="foreign/Enum";break;}});
        var original=six(false);var overlay=six(true);byte[] allow=allowlist(original);
        yes("six captured class hashes and exact stop ordinal",()->SnapshotCapsuleAudit.declaredStop(allow,original,overlay,new SnapshotCapsuleAudit.Work()));
        yes("independent strip metadata CFG handlers",()->checkEmission(original,overlay,allow));
        yes("bound caller real CFG",()->checkCaller(overlay.get(B).bytes));
        no("wrong stop ordinal",()->SnapshotCapsuleAudit.declaredStop(new String(allow,java.nio.charset.StandardCharsets.UTF_8).replace(";\t1\t182",";\t0\t182").getBytes(java.nio.charset.StandardCharsets.UTF_8),original,overlay,new SnapshotCapsuleAudit.Work()));
        no("original class pin drift",()->SnapshotCapsuleAudit.declaredStop(new String(allow,java.nio.charset.StandardCharsets.UTF_8).replace(original.get(B).digest,"0".repeat(64)).getBytes(java.nio.charset.StandardCharsets.UTF_8),original,overlay,new SnapshotCapsuleAudit.Work()));
        no("overlay metadata drift",()->{var a=new TreeMap<>(overlay);a.put(B,image(changed(overlay.get(B).bytes,"launch",m->m.access|=ACC_FINAL)));checkEmission(original,a,allow);});
        no("overlay original body drift",()->{var a=new TreeMap<>(overlay);a.put(B,image(changed(overlay.get(B).bytes,"launch",m->{for(var n:m.instructions)if(n instanceof MethodInsnNode call&&call.owner.equals("java/lang/ProcessBuilder")){call.name="otherStart";break;}})));checkEmission(original,a,allow);});
        no("overlay handler target drift",()->{var a=new TreeMap<>(overlay);a.put(B,image(changed(overlay.get(B).bytes,"launch",m->{var h=m.tryCatchBlocks.get(0);h.handler=h.start;})));checkEmission(original,a,allow);});
        Map<String,SnapshotCapsuleAudit.Image> helper=new TreeMap<>();for(var e:helperData().entrySet())helper.put(e.getKey(),image(e.getValue()));for(String n:List.of("SnapshotCopyEntry","SnapshotOverlayBuilder","SnapshotCapsuleAudit"))helper.put(n,image(empty(n)));
        yes("actual root and reciprocal emitted nest closure",()->SnapshotCapsuleAudit.helperClosure(helper,new SnapshotCapsuleAudit.Work()));
        no("missing CP nested dependency",()->{var a=new TreeMap<>(helper);a.remove(H+"$Stop");SnapshotCapsuleAudit.helperClosure(a,new SnapshotCapsuleAudit.Work());});
        no("shadowed key and this_class",()->{var a=new TreeMap<>(helper);a.put(H,a.get(H+"$Stop"));SnapshotCapsuleAudit.helperClosure(a,new SnapshotCapsuleAudit.Work());});
        no("fixture never production helper",()->{var a=new TreeMap<>(helper);a.put("SnapshotCapsuleAuditDataTest",image(empty("SnapshotCapsuleAuditDataTest")));SnapshotCapsuleAudit.helperClosure(a,new SnapshotCapsuleAudit.Work());});
        yes("actual CFG edge exact131072",()->SnapshotCapsuleAudit.graph(image(edgeData(false)).node.methods.get(0),-1,new SnapshotCapsuleAudit.Work()));
        no("actual CFG edge plus one",()->SnapshotCapsuleAudit.graph(image(edgeData(true)).node.methods.get(0),-1,new SnapshotCapsuleAudit.Work()));
    }
    static byte[] maximumHandlerData(){
        var w=writer("MaximumHandlers","java/lang/Object",ACC_PUBLIC|ACC_FINAL);
        var m=method(w,ACC_PUBLIC|ACC_STATIC,"body","()V");var begin=new Label();var handler=new Label();var end=new Label();
        m.visitLabel(begin);m.visitInsn(ACONST_NULL);for(int i=0;i<8190;i++)m.visitInsn(NOP);
        m.visitLabel(handler);m.visitInsn(ATHROW);m.visitLabel(end);
        for(int i=0;i<256;i++)m.visitTryCatchBlock(begin,end,handler,"java/lang/Throwable");
        end(m);w.visitEnd();return w.toByteArray();
    }
    static final String FS="decompengine/acp/LinuxFilesystemSyscalls";
    static void block(MethodVisitor method,int serial,String label,Consumer<MethodVisitor> body){
        String key="SCOPY001/"+serial+"/"+label;
        method.visitLdcInsn(key+"/BEGIN");method.visitInsn(POP);body.accept(method);method.visitLdcInsn(key+"/END");method.visitInsn(POP);
    }
    static void sampleBlock(MethodVisitor method,int serial,String suffix,Consumer<MethodVisitor> body){block(method,serial,FS+"/sample/"+suffix,body);}
    static void integerHook(MethodVisitor method,String name,int value){method.visitLdcInsn(value);own(method,name,"(I)V");}
    /** Independently authored producer bytes, not generated with auditor recipe helpers. */
    static byte[] allModeSample(boolean overlay){
        var writer=writer(FS,"java/lang/Object",ACC_PUBLIC|ACC_FINAL);var m=method(writer,ACC_PUBLIC|ACC_STATIC,"sample","()V");
        var begin=new Label();var end=new Label();
        if(overlay)sampleBlock(m,11,"ENTER",x->integerHook(x,"enter",12));
        m.visitLabel(begin);m.visitLineNumber(123,begin);
        m.visitLdcInsn(0L);m.visitVarInsn(LSTORE,2);m.visitLdcInsn(0L);m.visitVarInsn(LSTORE,4);m.visitLdcInsn(0L);m.visitVarInsn(LSTORE,0);
        if(overlay){
            sampleBlock(m,7,"5/WRITE",x->{x.visitVarInsn(LLOAD,0);x.visitVarInsn(LLOAD,2);x.visitVarInsn(LLOAD,4);x.visitInsn(LSUB);own(x,"writeResult","(JJ)V");});
            sampleBlock(m,6,"5/READ",x->{x.visitVarInsn(LLOAD,0);own(x,"readResult","(J)V");});
        }
        if(overlay)sampleBlock(m,1,"6/NOTE",x->integerHook(x,"note",40));
        m.visitInsn(ICONST_0);m.visitVarInsn(ISTORE,6);
        if(overlay)sampleBlock(m,5,"7/ERRNO",x->{x.visitVarInsn(ILOAD,6);own(x,"errno","(I)V");});
        m.visitInsn(ACONST_NULL);m.visitVarInsn(ASTORE,6);
        if(overlay)sampleBlock(m,9,"9/ALLOC",x->own(x,"copyAllocated","()V"));
        m.visitInsn(ACONST_NULL);m.visitVarInsn(ASTORE,7);m.visitVarInsn(ALOAD,6);m.visitVarInsn(ALOAD,7);
        m.visitMethodInsn(INVOKESTATIC,"kotlin/io/CloseableKt","closeFinally","(Ljava/io/Closeable;Ljava/lang/Throwable;)V",false);
        if(overlay)sampleBlock(m,10,"14/CLOSE",x->{x.visitVarInsn(ALOAD,7);own(x,"copyClosed","(Ljava/lang/Throwable;)V");});
        if(overlay){sampleBlock(m,2,"15/IOSTART",x->integerHook(x,"ioBegin",0));sampleBlock(m,3,"15/PHASEENTER",x->integerHook(x,"enter",4));}
        m.visitMethodInsn(INVOKESTATIC,"fixture/Calls","noop","()V",false);
        if(overlay){sampleBlock(m,8,"15/FSYNCEND",x->own(x,"fsyncComplete","()V"));sampleBlock(m,4,"15/PHASEEXIT",x->integerHook(x,"exit",4));sampleBlock(m,12,"RETURN",x->integerHook(x,"exit",12));}
        m.visitInsn(RETURN);m.visitLabel(end);m.visitLocalVariable("authoredLong","J",null,begin,end,0);
        m.visitMaxs(overlay?24:16,8);m.visitEnd();writer.visitEnd();return writer.toByteArray();
    }
    static byte[] allModeAllowlist(Map<String,SnapshotCapsuleAudit.Image> originals){
        var text=new StringBuilder(new String(allowlist(originals),java.nio.charset.StandardCharsets.UTF_8));
        String call="184 M fixture/Calls noop ()V false";
        String[][] rows={{"6","3","NOTE","40","BEFORE"},{"15",call,"IOSTART","0","BEFORE"},{"15",call,"PHASEENTER","4","BEFORE"},{"15",call,"PHASEEXIT","4","AFTER"},{"7","54 V 6","ERRNO","6","AFTER"},{"5","55 V 0","READ","0","AFTER"},{"5","55 V 0","WRITE","0,2,4","AFTER"},{"15",call,"FSYNCEND","0","AFTER"},{"9","58 V 6","ALLOC","0","AFTER"},{"14","184 M kotlin/io/CloseableKt closeFinally (Ljava/io/Closeable;Ljava/lang/Throwable;)V false","CLOSE","7","AFTER"}};
        for(var row:rows)text.append("SITE\t").append(FS).append("\tsample\t()V\t").append(String.join("\t",row)).append('\n');
        text.append("TIME\t").append(FS).append("\tsample\t()V\t12\n");return text.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8);
    }
    static LdcInsnNode beginBlock(MethodNode method,String suffix){
        for(var node:method.instructions)if(node instanceof LdcInsnNode constant&&constant.cst instanceof String text&&text.startsWith("SCOPY001/")&&text.endsWith("/"+suffix+"/BEGIN"))return constant;
        throw new AssertionError("missing authored block "+suffix);
    }
    static InsnList detachBlock(MethodNode method,AbstractInsnNode begin){
        String key=((String)((LdcInsnNode)begin).cst).replaceFirst("/BEGIN$","");var result=new InsnList();var node=begin;
        while(node!=null){var next=node.getNext();boolean last=node instanceof LdcInsnNode constant&&(key+"/END").equals(constant.cst);method.instructions.remove(node);result.add(node);node=next;if(last){if(node==null||node.getOpcode()!=POP)throw new AssertionError("missing authored end pop");method.instructions.remove(node);result.add(node);return result;}}
        throw new AssertionError("missing authored end");
    }
    static void emissionMutation(String label,Map<String,SnapshotCapsuleAudit.Image> original,Map<String,SnapshotCapsuleAudit.Image> overlay,byte[] allow,Consumer<MethodNode> mutation)throws Exception{
        no(label,()->{var changed=new TreeMap<>(overlay);changed.put(FS,image(changed(overlay.get(FS).bytes,"sample",mutation)));checkEmission(original,changed,allow);});
    }
    static byte[] noteBoundary(boolean nonneutral){return changed(boundCaller(true),"launch",method->{
        int markers=0;for(var node:method.instructions)if(node instanceof LdcInsnNode constant&&constant.cst instanceof String text&&text.startsWith("SCOPY001/0/")){constant.cst=text.replace("SCOPY001/0/","SCOPY001/1/");markers++;}
        if(markers!=2)throw new AssertionError("authored stop markers");
        String key="SCOPY001/0/"+B+"/launch/0/NOTE";var block=new InsnList();block.add(new LdcInsnNode(key+"/BEGIN"));block.add(new InsnNode(POP));
        if(nonneutral){block.add(new InsnNode(ICONST_0));block.add(new VarInsnNode(ISTORE,2));}
        block.add(new LdcInsnNode(40));block.add(new MethodInsnNode(INVOKESTATIC,H,"note","(I)V",false));block.add(new LdcInsnNode(key+"/END"));block.add(new InsnNode(POP));method.instructions.insertBefore(real(method).get(0),block);
    });}
    static void emissionControls()throws Exception{
        var original=six(false);original.put(FS,image(allModeSample(false)));var overlay=six(true);overlay.put(FS,image(allModeSample(true)));byte[] allow=allModeAllowlist(original);
        yes("all modes and TIME faithfully compose with valid stop",()->{checkCaller(overlay.get(B).bytes);checkEmission(original,overlay,allow);});
        emissionMutation("nonneutral NOTE store is not erased",original,overlay,allow,m->{var at=beginBlock(m,"NOTE").getNext();var extra=new InsnList();extra.add(new InsnNode(ICONST_0));extra.add(new VarInsnNode(ISTORE,2));m.instructions.insert(at,extra);});
        emissionMutation("extra stack neutral nodes are not a declared recipe",original,overlay,allow,m->{var extra=new InsnList();extra.add(new InsnNode(ICONST_0));extra.add(new InsnNode(POP));m.instructions.insert(beginBlock(m,"NOTE").getNext(),extra);});
        emissionMutation("known same-ABI integer hook is still the wrong recipe",original,overlay,allow,m->{((MethodInsnNode)beginBlock(m,"NOTE").getNext().getNext().getNext()).name="enter";});
        for(String mode:List.of("NOTE","IOSTART","PHASEENTER","PHASEEXIT","ERRNO","READ","WRITE","CLOSE","ENTER","RETURN")){
            emissionMutation("exact typed operand "+mode,original,overlay,allow,m->{var operand=beginBlock(m,mode).getNext().getNext();if(operand instanceof LdcInsnNode constant)constant.cst=((Integer)constant.cst)+1;else if(operand instanceof VarInsnNode variable)variable.var=variable.var==0?1:0;else throw new AssertionError("expected authored operand");});
        }
        for(String mode:List.of("ALLOC","FSYNCEND"))emissionMutation("exact zero-arg callee "+mode,original,overlay,allow,m->{((MethodInsnNode)beginBlock(m,mode).getNext().getNext()).name=mode.equals("ALLOC")?"fsyncComplete":"copyAllocated";});
        emissionMutation("metadata inside a block cannot be erased",original,overlay,allow,m->{var label=new LabelNode();var metadata=new InsnList();metadata.add(label);metadata.add(new LineNumberNode(321,label));m.instructions.insert(beginBlock(m,"NOTE").getNext(),metadata);});
        emissionMutation("wrong raw anchor cannot normalize away",original,overlay,allow,m->{var block=detachBlock(m,beginBlock(m,"NOTE"));m.instructions.insertBefore(m.instructions.getFirst(),block);});
        emissionMutation("AFTER sibling ordering is exact",original,overlay,allow,m->{var first=beginBlock(m,"WRITE");var read=detachBlock(m,beginBlock(m,"READ"));m.instructions.insertBefore(first,read);});
        emissionMutation("duplicate block fails population before normalization",original,overlay,allow,m->{var source=beginBlock(m,"NOTE");var copy=new InsnList();String key=((String)source.cst).replaceFirst("/BEGIN$","");copy.add(new LdcInsnNode(key+"/BEGIN"));copy.add(new InsnNode(POP));copy.add(new LdcInsnNode(40));copy.add(new MethodInsnNode(INVOKESTATIC,H,"note","(I)V",false));copy.add(new LdcInsnNode(key+"/END"));copy.add(new InsnNode(POP));m.instructions.insertBefore(source,copy);});
        emissionMutation("missing block fails population",original,overlay,allow,m->detachBlock(m,beginBlock(m,"NOTE")));
        emissionMutation("coherent wrong serial cannot normalize away",original,overlay,allow,m->{for(var node:m.instructions)if(node instanceof LdcInsnNode constant&&constant.cst instanceof String text&&text.startsWith("SCOPY001/1/"))constant.cst=text.replace("SCOPY001/1/","SCOPY001/99/");});
        emissionMutation("TIME entry precedes original head metadata",original,overlay,allow,m->{var entry=detachBlock(m,beginBlock(m,"ENTER"));var line=m.instructions.getFirst().getNext();if(!(line instanceof LineNumberNode))throw new AssertionError("authored head metadata");m.instructions.insert(line,entry);});
        noAt("original shape does not come from proposed row","site shape mismatch",()->checkEmission(original,overlay,new String(allow,java.nio.charset.StandardCharsets.UTF_8).replace("55 V 0","55 V 2").getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        noAt("selected fixture token is an exact inserted operand","exact inserted operand/site/order",()->{var changed=new TreeMap<>(overlay);changed.put(B,image(changed(overlay.get(B).bytes,"launch",m->{for(var node:m.instructions)if(node instanceof LdcInsnNode constant&&TOKEN.equals(constant.cst))constant.cst="f".repeat(64);})));checkEmission(original,changed,allow);});
        var sameOriginal=six(false);var sameOverlay=six(true);sameOverlay.put(B,image(noteBoundary(false)));
        String declaration="SITE\t"+B+"\tlaunch\t(L"+L+";)Ljava/lang/Process;\t0\t1\tNOTE\t40\tBEFORE\n";
        String base=new String(allowlist(sameOriginal),java.nio.charset.StandardCharsets.UTF_8);int site=base.indexOf("SITE\t");byte[] sameAllow=(base.substring(0,site)+declaration+base.substring(site)).getBytes(java.nio.charset.StandardCharsets.UTF_8);
        yes("coherent NOTE and valid STOP in same method",()->{checkCaller(sameOverlay.get(B).bytes);checkEmission(sameOriginal,sameOverlay,sameAllow);});
        var nonneutral=new TreeMap<>(sameOverlay);nonneutral.put(B,image(noteBoundary(true)));checkCaller(nonneutral.get(B).bytes);
        noAt("eight-node NOTE store refuses while caller stop remains valid","exact inserted recipe",()->checkEmission(sameOriginal,nonneutral,sameAllow));
    }
    static void chargedGraphControls()throws Exception{
        yes("actual8192x256 duplicate handler cells within original work budget",()->{
            var work=new SnapshotCapsuleAudit.Work();var actual=new SnapshotCapsuleAudit.Image(maximumHandlerData(),work);
            var graph=SnapshotCapsuleAudit.graph(actual.node.methods.get(0),-1,work);long edges=0;
            for(var row:graph)edges+=row.length;
            if(graph.size()!=8192||edges!=16382||work.visits>4000000)throw new AssertionError("bounded maximum handler graph");
        });
        yes("raw metadata advances are charged",()->{
            var m=new MethodNode();m.instructions.add(new LabelNode());m.instructions.add(new InsnNode(RETURN));m.instructions.add(new LabelNode());
            var work=new SnapshotCapsuleAudit.Work();var layout=new SnapshotCapsuleAudit.MethodLayout(m,work);
            if(work.visits<15||layout.instructions.size()!=1)throw new AssertionError("three charged raw passes and label table");
        });
        no("foreign label refuses via charged identity lookup",()->{
            var m=new MethodNode();m.instructions.add(new JumpInsnNode(GOTO,new LabelNode()));
            SnapshotCapsuleAudit.graph(m,-1,new SnapshotCapsuleAudit.Work());
        });
        no("null label is never an empty-slot match",()->{
            var m=new MethodNode();m.instructions.add(new JumpInsnNode(GOTO,null));
            SnapshotCapsuleAudit.graph(m,-1,new SnapshotCapsuleAudit.Work());
        });
        no("exhausted layout budget refuses before first raw advance",()->{
            var m=new MethodNode();m.instructions.add(new InsnNode(RETURN));
            var work=new SnapshotCapsuleAudit.Work();work.take(4000000);new SnapshotCapsuleAudit.MethodLayout(m,work);
        });
    }
    public static void main(String[] args)throws Exception{if(args.length!=0)throw new IllegalArgumentException("no external fixture inputs");helperControls();callerControls();parserAndLifetimeControls();bindingControls();chargedGraphControls();emissionControls();if(controls!=115)throw new AssertionError("authored control inventory mismatch: "+controls);System.out.println("class-data controls="+controls+"; no product classes loaded; fixture-only prospective result");}
}
