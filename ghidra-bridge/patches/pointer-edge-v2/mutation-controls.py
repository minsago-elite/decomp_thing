"""Bounded isolated negative controls. Mutant classes never enter the final modules."""
from pathlib import Path
import hashlib,json,subprocess,zipfile,shutil,threading,signal,os
P=Path(__file__).resolve().parent;R=P.parents[2];E=None
from control_support import evidence_root, bounded_run
E=evidence_root(R)
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
build=json.loads((E/'build-result.json').read_text());tests=json.loads((E/'test-result.json').read_text())
for entry in json.loads((P/'source-manifest.json').read_text())['sources']:
 assert sha(P/'src'/entry['path'])==entry['source_sha256']
assert len(tests)==5 and all(x['exit']==0 for x in tests)
mutations=[
 ('factory-copy-authority','SoftwareModeling','ghidra/program/model/data/PointerDataType.java',
  'authority && finiteOwnedFactory(getClass())','true','OwnedPointerIngressTest','Expected failure'),
 ('cold-name-map','SoftwareModeling','ghidra/program/database/data/SettingsDBAdapterV1.java',
  'String readSettingNameDirect(short index) throws IOException {','String readSettingNameDirect(short index) throws IOException { initNameMaps();',
  'OwnedPointerSettingsTest','observation never initializes name maps'),
 ('sticky-receipt','Project','ghidra/framework/data/DomainObjectAdapterDB.java',
  'if (failure != null) throw failure;','if (false) throw failure;','OwnedPointerLifecycleTest','Expected failure'),
 ('listing-origin-erased','SoftwareModeling','ghidra/program/database/code/CodeManager.java',
  '        catch (IOException | CancelledException | RuntimeException | Error e) {\n            program.recordOwnedIntegrityFailure(e); throw e;',
  '        catch (java.lang.UnsupportedOperationException e) { return null; }\n        catch (IOException | CancelledException | RuntimeException | Error e) {\n            program.recordOwnedIntegrityFailure(e); throw e;',
  'OwnedPointerLifecycleTest','monitor throws exact original'),
 ('settings-origin-erased','SoftwareModeling','ghidra/program/database/data/ProgramBasedDataTypeManagerDB.java',
  '        catch (IOException | CancelledException | RuntimeException | Error e) { ownedFailure(e); throw e; }',
  '        catch (java.lang.UnsupportedOperationException e) { return null; }\n        catch (IOException | CancelledException | RuntimeException | Error e) { ownedFailure(e); throw e; }',
  'OwnedPointerSettingsTest','adapter throws exact original'),
 ('policy-poisons-owner','SoftwareModeling','ghidra/program/database/data/ProgramDataTypeManager.java',
  'if (e != localPolicy) ownedFailure(e);','ownedFailure(e);',
  'OwnedPointerLifecycleTest','genuine policy refusal receipt clean'),
 ('name-limit-poisons-owner','SoftwareModeling','ghidra/program/database/data/SettingsDBAdapterV1.java',
  'if (name.length() > 64) return null;',
  'if (name.length() > 64) throw new java.lang.UnsupportedOperationException("mutant name limit");',
  'OwnedPointerSettingsTest','genuine policy refusal receipt clean'),
 ('acquire-cleanup-masks-origin','SoftwareModeling','ghidra/program/database/data/DataTypeManagerDB.java',
  'releaseOwnedLock(e);','lock.release();',
  'OwnedPointerLifecycleTest','Expected class java.lang.UnsupportedOperationException'),
 ('architecture-first-origin-lost','SoftwareModeling','ghidra/program/database/data/DataTypeManagerDB.java',
  'catch (IOException | CancelledException | RuntimeException | Error failure) {\n                primary = failure;\n                if (isOwnedStrict()) ownedFailure(failure);',
  'catch (IOException | CancelledException | RuntimeException | Error failure) {\n                primary = failure;',
  'OwnedPointerLifecycleTest','origin receipt retains exact original Throwable')]
mutation_root=E/('mutations-%03d'%(len(list(E.glob('mutations-*')))+1));mutation_root.mkdir()
shutil.copyfile(P/'mutation-controls.py',mutation_root/'mutation-controls.py')
results=[]
for name,module,source,before,after,test,marker in mutations:
 out=mutation_root/name;out.mkdir(parents=True,exist_ok=True)
 classes=out/'classes'
 if classes.exists():shutil.rmtree(classes)
 classes.mkdir()
 shutil.copytree(P/'tests',out/'tests',dirs_exist_ok=True)
 src=out/'src'/source;src.parent.mkdir(parents=True,exist_ok=True)
 text=(P/'src'/source).read_text();assert text.count(before)==1
 src.write_text(text.replace(before,after))
 runtime=out/'runtime'
 for m in ['Project','SoftwareModeling']:
  dest=runtime/m/'lib'/(m+'.jar');dest.parent.mkdir(parents=True,exist_ok=True)
  shutil.copyfile(E/'one'/(m+'.jar'),dest)
 cp=[runtime/Path(x['path']).stem/'lib'/Path(x['path']).name if Path(x['path']).name in ['Project.jar','SoftwareModeling.jar'] else R/x['path'] for x in build['classpath']]
 command=['/usr/lib/jvm/openjdk-bin-21/bin/javac','-J-XX:-UsePerfData','-J-Xmx512m','-J-XX:MaxMetaspaceSize=256m','-J-Djava.io.tmpdir='+str(E/'tmp'),'--release','21','-proc:none','-implicit:none','-sourcepath',str(E/'empty-sourcepath'),'-cp',':'.join(map(str,cp)),'-d',str(classes),str(src)]
 compile_result=bounded_run(command,capture_output=True,timeout=60)
 (out/'compile.log').write_bytes(compile_result.stdout+compile_result.stderr)
 assert compile_result.returncode==0,compile_result.stderr.decode()
 outer=source.removesuffix('.java')
 permitted={x['entry'] for x in json.loads((P/'class-allowlist.json').read_text())['replace'] if x['module']==module and (x['entry']==outer+'.class' or x['entry'].startswith(outer+'$'))}
 actual={str(p.relative_to(classes)) for p in classes.rglob('*.class')}
 sibling=json.loads((P/'class-allowlist.json').read_text())['preserve_compiler_sibling']
 assert actual==permitted|({sibling} if source.endswith('/DataTypeManagerDB.java') else set())
 actual=permitted # Explicitly discard unchanged compiler sibling; never replace its pristine payload.
 target=runtime/module/'lib'/(module+'.jar')
 with zipfile.ZipFile(E/'one'/(module+'.jar')) as base, zipfile.ZipFile(target,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as dest:
  for info in base.infolist():dest.writestr(info,(classes/info.filename).read_bytes() if info.filename in actual else base.read(info.filename))
 command=list(next(x['command'] for x in tests if x['test']==test))
 for i,arg in enumerate(command):
  if arg.startswith('-Downed.test.modules='):command[i]='-Downed.test.modules='+str(runtime)
 command[command.index('-cp')+1]=':'.join(map(str,[E/'test-classes']+cp))
 with (out/'stdout.log').open('wb') as stdout,(out/'stderr.log').open('wb') as stderr:
  process=subprocess.Popen(command,stdout=stdout,stderr=stderr,cwd=R,start_new_session=True)
  expired=threading.Event()
  def terminate():
   try:expired.set();os.killpg(process.pid,signal.SIGKILL)
   except ProcessLookupError:pass
  watchdog=threading.Timer(60,terminate);watchdog.start()
  try:_,status,usage=os.wait4(process.pid,0);process.returncode=os.waitstatus_to_exitcode(status)
  finally:watchdog.cancel()
 log=(out/'stdout.log').read_text()+(out/'stderr.log').read_text()
 assert not expired.is_set() and process.returncode!=0 and 'AssertionError' in log and marker in log,log[-6000:]
 result={'mutation':name,'source_sha256':sha(src),'original_sha256':sha(P/'src'/source),'before':before,'after':after,
  'test_sources':{str(p.relative_to(P)):sha(p) for p in sorted((P/'tests').rglob('*.java'))},'base_source_manifest_sha256':sha(P/'source-manifest.json'),
  'compile_command':compile_result.args,'compile_exit':compile_result.returncode,'test':test,'command':command,'exit':process.returncode,
  'expected_failure_marker':marker,'maxrss_kib':usage.ru_maxrss,'module_sha256':sha(target),'mutant_killed':True}
 (out/'result.json').write_text(json.dumps(result,indent=2)+'\n');results.append(result)
 print('PASS mutation killed:',name)
(E/'mutation-result.json').write_text(json.dumps(results,indent=2)+'\n')
shutil.copyfile(E/'mutation-result.json',mutation_root/'mutation-result.json')
