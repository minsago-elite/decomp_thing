from pathlib import Path
import json,subprocess,hashlib,sys,time,shutil,os,signal,threading
P=Path(__file__).resolve().parent;R=P.parents[2];E=None
from control_support import evidence_root, bounded_run
E=evidence_root(R)
pins=json.loads((E/'build-result.json').read_text())
assert hashlib.sha256((P/'source-manifest.json').read_bytes()).hexdigest()==pins['source_manifest_sha256']
for entry in json.loads((P/'source-manifest.json').read_text())['sources']:
 assert hashlib.sha256((P/'src'/entry['path']).read_bytes()).hexdigest()==entry['source_sha256']
for name,digest in pins['jdk21_pins'].items():assert hashlib.sha256(Path(name).read_bytes()).hexdigest()==digest
for name in ['Project.jar','SoftwareModeling.jar']:
 assert hashlib.sha256((E/'one'/name).read_bytes()).hexdigest()==pins['outputs'][0][name]
run=E/('run-%03d'%(len(list(E.glob('run-*')))+1));run.mkdir()
shutil.copytree(P/'tests',run/'tests')
shutil.copytree(P/'src',run/'src')
shutil.copyfile(P/'run-tests.py',run/'run-tests.py')
shutil.copyfile(P/'control_support.py',run/'control_support.py')
shutil.copyfile(P/'source-manifest.json',run/'source-manifest.json')
shutil.copyfile(E/'build-result.json',run/'build-result.json')
for module in ['Project','SoftwareModeling']:
 target=E/'runtime'/module/'lib'/(module+'.jar');target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(E/'one'/(module+'.jar'),target)
cp=[E/'runtime'/Path(x['path']).stem/'lib'/Path(x['path']).name if Path(x['path']).name in ['Project.jar','SoftwareModeling.jar'] else R/x['path'] for x in pins['classpath']]
classes=E/'test-classes'
if classes.exists():shutil.rmtree(classes)
classes.mkdir()
cmd=['/usr/lib/jvm/openjdk-bin-21/bin/javac','-J-XX:-UsePerfData','-J-Xmx512m','-J-XX:MaxMetaspaceSize=256m','-J-Djava.io.tmpdir='+str(E/'tmp'),'--release','21','-proc:none','-implicit:none','-sourcepath',str(E/'empty-sourcepath'),'-cp',':'.join(map(str,cp)),'-d',str(classes)]+[str(x) for x in sorted((run/'tests').rglob('*.java'))]
r=bounded_run(cmd,capture_output=True,timeout=60);(E/'tests-compile.log').write_bytes(r.stdout+r.stderr)
if r.returncode:print((r.stdout+r.stderr).decode());sys.exit(r.returncode)
bundle=R/'build/install/llm_bin_patch/libexec/ghidra/ghidra_12.1.3_PUBLIC'
results=[]
for test in sorted((run/'tests').rglob('*Test.java')):
 if len(sys.argv)>1 and test.stem not in sys.argv[1:]:continue
 name=test.stem
 cmd=['/usr/lib/jvm/openjdk-bin-21/bin/java','-XX:-UsePerfData','-Xmx512m','-XX:MaxMetaspaceSize=256m','-Djava.io.tmpdir='+str(E/'tmp'),'-Dapplication.tempdir='+str(E/'tmp'),'-Dapplication.cachedir='+str(E/'cache'),'-Dapplication.settingsdir='+str(E/'user'),'-Djava.util.prefs.userRoot='+str(E/'user/prefs'),'-Downed.test.modules='+str(E/'runtime'),'-Djava.awt.headless=true','-cp',':'.join(map(str,[classes]+cp)),'ghidra.program.database.data.'+name,str(bundle)]
 start=time.monotonic()
 expired=threading.Event()
 with (run/(name+'.stdout')).open('wb') as stdout_file, (run/(name+'.stderr')).open('wb') as stderr_file:
  process=subprocess.Popen(cmd,stdout=stdout_file,stderr=stderr_file,cwd=R,start_new_session=True)
  def terminate_group():
   try:
    expired.set();os.killpg(process.pid,signal.SIGKILL)
   except ProcessLookupError:pass
  watchdog=threading.Timer(60,terminate_group);watchdog.start()
  try:
   _,status,usage=os.wait4(process.pid,0)
   process.returncode=os.waitstatus_to_exitcode(status)
  finally:watchdog.cancel()
 log=(run/(name+'.stdout')).read_bytes()+(run/(name+'.stderr')).read_bytes()
 result={'test':name,'command':cmd,'exit':process.returncode,'timeout':expired.is_set(),
  'elapsed_s':time.monotonic()-start,'maxrss_kib':usage.ru_maxrss,'user_s':usage.ru_utime,'system_s':usage.ru_stime}
 (run/(name+'.log')).write_bytes(log);(E/(name+'.log')).write_bytes(log)
 print(name,process.returncode,log.decode()[-5000:])
 results.append(result)
(E/'test-result.json').write_text(json.dumps(results,indent=2)+'\n')
shutil.copyfile(E/'test-result.json',run/'test-result.json')
if any(x.get('exit')!=0 for x in results):sys.exit(1)
