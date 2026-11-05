"""DISABLED dependency controls only; never installs or activates a profile."""
from pathlib import Path
import hashlib,json,subprocess,zipfile,shutil,difflib,os,re
P=Path(__file__).resolve().parent;ROOT=P.parents[2]
from control_support import evidence_root, bounded_run
E=evidence_root(ROOT)
B=ROOT/'build/orchestration/exporter-v20-pointer-provenance-architecture-v2-review-evidence/api-source'
V=ROOT/'build/orchestration/exporter-v20-pointer-provenance-architecture-v2-evidence'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def save(p,x):p.write_text(json.dumps(x,indent=2)+'\n')
assert not (E/'build-result.json').exists(), 'Choose a fresh evidence directory for a new build'
for d in ['tmp','empty-sourcepath','test-classes','user','cache']: (E/d).mkdir(parents=True,exist_ok=True)
# Lock to reviewed compiler and ordered API jars. No implicit discovery or processors.
pins=json.loads((V/'declaration-result.json').read_text())
jdkpins=json.loads((P/'jdk21-pins.json').read_text())
for name,digest in jdkpins.items(): assert sha(Path(name))==digest
javac=Path('/usr/lib/jvm/openjdk-bin-21/bin/javac')
base_dependencies=json.loads((V/'dependencies.json').read_text())
for name,pin in base_dependencies.items(): assert sha(ROOT/name)==pin['expected']
cp=[]
for x in pins['classpath']:
 p=ROOT/x['path'];assert sha(p)==x['sha256'],p;cp.append(p)
allow=json.loads((P/'class-allowlist.json').read_text())
def apply_exact(base,diff):
 old=base.splitlines(True);lines=diff.splitlines(True);result=[];cursor=0;i=2
 while i<len(lines):
  match=re.match(r'@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@',lines[i]);assert match
  start=max(0,int(match[1])-1);assert start>=cursor
  result.extend(old[cursor:start]);cursor=start;i+=1
  while i<len(lines) and not lines[i].startswith('@@'):
   mode,line=lines[i][0],lines[i][1:]
   if mode in ' -':assert cursor<len(old) and old[cursor]==line;cursor+=1
   if mode in ' +':result.append(line)
   assert mode in ' +-';i+=1
 result.extend(old[cursor:]);return ''.join(result)
records=[]
# Enumerated reviewed source closure. Discovery checks extras; it never supplies compiler inputs.
source_paths=[P/'src'/x['path'] for x in json.loads((P/'source-manifest.json').read_text())['sources']]
assert set(source_paths)==set((P/'src').rglob('*.java')), 'Unreviewed source closure change'
for p in source_paths:
 rel=p.relative_to(P/'src'); base=B/rel
 if base.exists():
  module='Project' if str(rel).startswith('ghidra/framework/') else 'SoftwareModeling'
  archive=next(ROOT/name for name in base_dependencies if name.endswith('/'+module+'-src.zip'))
  with zipfile.ZipFile(archive) as z: assert z.read(str(rel))==base.read_bytes()
 diff=''.join(difflib.unified_diff(base.read_text().splitlines(True) if base.exists() else [],p.read_text().splitlines(True),fromfile='a/'+str(rel) if base.exists() else '/dev/null',tofile='b/'+str(rel)))
 assert apply_exact(base.read_text() if base.exists() else '',diff)==p.read_text()
 dest=P/'diffs'/rel.with_suffix('.patch');dest.parent.mkdir(parents=True,exist_ok=True);dest.write_text(diff)
 records.append({'path':str(rel),'base_sha256':sha(base) if base.exists() else None,'source_sha256':sha(p),'diff_sha256':sha(dest),'exact_patch_roundtrip':True})
save(P/'source-manifest.json',{'status':'DISABLED; dependency controls only','architecture_sha256':'aab21b0bba33a63d7c07b9034ed35348cd1d3804cba48cd1575a48298ff97747','sources':records})
def compile(sources,classes,classpath,label):
 classes.mkdir(parents=True,exist_ok=True)
 cmd=[str(javac),'-J-XX:-UsePerfData','-J-Xmx512m','-J-XX:MaxMetaspaceSize=256m','-J-Djava.io.tmpdir='+str(E/'tmp'),'--release','21','-proc:none','-implicit:none','-sourcepath',str(E/'empty-sourcepath'),'-classpath',':'.join(map(str,classpath)),'-d',str(classes)]+list(map(str,sources))
 r=bounded_run(cmd,cwd=ROOT,capture_output=True,timeout=90)
 (E/(label+'.stdout')).write_bytes(r.stdout);(E/(label+'.stderr')).write_bytes(r.stderr)
 save(E/(label+'.json'),{'command':cmd,'exit':r.returncode})
 if r.returncode:print(r.stderr.decode()[-10000:]);raise SystemExit(r.returncode)
def package(module,classes,target):
 original=next(p for p in cp if p.name==module+'.jar')
 entries={x['entry'] for x in allow['replace'] if x['module']==module}
 actual={str(p.relative_to(classes)) for p in classes.rglob('*.class')}
 sibling=allow['preserve_compiler_sibling']
 assert actual==entries|({sibling} if module=='SoftwareModeling' else set()),(actual-entries,entries-actual)
 with zipfile.ZipFile(original) as src,zipfile.ZipFile(target,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as dst:
  names=src.namelist();assert len(names)==len(set(names))
  for name in sorted(set(names)|entries):
   data=(classes/name).read_bytes() if name in entries else src.read(name)
   info=zipfile.ZipInfo(name,(1980,1,1,0,0,0));info.compress_type=zipfile.ZIP_DEFLATED;info.create_system=3;info.external_attr=(0o40755 if name.endswith('/') else 0o100644)<<16
   dst.writestr(info,data,compress_type=zipfile.ZIP_DEFLATED,compresslevel=9)
 with zipfile.ZipFile(original) as src,zipfile.ZipFile(target) as dst:
  for name in src.namelist():
   if name not in entries:assert src.read(name)==dst.read(name),name
 return {'module':module,'sha256':sha(target),'base_sha256':sha(original),'replacements':sorted(entries),'unchanged_payloads_verified':True,'CategoryCache_pristine':module=='SoftwareModeling'}
outputs=[]
for lane in ['one','two']:
 out=E/lane
 if out.exists():shutil.rmtree(out)
 out.mkdir()
 project=[p for p in source_paths if str(p.relative_to(P/'src')).startswith('ghidra/framework/')]
 compile(project,out/'project-classes',cp,lane+'-project')
 pr=package('Project',out/'project-classes',out/'Project.jar')
 software=[p for p in source_paths if str(p.relative_to(P/'src')).startswith('ghidra/program/')]
 derivedcp=[out/'Project.jar' if p.name=='Project.jar' else p for p in cp]
 compile(software,out/'software-classes',derivedcp,lane+'-software')
 sm=package('SoftwareModeling',out/'software-classes',out/'SoftwareModeling.jar')
 save(out/'manifest.json',{'scope':'isolated throwaway dependency control modules; DISABLED','modules':[pr,sm],'source_manifest_sha256':sha(P/'source-manifest.json')})
 outputs.append({n:sha(out/n) for n in ['Project.jar','SoftwareModeling.jar','manifest.json']})
assert outputs[0]==outputs[1]
save(E/'build-result.json',{'reproducible':True,'outputs':outputs,'compiler_sha256':sha(javac),'classpath':pins['classpath'],'status':'DISABLED','source_manifest_sha256':sha(P/'source-manifest.json'),'jdk21_pins':jdkpins})
save(P/'recipe-manifest.json',{'recipe_sha256':sha(Path(__file__)),'control_support_sha256':sha(P/'control_support.py'),'compiler_sha256':sha(javac),'compiler':pins['compiler'],'flags':['--release','21','-proc:none','-implicit:none','-sourcepath','EMPTY'],'classpath':pins['classpath'],'module_order':['Project','SoftwareModeling'],'class_allowlist_sha256':sha(P/'class-allowlist.json'),'zip':{'order':'lexical','time':'1980-01-01T00:00:00','compression':'DEFLATE9','file_mode':'100644','directory_mode':'40755'},'activation':False})
print('PASS: two clean builds; exact 24-class inventory; pristine remaining payloads; equal modules/manifests')
