"""Retain exact tools, configured headers, Python runtime and link inputs before freeze."""
from pathlib import Path
import sys,json,re
root=Path(__file__).resolve().parent.parent;sys.path.insert(0,str(root))
from bounded_runtime import bounded_run,public_result,digest
work=root/'toolchain-001'
env={'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C','TMPDIR':str(work)}
commands=[['/usr/bin/gcc','--version'],['/usr/bin/gcc','-dumpmachine'],['/usr/bin/gcc','-dumpspecs'],['/usr/bin/gcc','-print-prog-name=cc1'],['/usr/bin/gcc','-print-prog-name=collect2'],['/usr/bin/gcc','-print-search-dirs']]
for name in ('crtbeginS.o','crtendS.o','libgcc.a','libgcc_s.so','include'):
 commands.append(['/usr/bin/gcc','-print-file-name='+name])
results=[];paths=set()
for argv in commands:
 r=bounded_run(argv,work,env,timeout=10,output_limit=1048576,managed_scope=True)
 if r['exitCode']!=0:raise RuntimeError('tool inventory command failed')
 results.append(public_result(r))
 if argv[-1].startswith(('-print-prog-name=','-print-file-name=')):
  p=Path(r['stdout'].decode().strip())
  if p.is_file():paths.add(p.resolve())
  elif p.is_dir():paths.update(q.resolve() for q in p.rglob('*') if q.is_file())
for name in ('gcc','as','ld','readelf','python3','bwrap','systemd-run'):
 p=Path('/usr/bin')/name;paths.add(p.resolve())
for p in list(paths):
 with p.open('rb') as stream:
  if stream.read(4)!=b'\x7fELF':continue
 r=bounded_run(['/usr/bin/ldd',str(p)],work,env,timeout=10,output_limit=1048576,managed_scope=True)
 if r['exitCode']==0:
  for name in re.findall(r'(/[^\s()]+)',r['stdout'].decode()):
   q=Path(name)
   if q.is_file():paths.add(q.resolve())
 results.append(public_result(r))
for directory in (Path('/usr/include'),Path('/usr/lib/python3.14'),Path('/usr/lib/clang/23/include')):
 for p in directory.rglob('*'):
  if p.is_file():paths.add(p.resolve())
# Clang's reviewed helper build/runtime closure includes compiler configuration files.
helper=json.loads((work/'helper-pin-007.json').read_bytes());paths.update(Path(p) for p in helper['dependencies'])
value={'schemaVersion':2,'status':'pinned-before-preparation','gccTarget':'x86_64-pc-linux-gnu','commandReceipts':results,'helperPinSha256':digest(work/'helper-pin-007.json'),'dependencies':{str(p):digest(p) for p in sorted(paths)}}
with (work/sys.argv[1]).open('x') as f:json.dump(value,f,indent=2);f.write('\n')
print(len(paths),digest(work/sys.argv[1]))
