"""Hash exact compiler dependency graph, shared libraries and driver configs."""
from pathlib import Path
import hashlib,json,re,subprocess,sys
root=Path(__file__).resolve().parent.parent
work=root/'toolchain-001'
deps=(work/'helper-dependencies.d').read_text().replace('\\\n',' ').split(':',1)[1].split()
paths={Path(p).resolve() for p in deps}
for tool in [work/'record_identity_probe',Path('/usr/lib/llvm/23/bin/clang')]:
 listing=subprocess.check_output(['/usr/bin/ldd',str(tool)],text=True)
 for entry in re.findall(r'(/[^\s()]+)',listing):
  if Path(entry).is_file():paths.add(Path(entry).resolve())
for config in Path('/etc/clang').rglob('*.cfg'):paths.add(config.resolve())
paths.update([Path('/usr/lib/llvm/23/bin/clang++').resolve(),Path('/usr/bin/ld').resolve(),Path('/usr/bin/as').resolve()])
value={'schemaVersion':2,'sourceSha256':hashlib.sha256((root/'record_identity_probe.cpp').read_bytes()).hexdigest(),'binarySha256':hashlib.sha256((work/'record_identity_probe').read_bytes()).hexdigest(),'buildReceipt':sys.argv[2],'dependencies':{str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(paths)}}
with (work/sys.argv[1]).open('x') as stream:json.dump(value,stream,indent=2);stream.write('\n')
print(value['sourceSha256'],value['binarySha256'],len(paths))
