from pathlib import Path
import sys,json
r=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(r))
from bounded_runtime import bounded_run,public_result
argv=['/usr/lib/llvm/23/bin/clang++','-std=c++17','-MD','-MF',str(r/'toolchain-001/helper-dependencies.d'),'-I/usr/lib/llvm/23/include',str(r/'record_identity_probe.cpp'),'-L/usr/lib/llvm/23/lib64','-Wl,-rpath,/usr/lib/llvm/23/lib64','-lclang-cpp','-lLLVM','-o',str(r/'toolchain-001/record_identity_probe')]
env={'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C','TMPDIR':str(r/'toolchain-001')}
result=public_result(bounded_run(argv,r/'toolchain-001',env,timeout=60,output_limit=1048576,managed_scope=True))
out=r/'toolchain-001'/sys.argv[1]
with out.open('x') as f:json.dump(result,f,indent=2);f.write('\n')
print(result.get('exitCode'));print(bytes.fromhex(result.get('stderrHex','')).decode())
