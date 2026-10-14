"""Pure filesystem fixtures; native subprocess paths are forbidden."""
import copy,contextlib,hashlib,importlib.util,json,os,shlex,struct,subprocess,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
SOURCE=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location('pin_environment',SOURCE/'toolchain-001/pin_environment.py')
pin=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(pin)
l=pin.link_inputs

def authored_elf(needed=(), soname=None, interpreter=None):
 # Authored inert program/dynamic bytes only; never executed, not native capture.
 base=0x400000; raw=bytearray(1024); strings=bytearray(b'\0'); tags=[]
 for name in needed:
  tags.append((1,len(strings)));strings.extend(name.encode()+b'\0')
 if soname is not None:
  tags.append((14,len(strings)));strings.extend(soname.encode()+b'\0')
 tags.extend([(5,base+0x300),(10,len(strings)),(0,0)])
 raw[:16]=b'\x7fELF\x02\x01\x01'+b'\0'*9
 phnum=3 if interpreter else 2
 struct.pack_into('<HHIQQQIHHHHHH',raw,16,2 if interpreter else 3,62,1,0,64,0,0,64,56,phnum,0,0,0)
 struct.pack_into('<IIQQQQQQ',raw,64,1,4,0,base,base,len(raw),len(raw),4096)
 struct.pack_into('<IIQQQQQQ',raw,120,2,4,0x200,base+0x200,base+0x200,len(tags)*16,len(tags)*16,8)
 if interpreter:
  value=interpreter.encode()+b'\0';raw[0x180:0x180+len(value)]=value
  struct.pack_into('<IIQQQQQQ',raw,176,3,4,0x180,base+0x180,base+0x180,len(value),len(value),1)
 for i,row in enumerate(tags):struct.pack_into('<qQ',raw,0x200+i*16,*row)
 raw[0x300:0x300+len(strings)]=strings
 return bytes(raw)

class LinkInputTests(unittest.TestCase):
 def setUp(self):
  for name in ('Popen','run','call','check_call','check_output'):
   guard=patch.object(subprocess,name,side_effect=AssertionError('native subprocess forbidden'));guard.start();self.addCleanup(guard.stop)
  self.temp=tempfile.TemporaryDirectory(prefix='.link-fixture-',dir=SOURCE/'tests');self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
  for name in ('gcc-real','cc1','collect2','as','ld','lto-wrapper','plugin.so'):self.write('/tools/'+name,b'\x7fELF inert tool')
  self.path('/usr/bin').mkdir(parents=True);self.path('/usr/bin/gcc').symlink_to('/tools/gcc-real')
  self.write('/etc/gcc/specs',b'inert specs')
  for name in ('crti.o','crtn.o','crtbeginS.o','crtendS.o','libgcc_s.so.1'):self.write('/gcc/lib/'+name,b'\x7fELF inert '+name.encode())
  self.write('/gcc/lib/libgcc.a',b'!<arch>\ninert archive')
  self.write('/gcc/lib/libgcc_s.so',b'GROUP ( libgcc_s.so.1 -lgcc )')
  self.write('/lib/libc.so',b'/* GNU ld */ OUTPUT_FORMAT(elf64-x86-64) GROUP ( /lib/libc.so.6 /lib/libc_nonshared.a AS_NEEDED ( /lib/ld-linux.so.2 ) )')
  self.write('/lib/libc.so.6',b'\x7fELF inert libc');self.write('/lib/libc_nonshared.a',b'!<arch>\ninert libc archive');self.write('/lib/ld-linux.so.2',b'\x7fELF inert loader')
  self.path('/work').mkdir()
  self.argv=['/tools/collect2','-plugin','/tools/plugin.so','-plugin-opt=/tools/lto-wrapper','-plugin-opt=-pass-through=-lgcc','-shared','--eh-frame-hdr','-m','elf_x86_64','-o','/work/libcandidate.so','/gcc/lib/crti.o','/gcc/lib/crtbeginS.o','-L/gcc/lib','-L/lib','-z','relro','-z','now','-z','noexecstack','--no-undefined','/work/candidate.o','-lgcc','--push-state','--as-needed','-lgcc_s','--pop-state','-lc','-lgcc','/gcc/lib/crtendS.o','/gcc/lib/crtn.o']
  self.manifest={'schemaVersion':3,'driverArgv':['/usr/bin/gcc','-shared','-Wl,-z,relro,-z,now,-z,noexecstack,--no-undefined','/work/candidate.o','-o','/work/libcandidate.so'],'workingDirectory':'/work','environment':{'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C','TMPDIR':'/tmp'},'tools':{'gcc':'/usr/bin/gcc','cc1':'/tools/cc1','collect2':'/tools/collect2','as':'/tools/as','ld':'/tools/ld'},'specs':['/etc/gcc/specs'],'configurationRoots':['/etc/gcc'],'generatedFiles':['/work/candidate.o','/work/libcandidate.so'],'dryRun':''};self.operational_records();self.record()
 def operational_records(self):
  for name in ['worker_exec_monitor.c','worker_exec_proof.py','protocol.json','build_worker_monitor.py']:
   self.write('/public/'+name,('authored inert '+name).encode())
  self.write('/runtime/monitor',authored_elf(['libfixture.so.1'],interpreter='/runtime/ld-runtime.so'))
  self.write('/bin/bash',authored_elf(['libfixture.so.1'],interpreter='/runtime/ld-runtime.so'))
  self.write('/runtime/libfixture.so.1',authored_elf(['libother.so.1'],soname='libfixture.so.1'))
  self.write('/runtime/libother.so.1',authored_elf(soname='libother.so.1'))
  self.write('/runtime/ld-runtime.so',authored_elf(soname='ld-runtime.so'))
  self.write('/usr/bin/ldd',b'#!/bin/bash\n# authored inert metadata fixture; never run\n')
  self.write('/etc/ld.so.cache',b'authored inert cache selection bytes')
  self.write('/headers/stdio.h',b'authored inert header')
  inventory=[{'soname':name,'path':'/runtime/'+name} for name in ['libfixture.so.1','libother.so.1']]
  monitor={'schemaVersion':1,'binaryPath':'/runtime/monitor','sourcePath':'/public/worker_exec_monitor.c','parserPath':'/public/worker_exec_proof.py','protocolPath':'/public/protocol.json','buildScriptPath':'/public/build_worker_monitor.py','provisioningManifestPath':'/public/provision.json','buildInputs':[{'role':role,'path':name} for role,name in [('header','/headers/stdio.h'),('tool','/usr/bin/gcc'),('startup','/gcc/lib/crti.o'),('library','/lib/libc.so.6'),('configuration','/etc/gcc/specs')]],'runtimeLibraries':copy.deepcopy(inventory),'cachePath':'/etc/ld.so.cache'}
  def digest(name):return hashlib.sha256(self.path(name).read_bytes()).hexdigest()
  provision={'schemaVersion':1,'status':'provisioning-only-unqualified','binaryPath':monitor['binaryPath'],**{field:digest(monitor[key]) for field,key in [('binarySha256','binaryPath'),('sourceSha256','sourcePath'),('parserSha256','parserPath'),('protocolSha256','protocolPath')]},'dependencies':[],'buildCommand':['/usr/bin/gcc','-D_GNU_SOURCE','-std=c11','-O2','-Wall','-Wextra','-Werror','-Wl,-z,relro,-z,now,-z,noexecstack',monitor['sourcePath'],'-o',monitor['binaryPath']],'execution':{}}
  self.write('/public/provision.json',json.dumps(provision).encode())
  self.manifest['monitor']=monitor
  self.manifest['inspection']={'schemaVersion':1,'bashPath':'/bin/bash','scriptPath':'/usr/bin/ldd','cachePath':'/etc/ld.so.cache','runtimeLibraries':copy.deepcopy(inventory)}
 def path(self,name):return self.root/name.lstrip('/')
 def write(self,name,data):
  path=self.path(name);path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data)
 def record(self):self.manifest['dryRun']='Using built-in specs.\nReading specs from /etc/gcc/specs\nCOLLECT_LTO_WRAPPER=/tools/lto-wrapper\n '+shlex.join(self.argv)+'\n'
 def test_full_static_closure(self):
  value=pin.collect_pin(self.manifest,self.root);closure=value['implicitLinkClosure']
  for name in ('/gcc/lib/crti.o','/gcc/lib/crtn.o','/gcc/lib/libgcc.a','/gcc/lib/libgcc_s.so.1','/lib/libc.so.6','/lib/libc_nonshared.a','/lib/ld-linux.so.2','/tools/plugin.so','/tools/lto-wrapper'):self.assertIn(name,closure['files'])
  self.assertEqual(closure['files']['/usr/bin/gcc']['realpath'],'/tools/gcc-real');self.assertEqual(closure['files']['/usr/bin/gcc']['symlinks'],[{'path':'/usr/bin/gcc','target':'/tools/gcc-real'}]);self.assertEqual(pin.revalidate_pin(value,self.root),value);self.assertEqual(value['status'],'static-recording-unqualified');self.assertNotIn('/work/candidate.o',value['dependencies'])
 def test_startup_library_tools_specs_content_changes(self):
  for name in ('/gcc/lib/crti.o','/gcc/lib/crtn.o','/gcc/lib/crtbeginS.o','/gcc/lib/crtendS.o','/gcc/lib/libgcc.a','/gcc/lib/libgcc_s.so.1','/lib/libc.so.6','/tools/ld','/tools/plugin.so','/etc/gcc/specs'):
   with self.subTest(path=name):
    original=self.path(name).read_bytes();value=pin.collect_pin(self.manifest,self.root);self.path(name).write_bytes(original+b'changed')
    with self.assertRaises(l.Refusal):pin.revalidate_pin(value,self.root)
    self.path(name).write_bytes(original)
 def test_new_selection_configuration_and_symlink_target(self):
  value=pin.collect_pin(self.manifest,self.root);self.write('/gcc/lib/libc.so',b'\x7fELF preferred libc')
  with self.assertRaises(l.Refusal):pin.revalidate_pin(value,self.root)
  self.path('/gcc/lib/libc.so').unlink();self.write('/etc/gcc/new.specs',b'new config')
  with self.assertRaises(l.Refusal):pin.revalidate_pin(value,self.root)
  self.path('/etc/gcc/new.specs').unlink();self.write('/tools/gcc-other',b'\x7fELF inert tool');self.path('/usr/bin/gcc').unlink();self.path('/usr/bin/gcc').symlink_to('/tools/gcc-other')
  with self.assertRaises(l.Refusal):pin.revalidate_pin(value,self.root)
 def test_response_files_and_cycles(self):
  self.write('/work/inner.rsp',shlex.join(self.argv[1:]).encode());self.write('/work/outer.rsp',b'@/work/inner.rsp');self.argv=[self.argv[0],'@/work/outer.rsp'];self.record();value=pin.collect_pin(self.manifest,self.root);self.assertIn('/work/inner.rsp',value['dependencies']);self.path('/work/inner.rsp').write_bytes(self.path('/work/inner.rsp').read_bytes()+b' --unknown')
  with self.assertRaises(l.Refusal):pin.revalidate_pin(value,self.root)
  self.write('/work/inner.rsp',b'@/work/outer.rsp')
  with self.assertRaises(l.Refusal):pin.collect_pin(self.manifest,self.root)
 def test_script_include_search_and_recursion(self):
  self.write('/extra/libactual.a',b'!<arch>\ninert');self.write('/lib/included.ld',b'SEARCH_DIR("=/extra") INPUT ( -lactual )');self.write('/lib/libc.so',b'INCLUDE /lib/included.ld GROUP ( /lib/libc.so.6 )');value=pin.collect_pin(self.manifest,self.root);self.assertIn('/extra/libactual.a',value['dependencies']);self.write('/lib/included.ld',b'INCLUDE /lib/libc.so')
  with self.assertRaises(l.Refusal):pin.collect_pin(self.manifest,self.root)
 def test_malformed_unknown_unresolved_and_missing(self):
  for text in (b'GROUP ( /missing )',b'GROUP ( /lib/libc.so.6',b'SECTIONS { .text : {} }',b'INPUT()',b'/* unterminated',b'OUTPUT_FORMAT(elf32-i386) INPUT(/lib/libc.so.6)'):
   with self.subTest(script=text):
    self.write('/lib/libc.so',text)
    with self.assertRaises((l.Refusal,FileNotFoundError)):pin.collect_pin(self.manifest,self.root)
  self.write('/lib/libc.so',b'\x7fELF inert libc');self.write('/gcc/lib/libgcc.a',b'!<thin>\ninert')
  with self.assertRaises(l.Refusal):pin.collect_pin(self.manifest,self.root)
  self.write('/gcc/lib/libgcc.a',b'!<arch>\n');self.argv.remove('/gcc/lib/crtn.o');self.record()
  with self.assertRaises(l.Refusal):pin.collect_pin(self.manifest,self.root)
 def test_command_generated_and_schema_refusals(self):
  for arg in ('--unknown','-rpath=/ambient','-plugin-opt=unreviewed'):
   self.argv.append(arg);self.record()
   with self.assertRaises(l.Refusal):pin.collect_pin(self.manifest,self.root)
   self.argv.pop()
  self.record()
  for field,item in [('driverArgv','-nostdlib'),('generatedFiles','/lib/libc.so')]:
   altered=copy.deepcopy(self.manifest);altered[field].append(item)
   with self.assertRaises(l.Refusal):pin.collect_pin(altered,self.root)
  with self.assertRaises(l.Refusal):pin.revalidate_pin({'schemaVersion':2},self.root)
  altered=copy.deepcopy(self.manifest);altered['dryRun']+='unrecognized GCC warning\n'
  with self.assertRaises(l.Refusal):pin.collect_pin(altered,self.root)
 def test_script_addition_unselected_directory_addition_and_static_selection(self):
  value=pin.collect_pin(self.manifest,self.root)
  self.write('/lib/additional.so',b'\x7fELF new input')
  self.path('/lib/libc.so').write_bytes(self.path('/lib/libc.so').read_bytes()+b' INPUT(/lib/additional.so)')
  with self.assertRaises(l.Refusal):pin.revalidate_pin(value,self.root)
  self.write('/gcc/lib/libgcc_s.a',b'!<arch>\ninert static gcc_s')
  self.argv.insert(self.argv.index('-lgcc_s'),'-Bstatic');self.record()
  result=pin.collect_pin(self.manifest,self.root)
  selection=[x for x in result['implicitLinkClosure']['selections'] if x['request']=='-lgcc_s'][0]
  self.assertEqual(selection['selected'],'/gcc/lib/libgcc_s.a');self.assertTrue(selection['static'])
 def test_symlink_dotdot_exact_paths_and_changed_real_input(self):
  self.write('/tools/adjacent',b'\x7fELF lexical wrong input')
  for target in ('target','target2'):
   self.path('/'+target+'/deep').mkdir(parents=True)
   self.write('/'+target+'/adjacent',b'\x7fELF '+target.encode())
  alias=self.path('/tools/alias');alias.symlink_to('../target/deep')
  spelling='/tools/alias/../adjacent'
  self.argv.insert(-1,spelling);self.record()
  value=pin.collect_pin(self.manifest,self.root)
  row=value['implicitLinkClosure']['files'][spelling]
  self.assertEqual(row['realpath'],'/target/adjacent');self.assertTrue(row['symlinks'])
  before=self.path(spelling).read_bytes()
  alias.unlink();alias.symlink_to('../target2/deep')
  self.assertNotEqual(before,self.path(spelling).read_bytes())
  with self.assertRaises(l.Refusal):pin.revalidate_pin(value,self.root)
 def test_symlink_dotdot_search_response_and_script_paths(self):
  for target in ('target','target2'):
   self.path('/'+target+'/deep').mkdir(parents=True)
   for child in self.path('/gcc/lib').iterdir():self.write('/'+target+'/lib/'+child.name,child.read_bytes())
   self.write('/'+target+'/args.rsp',shlex.join(self.argv[1:]).encode())
   self.write('/'+target+'/extra.ld',b'INPUT(/lib/libc.so.6)')
  alias=self.path('/tools/alias');alias.symlink_to('../target/deep')
  original=list(self.argv)
  for kind in ('search','response','script'):
   with self.subTest(kind=kind):
    self.argv=list(original)
    if kind=='search':self.argv[self.argv.index('-L/gcc/lib')]='-L/tools/alias/../lib'
    elif kind=='response':self.argv=[self.argv[0],'@/tools/alias/../args.rsp']
    else:self.argv[-1:-1]=['-T','/tools/alias/../extra.ld']
    self.record();value=pin.collect_pin(self.manifest,self.root)
    self.assertTrue(any(row['symlinks'] for row in value['implicitLinkClosure']['files'].values() if '/alias/../' in row['logicalPath']))
    alias.unlink();alias.symlink_to('../target2/deep')
    with self.assertRaises(l.Refusal):pin.revalidate_pin(value,self.root)
    alias.unlink();alias.symlink_to('../target/deep')
 def test_static_state_reaches_direct_include_group_and_as_needed_scripts(self):
  self.write('/lib/libnested.so',b'\x7fELF dynamic nested')
  self.write('/lib/libnested.a',b'!<arch>\nstatic nested')
  for included in (False,True):
   with self.subTest(included=included):
    if included:
     self.write('/lib/outer.ld',b'INCLUDE /lib/inner.ld')
     self.write('/lib/inner.ld',b'GROUP(AS_NEEDED(-lnested))')
    else:self.write('/lib/outer.ld',b'INPUT(-lnested)')
    original=list(self.argv)
    self.argv[-1:-1]=['--push-state','-Bstatic','/lib/outer.ld','--pop-state','/lib/outer.ld'];self.record()
    value=pin.collect_pin(self.manifest,self.root)
    nested=[row for row in value['implicitLinkClosure']['selections'] if row['request']=='-lnested']
    self.assertEqual([(row['static'],row['selected']) for row in nested],[(True,'/lib/libnested.a'),(False,'/lib/libnested.so')])
    self.argv=original
 def test_known_file_byte_count_and_small_text_overflow_do_not_open(self):
  self.write('/work/eight',b'12345678');self.write('/work/twelve',b'123456789012')
  resolver=l.Resolver(self.root)
  with patch.object(l,'MAX_BYTES',16):
   resolver.file('/work/eight')
   with patch.object(l.os,'open',side_effect=AssertionError('known overflow must not open')):
    with self.assertRaises(l.Refusal):resolver.file('/work/twelve')
   resolver.file('/work/eight')
   self.assertEqual(resolver.io_bytes,16)
   with patch.object(l.os,'open',side_effect=AssertionError('shared read work must be bounded')):
    with self.assertRaises(l.Refusal):resolver.file('/work/eight')
  resolver=l.Resolver(self.root);resolver.file('/work/eight')
  with patch.object(l,'MAX_FILES',1),patch.object(l.os,'open',side_effect=AssertionError('file count before open')):
   with self.assertRaises(l.Refusal):resolver.file('/work/twelve')
  with patch.object(l,'MAX_TEXT',4),patch.object(l.os,'open',side_effect=AssertionError('text cap before open')):
   with self.assertRaises(l.Refusal):l.Resolver(self.root).response(['@/work/eight'])
 def test_directory_limit_stops_enumeration_before_sort(self):
  for i in range(20):self.write('/work/many/'+str(i),b'x')
  original=l.os.scandir;seen=[]
  @contextlib.contextmanager
  def instrumented(path):
   with original(path) as entries:
    def counted():
     for child in entries:
      seen.append(child.name);yield child
    yield counted()
  with patch.object(l,'MAX_FILES',4),patch.object(l.os,'scandir',instrumented):
   with self.assertRaises(l.Refusal):l.Resolver(self.root).directory('/work/many')
  self.assertEqual(len(seen),5)
 def test_response_words_and_shared_work_exact_and_one_over(self):
  self.write('/work/four.rsp',b'a b c d');opened=[];original=l.os.open
  def instrumented(path,*args,**kwargs):
   if str(path)=='four.rsp':opened.append(str(path))
   return original(path,*args,**kwargs)
  with patch.object(l,'MAX_WORDS',4),patch.object(l.os,'open',instrumented):
   self.assertEqual(l.Resolver(self.root).response(['@/work/four.rsp']),['a','b','c','d'])
   opened.clear()
   with self.assertRaises(l.Refusal):l.Resolver(self.root).response(['@/work/four.rsp']*3)
   self.assertEqual(opened,['four.rsp'])
  resolver=l.Resolver(self.root)
  with patch.object(l,'MAX_WORK',3):
   self.assertEqual(resolver.response(['a','b','c']),['a','b','c'])
   with self.assertRaises(l.Refusal):resolver.response(['d'])
   self.assertEqual(resolver.expanded_words,3)
  with patch.object(l,'MAX_WORDS',4):
   self.assertEqual(l.recorded_command(' /tools/collect2 a b c'),['/tools/collect2','a','b','c'])
   with self.assertRaises(l.Refusal):l.recorded_command(' /tools/collect2 a b c d')
 def test_manifest_raw_parse_and_typed_roots_refuse_before_resolution(self):
  self.write('/work/manifest.json',json.dumps(self.manifest).encode())
  self.assertEqual(pin.load_manifest(self.path('/work/manifest.json')),self.manifest)
  with patch.object(l,'MAX_MANIFEST',16),patch.object(pin.os,'read',side_effect=AssertionError('oversize JSON must not read')),patch.object(pin.json,'loads',side_effect=AssertionError('oversize JSON must not parse')):
   with self.assertRaises(l.Refusal):pin.load_manifest(self.path('/work/manifest.json'))
  self.write('/work/manifest.json',b'{"schemaVersion":3,"schemaVersion":3}')
  with self.assertRaises(l.Refusal):pin.load_manifest(self.path('/work/manifest.json'))
  for kind in ('unknown','roots','path','command'):
   altered=copy.deepcopy(self.manifest)
   if kind=='unknown':altered['unexpected']=True
   elif kind=='roots':altered['specs']=['/x']*129
   elif kind=='path':altered['tools']['ld']=12
   else:altered['dryRun']='x'* (l.MAX_TEXT+1)
   with patch.object(l.Resolver,'file',side_effect=AssertionError('typed validation before filesystem')):
    with self.assertRaises(l.Refusal):pin.collect_pin(altered,self.root)
 def test_closed_schema_roundtrip_and_v2_unknown_forms(self):
  import importlib.metadata
  import fastjsonschema
  schema=json.loads((SOURCE/'contracts/toolchain-pin-schema.json').read_bytes())
  validator=fastjsonschema.compile(schema)
  value=pin.collect_pin(self.manifest,self.root);validator(value)
  self.assertEqual(importlib.metadata.version('fastjsonschema'),'2.22.2')
  for target in ('top','closure','manifest','file'):
   changed=copy.deepcopy(value)
   where={'top':changed,'closure':changed['implicitLinkClosure'],'manifest':changed['implicitLinkClosure']['manifest'],'file':next(iter(changed['implicitLinkClosure']['files'].values()))}[target]
   where['unknown']=True
   with self.assertRaises(fastjsonschema.JsonSchemaException):validator(changed)
  value['schemaVersion']=2
  with self.assertRaises(fastjsonschema.JsonSchemaException):validator(value)
 def test_import_no_subprocess_and_unknown_pin_fields(self):
  value=pin.collect_pin(self.manifest,self.root);value['unexpected']=True
  with self.assertRaises(l.Refusal):pin.revalidate_pin(value,self.root)
  spec=importlib.util.spec_from_file_location('second_pin',SPEC.origin);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);self.assertTrue(callable(module.revalidate_pin))

 def test_monitor_and_inspection_are_nonempty_operational_not_qualified(self):
  value=pin.collect_pin(self.manifest,self.root)
  self.assertEqual(value['status'],'static-recording-unqualified')
  for field in ['monitorClosure','inspectionClosure']:
   closure=value[field];self.assertEqual(closure['selectionStatus'],'declared-selection-native-unqualified')
   self.assertEqual(set(closure['elfGraph']),{'/runtime/monitor' if field=='monitorClosure' else '/bin/bash','/runtime/ld-runtime.so','/runtime/libfixture.so.1','/runtime/libother.so.1'})
  for name in ['/runtime/monitor','/public/worker_exec_proof.py','/public/protocol.json','/public/build_worker_monitor.py','/headers/stdio.h','/etc/ld.so.cache','/bin/bash','/usr/bin/ldd','/runtime/libother.so.1']:
   self.assertIn(name,value['dependencies'])
  self.assertEqual(value['monitorClosure']['buildInputStatus'],'recorded-build-inputs-unqualified')
  self.assertEqual(json.loads(self.path('/public/provision.json').read_bytes())['dependencies'],[])
  self.assertTrue(value['monitorClosure']['elfGraph']['/runtime/monitor']['needed'])
 def test_missing_empty_malformed_operational_records_fail_before_file_read(self):
  cases=[]
  for field in ['monitor','inspection']:
   record=copy.deepcopy(self.manifest);del record[field];cases.append(record)
   for replacement in [[],None,True,{}, {'schemaVersion':True}]:
    record=copy.deepcopy(self.manifest);record[field]=replacement;cases.append(record)
   for replacement in [[],{},[{'soname':'libx','path':'relative'}],[{'soname':'libx','path':'/runtime/libx'}]*2]:
    record=copy.deepcopy(self.manifest);record[field]['runtimeLibraries']=replacement;cases.append(record)
  for key in ['buildInputs','runtimeLibraries']:
   record=copy.deepcopy(self.manifest);record['monitor'][key]=[];cases.append(record)
  record=copy.deepcopy(self.manifest);record['monitor']['buildInputs']=record['monitor']['buildInputs'][1:];cases.append(record)
  record=copy.deepcopy(self.manifest);record['monitor']['buildInputs'][0]['role']='claimed-complete';cases.append(record)
  record=copy.deepcopy(self.manifest);record['inspection']['cachePath']='/etc';cases.append(record)
  with patch.object(l.Resolver,'file',side_effect=AssertionError('typed validation must precede filesystem reads')):
   for record in cases:
    with self.subTest(record=record),self.assertRaises(l.Refusal):pin.collect_pin(record,self.root)
 def test_exact_transitive_graph_rejects_missing_extra_wrong_soname_and_interpreter(self):
  for field in ['monitor','inspection']:
   record=copy.deepcopy(self.manifest);record[field]['runtimeLibraries'].pop()
   with self.assertRaisesRegex(l.Refusal,'transitive'):pin.collect_pin(record,self.root)
   record=copy.deepcopy(self.manifest);record[field]['runtimeLibraries'].append({'soname':'unused.so','path':'/runtime/unused.so'})
   with self.assertRaisesRegex(l.Refusal,'unreachable'):pin.collect_pin(record,self.root)
  original=self.path('/runtime/libother.so.1').read_bytes()
  self.write('/runtime/libother.so.1',authored_elf(soname='wrong.so'))
  with self.assertRaisesRegex(l.Refusal,'SONAME'):pin.collect_pin(self.manifest,self.root)
  self.write('/runtime/libother.so.1',original);self.path('/runtime/ld-runtime.so').unlink()
  with self.assertRaises(FileNotFoundError):pin.collect_pin(self.manifest,self.root)
 def test_elf_metadata_rejects_ranges_mappings_duplicates_search_and_unknowns(self):
  original=authored_elf(['libfixture.so.1'],interpreter='/runtime/ld-runtime.so')
  cases=[]
  def altered(offset,fmt,*values):
   raw=bytearray(original);struct.pack_into(fmt,raw,offset,*values);cases.append(bytes(raw))
  altered(5,'B',2);altered(18,'H',3);altered(56,'H',129)
  altered(120+16,'Q',0x700000) # PT_DYNAMIC virtual address is outside PT_LOAD.
  altered(120+8,'Q',0x210) # File offset disagrees with its virtual mapping.
  altered(0x210,'q',15);altered(0x210,'q',29);altered(0x210,'q',0x7fffffff)
  altered(0x218,'Q',0x99999999) # Unmapped DT_STRTAB.
  altered(0x228,'Q',2**64-1) # String size before materialization.
  altered(0x238,'Q',2**64-1) # Nonzero DT_NULL value does not create input authority.
  raw=bytearray(original);struct.pack_into('<qQ',raw,0x230,5,0x400300);cases.append(bytes(raw))
  cases.extend([original[:64],b'not an ELF'])
  for raw in cases:
   with self.subTest(raw=raw[:24]),self.assertRaises(l.Refusal):pin.monitor_inputs.elf(raw,l)
 def test_elf_self_interpreter_dynamic_flags_and_duplicate_metadata_refuse(self):
  raw=authored_elf(['libfixture.so.1'],interpreter='/runtime/monitor')
  original=self.path('/runtime/monitor').read_bytes();self.write('/runtime/monitor',raw)
  with self.assertRaisesRegex(l.Refusal,'dynamic operational'):pin.collect_pin(self.manifest,self.root)
  self.write('/runtime/monitor',original)
  for tag,value in [(30,1),(0x6ffffffb,0x800),(5,0x400300)]:
   raw=bytearray(original)
   # Extend dynamic table by one slot, retaining a final zero terminator.
   struct.pack_into('<Q',raw,120+32,80);struct.pack_into('<Q',raw,120+40,80)
   struct.pack_into('<qQ',raw,0x230,tag,value)
   with self.subTest(tag=tag),self.assertRaises(l.Refusal):pin.monitor_inputs.elf(bytes(raw),l)
 def test_cache_byte_cap_and_graph_count_stop_before_payload_open(self):
  resolver=l.Resolver(self.root)
  with patch.object(l.os,'open',side_effect=AssertionError('cache cap before open')):
   with self.assertRaisesRegex(l.Refusal,'role byte'):resolver.file('/etc/ld.so.cache',maximum=1)
  record=self.manifest['monitor'];resolver=l.Resolver(self.root)
  original=l.os.open
  def opened(name,*args,**kwargs):
   if name in ('ld-runtime.so','libfixture.so.1'):raise AssertionError('graph count before next open')
   return original(name,*args,**kwargs)
  with patch.object(pin.monitor_inputs,'MAX_IMAGES',1),patch.object(l.os,'open',opened):
   # Count admission rejects an inventory of two before any graph file read.
   with self.assertRaises(l.Refusal):pin.monitor_inputs.graph(record['binaryPath'],record['runtimeLibraries'],resolver,l,{})
 def test_all_operational_input_classes_are_revalidated_and_equal_byte_replacement_refuses(self):
  names=['/runtime/monitor','/public/worker_exec_monitor.c','/public/worker_exec_proof.py','/public/protocol.json','/public/build_worker_monitor.py','/public/provision.json','/headers/stdio.h','/etc/ld.so.cache','/bin/bash','/usr/bin/ldd','/runtime/libfixture.so.1','/runtime/libother.so.1','/runtime/ld-runtime.so']
  for name in names:
   with self.subTest(name=name):
    value=pin.collect_pin(self.manifest,self.root);old=self.path(name).read_bytes();self.write(name,old+b'changed')
    with self.assertRaises((l.Refusal,ValueError)):pin.revalidate_pin(value,self.root)
    self.write(name,old)
  name='/headers/stdio.h';value=pin.collect_pin(self.manifest,self.root);target=self.path(name);fd=os.open(target,os.O_RDONLY)
  try:
   other=target.with_name('replacement');other.write_bytes(target.read_bytes());self.assertNotEqual(os.fstat(fd).st_ino,other.stat().st_ino);os.replace(other,target)
   with self.assertRaisesRegex(l.Refusal,'drift'):pin.revalidate_pin(value,self.root)
  finally:os.close(fd)
 def test_monitor_provisioning_hash_command_and_schema_cannot_mint_authority(self):
  original=self.path('/public/provision.json').read_bytes()
  for key,replacement in [('binarySha256','0'*64),('sourceSha256','0'*64),('status','native-qualified'),('buildCommand',[]),('dependencies',[{}]),('unexpected',True)]:
   value=json.loads(original);value[key]=replacement;self.write('/public/provision.json',json.dumps(value).encode())
   with self.subTest(key=key),self.assertRaises(l.Refusal):pin.collect_pin(self.manifest,self.root)
  self.write('/public/provision.json',b'{"schemaVersion":1,"schemaVersion":1}')
  with self.assertRaises(l.Refusal):pin.collect_pin(self.manifest,self.root)
 def test_inspection_shebang_script_cache_and_bash_substitution_refuse(self):
  original=self.path('/usr/bin/ldd').read_bytes()
  for raw in [b'#!/usr/bin/env bash\n',b'#!/bin/bash -p\n',b'#!/bin/sh\n',b'#!/bin/bash\r\n',b'#!/bin/bash']:
   self.write('/usr/bin/ldd',raw)
   with self.assertRaisesRegex(l.Refusal,'shebang'):pin.collect_pin(self.manifest,self.root)
  self.write('/usr/bin/ldd',original);value=pin.collect_pin(self.manifest,self.root);self.write('/etc/ld.so.cache',b'changed selector bytes')
  with self.assertRaises(l.Refusal):pin.revalidate_pin(value,self.root)
  self.path('/etc/ld.so.cache').unlink();self.path('/etc/ld.so.cache').symlink_to('/public/protocol.json')
  with self.assertRaisesRegex(l.Refusal,'cache'):pin.collect_pin(self.manifest,self.root)
 def test_operational_role_count_and_byte_bounds_precede_descriptor_open(self):
  self.write('/work/role',b'12345')
  with patch.object(l.os,'open',side_effect=AssertionError('role cap must precede open')):
   with self.assertRaisesRegex(l.Refusal,'role byte'):l.Resolver(self.root).file('/work/role',maximum=4)
  self.assertEqual(l.Resolver(self.root).file('/work/role',maximum=5),b'12345')
  record=copy.deepcopy(self.manifest);record['monitor']['runtimeLibraries']*=65
  with patch.object(l.Resolver,'file',side_effect=AssertionError('count cap before file')):
   with self.assertRaises(l.Refusal):pin.collect_pin(record,self.root)
  with patch.object(pin.monitor_inputs,'MAX_IMAGE',1023):
   original=l.os.open
   def opened(path,*args,**kwargs):
    if path=='monitor':raise AssertionError('known ELF cap must precede open')
    return original(path,*args,**kwargs)
   with patch.object(l.os,'open',opened),self.assertRaisesRegex(l.Refusal,'role byte'):pin.collect_pin(self.manifest,self.root)
 def test_descriptor_replacement_and_partial_open_failure_recover(self):
  self.write('/work/stable',b'original');target=self.path('/work/stable');original=l.os.open;before=len(os.listdir('/proc/self/fd'))
  def replaced(name,*args,**kwargs):
   if name=='stable':
    other=target.with_name('other');other.write_bytes(b'replaced');os.replace(other,target)
   return original(name,*args,**kwargs)
  with patch.object(l.os,'open',replaced),self.assertRaisesRegex(l.Refusal,'before descriptor'):l.Resolver(self.root).file('/work/stable')
  self.assertEqual(before,len(os.listdir('/proc/self/fd')))
  def failed(name,*args,**kwargs):
   if name=='stable':raise OSError('authored open failure')
   return original(name,*args,**kwargs)
  with patch.object(l.os,'open',failed),self.assertRaises(OSError):l.Resolver(self.root).file('/work/stable')
  self.assertEqual(before,len(os.listdir('/proc/self/fd')))
 def test_fixed_operational_api_refuses_absent_hash_mismatch_and_requires_revalidation(self):
  base=self.path('/public');folder=base/'toolchain-001';folder.mkdir();profile={'toolchainEnvironmentPinSha256':'a'*64}
  with patch.object(pin,'BASE',base),patch.object(pin,'revalidate_pin',side_effect=l.Refusal('authored revalidation refusal')) as validate:
   with self.assertRaises(l.Refusal):pin.load_monitor_binding(profile)
   self.assertFalse(validate.called)
   raw=json.dumps(pin.collect_pin(self.manifest,self.root)).encode();(folder/'environment-pin.json').write_bytes(raw)
   with self.assertRaisesRegex(l.Refusal,'byte hash'):pin.load_inspection_binding(profile)
   self.assertFalse(validate.called)
   profile['toolchainEnvironmentPinSha256']=hashlib.sha256(raw).hexdigest()
   with self.assertRaisesRegex(l.Refusal,'revalidation'):pin.load_monitor_binding(profile)
   validate.assert_called_once();self.assertEqual(validate.call_args.args[1],Path('/'))
  with patch.object(pin,'BASE',base),patch.object(pin,'revalidate_pin',return_value=pin.collect_pin(self.manifest,self.root)):
   with self.assertRaisesRegex(l.Refusal,'fixed public'):pin.load_monitor_binding(profile)
 def test_binding_views_include_complete_canonical_runtime_and_inspection_inputs(self):
  value=pin.collect_pin(self.manifest,self.root)
  # Pure normalization check only; the separate gate test above proves mandatory revalidation.
  with patch.object(pin,'_load_operational',return_value=(value,'b'*64)):
   monitor=pin.load_monitor_binding({});inspection=pin.load_inspection_binding({})
  self.assertEqual(monitor['binaryPath'],'/runtime/monitor')
  self.assertEqual({row['path'] for row in monitor['dependencies']},{'/runtime/ld-runtime.so','/runtime/libfixture.so.1','/runtime/libother.so.1','/etc/ld.so.cache'})
  self.assertEqual({row['path'] for row in inspection['dependencies']},{'/bin/bash','/usr/bin/ldd','/runtime/ld-runtime.so','/runtime/libfixture.so.1','/runtime/libother.so.1','/etc/ld.so.cache'})
  self.assertEqual(inspection['environmentPinSha256'],'b'*64)
 def test_new_closed_schema_refuses_each_operational_unknown_missing_and_native_claim(self):
  import fastjsonschema
  validate=fastjsonschema.compile(json.loads((SOURCE/'contracts/toolchain-pin-schema.json').read_bytes()));value=pin.collect_pin(self.manifest,self.root);validate(value)
  for field in ['monitorClosure','inspectionClosure']:
   bad=copy.deepcopy(value);del bad[field]
   with self.assertRaises(fastjsonschema.JsonSchemaException):validate(bad)
   for sub in ['record','elfGraph','files']:
    bad=copy.deepcopy(value)
    if sub=='record':bad[field][sub]['unexpected']=True
    elif sub=='elfGraph':next(iter(bad[field][sub].values()))['unexpected']=True
    else:next(iter(bad[field][sub].values()))['identity']['unexpected']=True
    with self.assertRaises(fastjsonschema.JsonSchemaException):validate(bad)
  bad=copy.deepcopy(value);bad['status']='native-qualified'
  with self.assertRaises(fastjsonschema.JsonSchemaException):validate(bad)



class X86PltMetadataTests(unittest.TestCase):
 def image(self, tags=None, flags=5, filesz=1024, memsz=1024, overlap=False):
  raw=bytearray(authored_elf(needed=['libfixture.so.1']))
  rows=[(1,1),(5,0x400300),(10,17)]+(tags if tags is not None else [(0x70000000,0x400380),(0x70000001,64),(0x70000003,16)])+[(0,0)]
  struct.pack_into('<I',raw,68,flags)
  struct.pack_into('<QQ',raw,96,filesz,memsz)
  struct.pack_into('<QQ',raw,152,len(rows)*16,len(rows)*16)
  for i,row in enumerate(rows):struct.pack_into('<qQ',raw,0x200+i*16,*row)
  if overlap:
   struct.pack_into('<H',raw,56,3)
   struct.pack_into('<IIQQQQQQ',raw,176,1,5,0x380,0x400380,0x400380,64,64,16)
  return bytes(raw)
 def test_valid_optional_metadata_preserves_graph_result(self):
  self.assertEqual(pin.monitor_inputs.elf(self.image(),l),pin.monitor_inputs.elf(authored_elf(needed=['libfixture.so.1']),l))
 def test_missing_duplicate_and_unknown_tags_refuse(self):
  good=[(0x70000000,0x400380),(0x70000001,64),(0x70000003,16)]
  cases=[good[:i]+good[i+1:] for i in range(3)]+[good+[good[i]] for i in range(3)]+[good+[(tag,16)] for tag in (0x70000002,0x70000004,0x70001234)]
  for rows in cases:
   with self.subTest(rows=rows),self.assertRaises(l.Refusal):pin.monitor_inputs.elf(self.image(rows),l)
 def test_extent_alignment_and_mapping_refuse(self):
  for address,size,entry in [(0,64,16),(0x400380,0,16),(0x400380,64,0),(0x400380,64,3),(0x400380,8,16),(0x400380,65,16),(0x400381,64,16),((1<<64)-16,32,16),(0x400400,64,16),(0x4003f0,32,16)]:
   with self.subTest(address=address,size=size,entry=entry),self.assertRaises(l.Refusal):pin.monitor_inputs.elf(self.image([(0x70000000,address),(0x70000001,size),(0x70000003,entry)]),l)
  for kwargs in [{'flags':4},{'filesz':0x380,'memsz':1024},{'overlap':True}]:
   with self.subTest(kwargs=kwargs),self.assertRaises(l.Refusal):pin.monitor_inputs.elf(self.image(**kwargs),l)

if __name__=='__main__':unittest.main()
