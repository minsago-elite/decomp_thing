"""Pure filesystem fixtures; native subprocess paths are forbidden."""
import copy,contextlib,importlib.util,json,shlex,subprocess,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
SOURCE=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location('pin_environment',SOURCE/'toolchain-001/pin_environment.py')
pin=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(pin)
l=pin.link_inputs

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
  self.manifest={'schemaVersion':3,'driverArgv':['/usr/bin/gcc','-shared','-Wl,-z,relro,-z,now,-z,noexecstack,--no-undefined','/work/candidate.o','-o','/work/libcandidate.so'],'workingDirectory':'/work','environment':{'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C','TMPDIR':'/tmp'},'tools':{'gcc':'/usr/bin/gcc','cc1':'/tools/cc1','collect2':'/tools/collect2','as':'/tools/as','ld':'/tools/ld'},'specs':['/etc/gcc/specs'],'configurationRoots':['/etc/gcc'],'generatedFiles':['/work/candidate.o','/work/libcandidate.so'],'dryRun':''};self.record()
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
   with patch.object(Path,'open',side_effect=AssertionError('known overflow must not open')):
    with self.assertRaises(l.Refusal):resolver.file('/work/twelve')
   resolver.file('/work/eight')
   self.assertEqual(resolver.io_bytes,16)
   with patch.object(Path,'open',side_effect=AssertionError('shared read work must be bounded')):
    with self.assertRaises(l.Refusal):resolver.file('/work/eight')
  resolver=l.Resolver(self.root);resolver.file('/work/eight')
  with patch.object(l,'MAX_FILES',1),patch.object(Path,'open',side_effect=AssertionError('file count before open')):
   with self.assertRaises(l.Refusal):resolver.file('/work/twelve')
  with patch.object(l,'MAX_TEXT',4),patch.object(Path,'open',side_effect=AssertionError('text cap before open')):
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
  self.write('/work/four.rsp',b'a b c d');opened=[];original=Path.open
  def instrumented(path,*args,**kwargs):opened.append(path.name);return original(path,*args,**kwargs)
  with patch.object(l,'MAX_WORDS',4),patch.object(Path,'open',instrumented):
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

if __name__=='__main__':unittest.main()
