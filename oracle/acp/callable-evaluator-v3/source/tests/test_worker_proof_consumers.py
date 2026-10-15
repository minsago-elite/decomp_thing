"""Pure consumer controls: every native operation is mocked, never launched."""
import copy
import json
from pathlib import Path
import runpy
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import interface_gate_v3 as gate
from test_identity_graph import completed_result

ROOT = Path(gate.__file__).parent


def inspection_fixture(root):
    binding = {'environmentPinSha256':'a'*64,'dependencies':[]}
    for role, content in (('bash',b'\x7fELFinert'), ('script',b'#!/bin/bash\n# inert'), ('cache',b'inert cache')):
        path = root / role
        path.write_bytes(content)
        binding[role+'Path'] = str(path)
        binding[role+'Sha256'] = gate.digest(path)
        binding['dependencies'].append({'path':str(path),'sha256':gate.digest(path)})
    return binding


def _producer_execution(inputs, *, phase, target=None, profile_sha=None, stdout=b'', exit_code=0):
    """Authored raw proof with separate executable and independently supplied inputs."""
    import hashlib
    import bounded_runtime as runtime
    if profile_sha is None:profile_sha=gate.load_profile_with_digest()[1]
    target=target or ('/usr/lib/llvm/23/bin/clang++',{'device':7,'inode':8,'mode':0o755,'sha256':'0'*64})
    name,row=target
    value=completed_result(stdout=stdout,exit_code=exit_code,target_sha=row['sha256'],phase=phase)
    pins=value['launchInputPins'];pins.pop('/authored/worker',None);pins.update(copy.deepcopy(inputs));pins[name]=copy.deepcopy(row)
    pins[str(runtime.BASE/'contracts/candidate-build-profile.json')]['sha256']=profile_sha
    value['bounds']['profileSha256']=profile_sha
    binding=value['workerProofBindings'];binding['expected'].update(targetDevice=row['device'],targetInode=row['inode'])
    binding['targetSha256']=row['sha256']
    binding['launchPinsSha256']=hashlib.sha256(json.dumps(pins,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()
    records=[json.loads(line)for line in value['workerProofRaw'].splitlines()]
    records[0].update(ed=row['device'],ei=row['inode'],od=row['device'],oi=row['inode'])
    value['workerProofRaw']=b''.join((json.dumps(record,separators=(',',':'))+'\n').encode()for record in records)
    value['workerProof']['proofSha256']=hashlib.sha256(value['workerProofRaw']).hexdigest()
    return value


class WorkerProofConsumers(unittest.TestCase):
    def test_probe_fallback_retains_before_after_digest_caps_and_same_absolute_end(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            work=Path(directory);source=work/'source.c';helper=work/'helper'
            for mutation in (None,'source','helper'):
                source.write_bytes(b'authored source');helper.write_bytes(b'authored helper')
                helper_sha=gate.digest(helper);calls=[];real_digest=gate.digest
                def hashing(path,**kwargs):calls.append((path,kwargs));return real_digest(path,**kwargs)
                refusal={'schemaVersion':3,'status':'refused','diagnostics':['unsupported-integer-builtin-kind']}
                result=completed_result(json.dumps(refusal).encode(),exit_code=2,target_sha=helper_sha,phase='probe')
                def run(*args,**kwargs):
                    if mutation is not None:(source if mutation=='source' else helper).write_bytes(b'changed input')
                    return result
                with self.subTest(mutation=mutation),patch.object(gate.time,'monotonic',return_value=0), \
                        patch.object(gate,'digest',side_effect=hashing),patch.object(gate,'bounded_run',side_effect=run) as runner, \
                        patch.object(gate,'probe_command',return_value=['NOT-EXECUTED']):
                    if mutation is None:
                        value=gate.probe(source,helper,work,{},deadline=10.0)
                        self.assertEqual('refused',value['status']);self.assertTrue(value['inputBindings']['inputsUnchanged'])
                    else:
                        with self.assertRaisesRegex(ValueError,'inputs changed') as caught:gate.probe(source,helper,work,{},deadline=10.0)
                        self.assertIs(caught.exception.bounded_result,result)
                expected=[source,helper,source]+([] if mutation=='source' else [helper])
                self.assertEqual(expected,[path for path,_ in calls])
                self.assertTrue(all(kwargs=={'maximum':16777216,'deadline':10.0} for _,kwargs in calls))
                self.assertEqual(10.0,runner.call_args.kwargs['phase_deadline'])
                self.assertEqual(10.0,runner.call_args.kwargs['timeout'])

    def test_probe_captured_handoff_does_not_add_fallback_pathname_hashes(self):
        import bounded_runtime as runtime
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            work=Path(directory);source=work/'source.c';source.write_bytes(b'authored source')
            helper=work/'helper';helper.write_bytes(b'authored helper')
            expected=runtime._pin_files((source,));reached=ValueError('authored handoff command reached')
            with patch.object(gate.time,'monotonic',return_value=0), \
                    patch.object(gate,'digest',side_effect=AssertionError('handoff must retain its physical pins')), \
                    patch.object(runtime,'_pin_files',wraps=runtime._pin_files) as pinned, \
                    patch.object(gate,'bounded_run',side_effect=AssertionError('no worker')), \
                    patch.object(gate,'probe_command',side_effect=reached) as command:
                with self.assertRaises(ValueError) as caught:gate.probe(source,helper,work,{},deadline=10.0,expected_inputs=expected)
            self.assertIs(caught.exception,reached)
            self.assertEqual([(expected,10.0),([helper],10.0),(expected,10.0)],[call.args for call in pinned.call_args_list])
            self.assertEqual(expected,command.call_args.kwargs['read_only_files'])

    def test_helper_build_rehashes_actual_source_schema_with_distinct_role_caps_and_no_new_end(self):
        build=runpy.run_path(str(ROOT/'toolchain-001/build_helper.py'),run_name='inert_import')['build']
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root=Path(directory);(root/'toolchain-001').mkdir();(root/'contracts').mkdir()
            source=root/'record_identity_probe.cpp';schema=root/'contracts/helper-schema.json'
            for mutation in (None,'source','schema'):
                source.write_bytes(b'authored source');schema.write_bytes(b'{}')
                calls=[];real_digest=gate.digest
                def hashing(path,**kwargs):calls.append((path,kwargs));return real_digest(path,**kwargs)
                from bounded_runtime import _pin_files
                result=_producer_execution(_pin_files([source]),phase='helper-build',exit_code=1)
                def run(*args,**kwargs):
                    if mutation is not None:(source if mutation=='source' else schema).write_bytes(b'changed')
                    return result
                with self.subTest(mutation=mutation),patch.dict(build.__globals__,ROOT=root,digest=hashing,
                        contained_command=Mock(return_value=['NOT-EXECUTED']),bounded_run=run):
                    if mutation is None:
                        value=build('not-published.json');self.assertFalse(value['publication']['published'])
                        self.assertFalse((root/'toolchain-001/record_identity_probe').exists())
                    else:
                        with self.assertRaisesRegex(ValueError,'source/schema drift'):build('refused-'+mutation+'.json')
                        self.assertFalse((root/'toolchain-001'/('refused-'+mutation+'.json')).exists())
                expected=[(source,{'maximum':16777216,'deadline':None}),(schema,{'maximum':65536,'deadline':None}),
                          (source,{'maximum':16777216,'deadline':None})]
                if mutation!='source':expected.append((schema,{'maximum':65536,'deadline':None}))
                self.assertEqual(expected,calls)

    def test_helper_schema_oversize_and_source_symlink_refuse_before_worker(self):
        build=runpy.run_path(str(ROOT/'toolchain-001/build_helper.py'),run_name='inert_import')['build']
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root=Path(directory);(root/'toolchain-001').mkdir();(root/'contracts').mkdir()
            source=root/'record_identity_probe.cpp';schema=root/'contracts/helper-schema.json'
            source.write_bytes(b'authored source');schema.write_bytes(b' '*65537)
            runner=Mock(side_effect=AssertionError('input refusal before worker'))
            with patch.dict(build.__globals__,ROOT=root,bounded_run=runner):
                with self.assertRaisesRegex(ValueError,'regular file byte bound'):build('oversize.json')
                schema.write_bytes(b'{}');source.unlink();source.symlink_to(schema)
                with self.assertRaises(OSError):build('symlink.json')
            runner.assert_not_called()
            self.assertFalse((root/'worker-work').exists())

    def test_owned_leaf_retains_unknown_and_preserves_primary_cleanup_errors(self):
        for prefix in ('helper-build-','helper-inspection-'):
            with tempfile.TemporaryDirectory(dir=ROOT) as directory:
                root=Path(directory)
                for raised in (False,True):
                    leaf=gate.owned_worker_leaf(root,prefix)
                    result=completed_result();result['cleanupVerified']=False
                    primary=ValueError('primary controller failure');primary.bounded_result=result
                    def runner():
                        if raised:raise primary
                        return result
                    with self.assertRaisesRegex(ValueError,'primary controller failure') as caught:
                        with leaf:
                            leaf.run(runner)
                            raise primary
                    self.assertIs(caught.exception,primary)
                    self.assertIs(primary.bounded_result,result)
                    self.assertTrue(leaf.path.is_dir())
                    self.assertFalse(primary.leafCleanup['deletionAttempted'])
                    self.assertEqual(primary.leafCleanup['identity']['inode'],leaf.path.stat().st_ino)
                leaf=gate.owned_worker_leaf(root,prefix)
                result=completed_result();primary=ValueError('primary');primary.bounded_result=result
                with patch.object(gate.shutil,'rmtree',side_effect=OSError('injected delete failure')):
                    with self.assertRaisesRegex(ValueError,'primary') as caught:
                        with leaf:
                            leaf.run(lambda:result)
                            raise primary
                self.assertIs(caught.exception,primary)
                self.assertIs(primary.bounded_result,result)
                self.assertIn('injected delete failure',primary.leafCleanup['secondaryError'])
                self.assertTrue(leaf.path.is_dir())

    def test_owned_leaf_success_prelaunch_and_stale_identity(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root=Path(directory)
            for launched in (False,True):
                with gate.owned_worker_leaf(root,'helper-build-') as leaf:
                    if launched:leaf.run(completed_result)
                    path=leaf.path
                self.assertFalse(path.exists())
            leaf=gate.owned_worker_leaf(root,'helper-inspection-')
            original=leaf.path.with_name(leaf.path.name+'-retained')
            with self.assertRaisesRegex(ValueError,'cleanup incomplete'):
                with leaf:
                    leaf.run(completed_result)
                    leaf.path.rename(original)
                    leaf.path.mkdir()
            self.assertTrue(original.is_dir())
            self.assertTrue(leaf.path.is_dir())

    def test_wrapper_success_without_worker_proof_is_incomplete(self):
        result = completed_result()
        for key in ('workerExecVerified', 'workerTerminationVerified'):
            bad = copy.deepcopy(result)
            bad[key] = False
            self.assertFalse(gate._complete_execution(bad))
        self.assertTrue(gate._complete_execution(result))
        self.assertTrue(gate._complete_execution(gate.public_result(result)))

    def test_exports_contain_exact_library_and_reject_unproved_worker(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            work = Path(directory)
            library = work / 'inert.so'
            library.write_bytes(b'inert')
            bad = completed_result()
            bad['workerExecVerified'] = False
            command = Mock(return_value=['NOT-EXECUTED'])
            with patch.object(gate, 'contained_command', command), patch.object(gate, 'bounded_run', return_value=bad) as runner:
                result = gate.export_inventory(library, 4, work, {})
            self.assertEqual(result['status'], 'unknown')
            command.assert_called_once_with(['/usr/bin/readelf', '--dyn-syms', '--wide', str(library)], work, read_only_files=(library,), environment={})
            self.assertEqual(runner.call_args.kwargs['phase'], 'elf-inspection')

    def test_helper_build_contains_only_explicit_source_and_rejects_wrapper_success(self):
        build = runpy.run_path(str(ROOT / 'toolchain-001/build_helper.py'), run_name='inert_import')['build']
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            work = root / 'toolchain-001'
            work.mkdir()
            source = root / 'record_identity_probe.cpp'
            source.write_text('// inert')
            (root/'contracts').mkdir()
            (root/'contracts/helper-schema.json').write_bytes(b'{}')
            command = Mock(return_value=['NOT-EXECUTED'])
            bad = completed_result()
            bad['workerTerminationVerified'] = False
            bad['cleanupVerified'] = False
            bad['rootReaped'] = False
            bad['finalAbsenceVerified'] = False
            bad['kernelScope']['finalAbsenceVerified'] = False
            runner = Mock(return_value=bad)
            with patch.dict(build.__globals__, ROOT=root, contained_command=command, bounded_run=runner):
                with self.assertRaisesRegex(ValueError, 'incomplete helper build'):
                    build('not-created.json')
            self.assertEqual(command.call_args.args[1].parent, root/'worker-work')
            self.assertNotEqual(command.call_args.args[1], work)
            self.assertEqual(command.call_args.kwargs['read_only_files'], (source,))
            self.assertEqual(command.call_args.kwargs['environment'], runner.call_args.args[2])
            self.assertIn(str(source), command.call_args.args[0])
            self.assertEqual(runner.call_args.kwargs['phase'], 'helper-build')
            self.assertFalse((work / 'not-created.json').exists())
            self.assertFalse((work/'record_identity_probe').exists())
            self.assertFalse((work/'helper-dependencies.d').exists())
            self.assertTrue(runner.return_value['leafCleanup']['retained'])
            self.assertTrue(Path(runner.return_value['leafCleanup']['identity']['path']).is_dir())
            primary=ValueError('raised unverified build');primary.bounded_result=bad
            runner.side_effect=primary
            with patch.dict(build.__globals__, ROOT=root, contained_command=command, bounded_run=runner):
                with self.assertRaisesRegex(ValueError,'raised unverified build') as caught:
                    build('raised-not-created.json')
            self.assertIs(caught.exception,primary)
            self.assertIs(primary.bounded_result,bad)
            self.assertTrue(Path(primary.leafCleanup['identity']['path']).is_dir())
            self.assertFalse((work/'raised-not-created.json').exists())
            runner.side_effect=None
            cleanup_bad=completed_result();cleanup_bad['workerTerminationVerified']=False
            runner.return_value=cleanup_bad
            with patch.dict(build.__globals__,ROOT=root,contained_command=command,bounded_run=runner), patch.object(gate.shutil,'rmtree',side_effect=OSError('injected build deletion')):
                with self.assertRaisesRegex(ValueError,'incomplete helper build') as caught:
                    build('cleanup-not-created.json')
            self.assertIs(caught.exception.bounded_result,cleanup_bad)
            self.assertIn('injected build deletion',caught.exception.leafCleanup['secondaryError'])

    def test_helper_staged_outputs_publish_only_after_complete_and_valid_elf(self):
        import struct
        functions = runpy.run_path(str(ROOT/'toolchain-001/build_helper.py'),run_name='inert_import')
        build = functions['build']
        elf = bytearray(120)
        elf[:7] = b'\x7fELF\x02\x01\x01'
        struct.pack_into('<HHI',elf,16,3,62,1)
        struct.pack_into('<Q',elf,32,64)
        struct.pack_into('<HHH',elf,52,64,56,1)
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            (root/'toolchain-001').mkdir()
            (root/'contracts').mkdir()
            source = root/'record_identity_probe.cpp'
            source.write_bytes(b'// fixed')
            (root/'contracts/helper-schema.json').write_bytes(b'{}')
            seen = []
            def command(argv,cwd,**kwargs):
                seen.append((argv,cwd,kwargs))
                self.assertEqual(cwd.parent,root/'worker-work')
                self.assertFalse(source.is_relative_to(cwd))
                self.assertEqual(kwargs['read_only_files'],(source,))
                self.assertTrue(Path(argv[argv.index('-o')+1]).is_relative_to(cwd))
                self.assertTrue(Path(argv[argv.index('-MF')+1]).is_relative_to(cwd))
                return argv
            def run(argv,cwd,env,**kwargs):
                Path(argv[argv.index('-o')+1]).write_bytes(elf)
                Path(argv[argv.index('-MF')+1]).write_bytes(b'output: '+str(source).encode())
                self.assertFalse((root/'toolchain-001/record_identity_probe').exists())
                from bounded_runtime import _pin_files
                return _producer_execution(_pin_files([source]),phase='helper-build')
            with patch.dict(build.__globals__,ROOT=root,contained_command=command,bounded_run=run):
                result=build('receipt.json')
            self.assertTrue(result['publication']['published'])
            self.assertEqual((root/'toolchain-001/record_identity_probe').read_bytes(),elf)
            self.assertFalse(Path(result['workerCwd']).exists())
            self.assertEqual(source.read_bytes(),b'// fixed')

    def test_actual_containment_recipe_writes_only_leaf_and_keeps_inputs_readonly(self):
        from bounded_runtime import contained_command
        (ROOT/'worker-work').mkdir(mode=0o700,exist_ok=True)
        with tempfile.TemporaryDirectory(dir=ROOT/'worker-work') as directory:
            work=Path(directory)
            tool=work/'tool';tool.write_bytes(b'inert')
            source=ROOT/'record_identity_probe.cpp'
            env={'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C','TMPDIR':str(work)}
            command=contained_command(['/usr/bin/true'],work,read_only_files=(source,tool),environment=env)
            writable=[command[i+1:i+3] for i,value in enumerate(command) if value=='--bind']
            readonly=[command[i+1:i+3] for i,value in enumerate(command) if value=='--ro-bind']
            self.assertEqual(writable,[[str(work),str(work)]])
            self.assertIn([str(source),str(source)],readonly)
            self.assertIn([str(tool),str(tool)],readonly)
            self.assertNotIn([str(ROOT),str(ROOT)],writable)
            self.assertNotIn([str(ROOT/'toolchain-001'),str(ROOT/'toolchain-001')],writable)

    def test_helper_output_reader_rejects_symlink_oversize_and_non_elf(self):
        read = runpy.run_path(str(ROOT/'toolchain-001/build_helper.py'),run_name='inert_import')['read_output']
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root=Path(directory);file=root/'file';file.write_bytes(b'not ELF')
            with self.assertRaises(ValueError):read(file,2)
            with self.assertRaises(ValueError):read(file,100,elf=True)
            link=root/'link';link.symlink_to(file)
            with self.assertRaises(OSError):read(link,100)

    def test_pin_dependency_inspection_is_contained_and_requires_proof(self):
        import json
        pin = runpy.run_path(str(ROOT / 'toolchain-001/pin_helper.py'), run_name='inert_import')['pin']
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            work = root / 'toolchain-001'
            work.mkdir()
            (root / 'contracts').mkdir()
            source = root / 'record_identity_probe.cpp'
            schema = root / 'contracts/helper-schema.json'
            binary = work / 'record_identity_probe'
            for path in (source, schema, binary):
                path.write_bytes(b'inert')
            (work / 'helper-dependencies.d').write_text('output: ' + str(source))
            receipt = gate.public_result(completed_result())
            receipt.update(schemaVersion=3, sourceSha256=gate.digest(source),
                           helperSchemaSha256=gate.digest(schema), binarySha256=gate.digest(binary))
            (work / 'build.json').write_text(json.dumps(receipt))
            binding = inspection_fixture(root)
            bad = completed_result()
            bad['workerTerminationVerified'] = False
            bad['cleanupVerified'] = False
            bad['rootReaped'] = False
            bad['finalAbsenceVerified'] = False
            bad['kernelScope']['finalAbsenceVerified'] = False
            command = Mock(return_value=['NOT-EXECUTED'])
            runner = Mock(return_value=bad)
            with patch.dict(pin.__globals__, ROOT=root, contained_command=command, bounded_run=runner, load_inspection_binding=lambda profile:binding):
                with self.assertRaisesRegex(ValueError, 'incomplete helper dependency inspection') as error:
                    pin('not-created.json', 'build.json')
            self.assertIs(error.exception.bounded_result, bad)
            self.assertTrue(Path(error.exception.leafCleanup['identity']['path']).exists())
            self.assertEqual(command.call_args.args[0], [binding['bashPath'],binding['scriptPath'], str(binary)])
            self.assertEqual(command.call_args.args[1].parent, root/'worker-work')
            self.assertNotEqual(command.call_args.args[1], work)
            self.assertEqual(command.call_args.kwargs['read_only_files'], (binary,Path(binding['scriptPath']),Path(binding['cachePath'])))
            self.assertEqual(command.call_args.kwargs['environment'], runner.call_args.args[2])
            self.assertEqual(runner.call_args.kwargs['phase'], 'elf-inspection')
            self.assertEqual(runner.call_args.kwargs['timeout'], gate.load_profile()['bounds']['elfInspectionSeconds'])
            self.assertEqual(runner.call_args.kwargs['output_limit'], gate.load_profile()['bounds']['outputBytesPerStream'])
            primary=ValueError('raised unverified inspection');primary.bounded_result=bad
            runner.side_effect=primary
            with patch.dict(pin.__globals__,ROOT=root,contained_command=command,bounded_run=runner,load_inspection_binding=lambda profile:binding):
                with self.assertRaisesRegex(ValueError,'raised unverified inspection') as caught:
                    pin('raised-not-created.json','build.json')
            self.assertIs(caught.exception,primary)
            self.assertIs(primary.bounded_result,bad)
            self.assertTrue(Path(primary.leafCleanup['identity']['path']).is_dir())
            self.assertFalse((work/'raised-not-created.json').exists())
            runner.side_effect=None
            cleanup_bad=completed_result();cleanup_bad['workerTerminationVerified']=False
            runner.return_value=cleanup_bad
            with patch.dict(pin.__globals__,ROOT=root,contained_command=command,bounded_run=runner,load_inspection_binding=lambda profile:binding), patch.object(gate.shutil,'rmtree',side_effect=OSError('injected inspection deletion')):
                with self.assertRaisesRegex(ValueError,'incomplete helper dependency inspection') as caught:
                    pin('cleanup-not-created.json','build.json')
            self.assertIs(caught.exception.bounded_result,cleanup_bad)
            self.assertIn('injected inspection deletion',caught.exception.leafCleanup['secondaryError'])
            self.assertFalse((work / 'not-created.json').exists())

    def test_fixed_inspection_recipe_rejects_substitution_and_other_shebangs(self):
        recipe = runpy.run_path(str(ROOT / 'toolchain-001/pin_helper.py'), run_name='inert_import')['inspection_recipe']
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            binding = inspection_fixture(root)
            (root/'tool').write_bytes(b'inert')
            logical, actual, inputs = recipe(binding, root/'tool')
            self.assertEqual(logical, ['/usr/bin/ldd',str(root/'tool')])
            self.assertEqual(actual, [binding['bashPath'],binding['scriptPath'],str(root/'tool')])
            for role in ('bash','script','cache'):
                path = Path(binding[role+'Path'])
                original = path.read_bytes()
                path.write_bytes(original+b'changed')
                with self.assertRaisesRegex(ValueError, 'substitution'):recipe(binding, root/'tool')
                path.write_bytes(original)
            script = Path(binding['scriptPath'])
            for shebang in (b'#!/usr/bin/env bash\n',b'#!/bin/bash -e\n',b'#!/bin/sh\n',b'#!/bin/bash\r\n'):
                script.write_bytes(shebang)
                changed = copy.deepcopy(binding)
                changed['scriptSha256'] = gate.digest(script)
                with self.assertRaisesRegex(ValueError, 'shebang'):recipe(changed,root/'tool')

    def test_pin_rejects_old_wrapper_only_receipt_before_inspection(self):
        import json
        pin = runpy.run_path(str(ROOT / 'toolchain-001/pin_helper.py'), run_name='inert_import')['pin']
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            work = root / 'toolchain-001'
            work.mkdir()
            bad = completed_result()
            bad.pop('workerExecVerified', None)
            (work / 'build.json').write_text(json.dumps(gate.public_result(bad)))
            runner = Mock(side_effect=AssertionError('inspection must not run'))
            with patch.dict(pin.__globals__, ROOT=root, bounded_run=runner):
                with self.assertRaisesRegex(ValueError, 'helper build is not bound'):
                    pin('not-created.json', 'build.json')
            runner.assert_not_called()
            self.assertFalse((work / 'not-created.json').exists())


class _PinFilesystem:
    """Finite authored virtual metadata/FDs; never consult the actual host."""
    def __init__(self):
        import stat
        self.nodes={};self.fds={};self.next_fd=100;self.events=[];self.now=0.0
        self.after_read=self.after_open=self.after_write=None
        self.read_error=self.close_error=self.open_error=self.metadata_error=None
        self.after_close=None;self.write_size=None;self.iterators=[]
        self.add('/',mode=stat.S_IFDIR|0o700)

    def add(self,path,data=b'',*,mode=None,size=None,target=None):
        import stat
        path=str(path)
        if path!='/':
            parent=str(Path(path).parent)
            if parent not in self.nodes:self.add(parent,mode=stat.S_IFDIR|0o700)
        self.nodes[path]={'data':bytearray(data),'mode':stat.S_IFREG|0o600 if mode is None else mode,
                          'size':len(data) if size is None else size,'target':target,
                          'ino':len(self.nodes)+1,'mtime':1}
        return self.nodes[path]

    def name(self,path,dir_fd=None):
        path=str(path)
        return path if path.startswith('/') else str(Path(self.fds[dir_fd]['path'])/path)

    def metadata(self,node):
        from types import SimpleNamespace
        return SimpleNamespace(st_dev=1,st_ino=node['ino'],st_mode=node['mode'],st_uid=1000,st_gid=1000,
                               st_nlink=1,st_size=node['size'],st_mtime_ns=node['mtime'],st_ctime_ns=node['mtime'])

    def stat(self,path,*,dir_fd=None,follow_symlinks=False):
        name=self.name(path,dir_fd);self.events.append(('stat',name))
        if name not in self.nodes:raise FileNotFoundError(2,'authored absent',str(path))
        return self.metadata(self.nodes[name])

    def open(self,path,flags,mode=0o777,*,dir_fd=None):
        import os
        name=self.name(path,dir_fd);self.events.append(('open',name,flags,mode))
        if self.open_error is not None:raise self.open_error
        if flags&os.O_CREAT:
            if name in self.nodes:raise FileExistsError(name)
            self.add(name)
        if name not in self.nodes:raise FileNotFoundError(2,'authored absent',str(path))
        self.next_fd+=1;fd=self.next_fd
        self.fds[fd]={'path':name,'node':self.nodes[name],'offset':0}
        if self.after_open is not None:self.after_open(self,name)
        return fd

    def fstat(self,fd):
        self.events.append(('fstat',fd))
        if self.metadata_error is not None:raise self.metadata_error
        return self.metadata(self.fds[fd]['node'])

    def read(self,fd,count):
        entry=self.fds[fd];self.events.append(('read',entry['path'],count))
        if self.read_error is not None:raise self.read_error
        node=entry['node'];offset=entry['offset'];amount=min(count,max(0,node['size']-offset))
        data=bytes(node['data'][offset:offset+amount]) if len(node['data'])==node['size'] else b'x'*amount
        entry['offset']+=len(data)
        if self.after_read is not None:self.after_read(self,entry,data)
        return data

    def write(self,fd,data):
        entry=self.fds[fd];self.events.append(('write',entry['path'],len(data)))
        count=len(data) if self.write_size is None else min(len(data),self.write_size)
        entry['node']['data'].extend(data[:count]);entry['node']['size']+=count
        if self.after_write is not None:self.after_write(self,entry)
        return count

    def chmod(self,fd,mode):
        import stat
        self.events.append(('chmod',fd,mode));self.fds[fd]['node']['mode']=stat.S_IFMT(self.fds[fd]['node']['mode'])|mode

    def close(self,fd):
        self.events.append(('close',fd));self.fds.pop(fd)
        if self.after_close is not None:self.after_close(self,fd)
        if self.close_error is not None:raise self.close_error

    def readlink(self,path,*,dir_fd=None):
        return self.nodes[self.name(path,dir_fd)]['target']

    def scan(self,fd):
        from types import SimpleNamespace
        parent=self.fds[fd]['path'];names=sorted(Path(name).name for name in self.nodes if name!=parent and str(Path(name).parent)==parent)
        class Iterator:
            def __init__(self):self.index=0;self.closed=False;self.advances=0
            def __next__(self):
                self.advances+=1
                if self.index==len(names):raise StopIteration
                value=SimpleNamespace(name=names[self.index]);self.index+=1;return value
            def close(self):self.closed=True
        result=Iterator();self.iterators.append(result);return result

    def effects(self,module):
        from contextlib import ExitStack
        stack=ExitStack();ops=module['os']
        for name,operation in (('open',self.open),('stat',self.stat),('fstat',self.fstat),('read',self.read),
                               ('write',self.write),('close',self.close),('fchmod',self.chmod),('readlink',self.readlink),('scandir',self.scan)):
            stack.enter_context(patch.object(ops,name,side_effect=operation))
        stack.enter_context(patch.object(module['time'],'monotonic',side_effect=lambda:self.now))
        return stack


class HelperPinBoundedInputs(unittest.TestCase):
    def setUp(self):
        self.module=runpy.run_path(str(ROOT/'toolchain-001/pin_helper.py'),run_name='inert_import')
        self.g=self.module['pin'].__globals__

    def capture(self,fs,path='/fixture/input',**kwargs):
        ledger=kwargs.pop('ledger',self.g['_Ledger']())
        with fs.effects(self.g):
            return self.g['_capture'](path,role='authored',maximum=kwargs.pop('maximum',100),ledger=ledger,**kwargs),ledger

    def test_pin_capture_same_fd_version_bytes_prefix_and_real_strict_json(self):
        import hashlib
        fs=_PinFilesystem();data=b'\xef\xbb\xbf{"text":"authored"}'
        fs.add('/fixture/input',data)
        record,ledger=self.capture(fs,retain=True,prefix_bytes=4)
        self.assertEqual(data,record.raw);self.assertEqual(data[:4],record.prefix)
        self.assertEqual(hashlib.sha256(data).hexdigest(),record.sha256)
        self.assertEqual(len(data),record.size);self.assertEqual(len(data),ledger.bytes)
        self.assertEqual({'text':'authored'},self.g['_decode_json'](record.raw))
        with self.assertRaises(AttributeError):record.sha256='forged'
        for raw in (b'{"x":1,"x":2}',b'{"x":NaN}',b'{',b'\xff'):
            with self.assertRaises(ValueError):self.g['_decode_json'](raw)
        self.assertFalse(fs.fds)
        closes=[e[1]for e in fs.events if e[0]=='close'];self.assertEqual(len(closes),len(set(closes)))

    def test_pin_capture_special_symlink_and_role_overflow_precede_payload(self):
        import stat
        for mode,size in ((stat.S_IFIFO|0o600,1),(stat.S_IFDIR|0o700,1),(stat.S_IFREG|0o600,101)):
            fs=_PinFilesystem();fs.add('/fixture/input',b'x',mode=mode,size=size)
            with self.subTest(mode=mode),self.assertRaises(ValueError):self.capture(fs)
            self.assertFalse([e for e in fs.events if e[0]=='read']);self.assertFalse(fs.fds)
        fs=_PinFilesystem();fs.add('/fixture/input',b'x',mode=stat.S_IFLNK|0o777,target='/fixture/other')
        with self.assertRaisesRegex(ValueError,'symlink'):self.capture(fs)
        self.assertFalse([e for e in fs.events if e[0]=='read']);self.assertFalse(fs.fds)

    def test_pin_capture_growth_truncation_mutation_and_original_revalidation(self):
        for mutation in ('growth','truncated','version','replacement'):
            fs=_PinFilesystem();fs.add('/fixture/input',b'abc')
            fired=[]
            def change(owner,entry,data):
                if fired:return
                fired.append(True)
                if mutation=='growth':entry['node']['data'].extend(b'!');entry['node']['size']+=1
                elif mutation=='truncated':entry['node']['size']=1
                elif mutation=='version':entry['node']['mtime']+=1
                else:owner.add('/fixture/input',b'abc')['ino']+=100
            fs.after_read=change
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):self.capture(fs)
            self.assertFalse(fs.fds)
        fs=_PinFilesystem();fs.add('/fixture/input',b'A');record,ledger=self.capture(fs)
        fs.nodes['/fixture/input']['mtime']+=1
        with fs.effects(self.g),self.assertRaisesRegex(ValueError,'original input version'):
            self.g['_revalidate'](record,ledger=ledger)
        self.assertFalse(fs.fds)

    def test_pin_capture_errors_late_open_and_close_preserve_exact_primary_once(self):
        fs=_PinFilesystem();fs.add('/fixture/input',b'x')
        primary=OSError('authored read failure');secondary=OSError('authored close failure')
        fs.read_error=primary;fs.close_error=secondary
        with self.assertRaises(OSError) as caught:self.capture(fs)
        self.assertIs(primary,caught.exception);self.assertIs(secondary,primary.pinInputCloseFailure)
        self.assertFalse(fs.fds)
        closes=[e[1]for e in fs.events if e[0]=='close'];self.assertEqual(len(closes),len(set(closes)))
        fs=_PinFilesystem();fs.add('/fixture/input',b'x');fs.after_open=lambda owner,name:setattr(owner,'now',5.0)
        with self.assertRaises(TimeoutError):self.capture(fs,ledger=self.g['_Ledger'](5.0),deadline=5.0)
        self.assertFalse(fs.fds);self.assertFalse([e for e in fs.events if e[0]=='fstat'])
        fs=_PinFilesystem();fs.add('/fixture/input',b'x');fs.close_error=secondary
        with self.assertRaises(OSError) as caught:self.capture(fs)
        self.assertIs(secondary,caught.exception);self.assertFalse(fs.fds)
        for field in ('open_error','metadata_error'):
            fs=_PinFilesystem();fs.add('/fixture/input',b'x');failure=OSError('authored metadata/open refusal')
            setattr(fs,field,failure)
            with self.subTest(field=field),self.assertRaises(OSError) as caught:self.capture(fs)
            self.assertIs(failure,caught.exception);self.assertFalse(fs.fds)
            self.assertFalse([event for event in fs.events if event[0]=='read'])

    def test_pin_remaining_bytes_repeated_charge_and_large_hash_only_host_stream(self):
        fs=_PinFilesystem();fs.add('/fixture/input',b'abc');ledger=self.g['_Ledger']();ledger.bytes=self.g['_INPUT_BYTES']-3
        record,_=self.capture(fs,ledger=ledger);self.assertEqual(self.g['_INPUT_BYTES'],ledger.bytes)
        reads=len([e for e in fs.events if e[0]=='read'])
        with fs.effects(self.g),self.assertRaisesRegex(ValueError,'remaining direct byte'):
            self.g['_revalidate'](record,ledger=ledger)
        self.assertEqual(reads,len([e for e in fs.events if e[0]=='read']));self.assertFalse(fs.fds)
        fs=_PinFilesystem();size=self.g['_SMALL']+1;fs.add('/fixture/input',size=size)
        record,ledger=self.capture(fs,maximum=self.g['_INPUT_BYTES'])
        self.assertEqual(size,record.size);self.assertIsNone(record.raw);self.assertEqual(b'',record.prefix)
        self.assertEqual(size,ledger.bytes);self.assertTrue(all(e[2]<=65536 for e in fs.events if e[0]=='read'))
        self.assertFalse(fs.fds)

    def test_pin_depfile_stdout_path_alias_and_shared_work_boundaries(self):
        import stat
        ledger=self.g['_Ledger']()
        escaped=b'output: /a'+bytes([92])+b' b /a'+bytes([92])+b'#c '+bytes([92,10])+b' /a'+bytes([92])+b':c'
        self.assertEqual([Path('/a b'),Path('/a#c'),Path('/a:c')],self.g['_dep_paths'](escaped,ledger))
        self.assertEqual([Path('/a')],self.g['_stdout_paths'](b'lib => /a (0x0)\n',ledger))
        for raw in (b'output: relative',b'output: $variable',b'output: /a: /b',b'output: /a'+bytes([92])):
            with self.assertRaises(ValueError):self.g['_dep_paths'](raw,self.g['_Ledger']())
        ledger=self.g['_Ledger']();ledger.work=self.g['_WORK']-1
        with self.assertRaisesRegex(ValueError,'work bound'):self.g['_dep_paths'](b'xx',ledger)
        ledger=self.g['_Ledger']();ledger.tokens=self.g['_FILES']-1;ledger.token()
        with self.assertRaisesRegex(ValueError,'token bound'):ledger.token()
        for path in ('relative','/a/../b','//a','/'+('x'*4096),'/'+('/'.join(['a']*128))):
            with self.assertRaises(ValueError):self.g['_path'](path,self.g['_Ledger']())
        for count in (40,41):
            fs=_PinFilesystem()
            for i in range(count):fs.add('/a'+str(i),size=len('/a'+str(i+1)),mode=stat.S_IFLNK|0o777,target='/a'+str(i+1))
            fs.add('/a'+str(count),b'A')
            if count==40:record,_=self.capture(fs,'/a0',aliases=True);self.assertEqual('/a40',record.canonical)
            else:
                with self.assertRaisesRegex(ValueError,'symlink'):self.capture(fs,'/a0',aliases=True)
            self.assertFalse(fs.fds)

    def test_pin_config_scan_counts_nonmatches_eof_closes_and_revalidates(self):
        import stat
        for remaining in (3,2):
            fs=_PinFilesystem();fs.add('/etc/clang',mode=stat.S_IFDIR|0o700)
            fs.add('/etc/clang/a.cfg',b'A');fs.add('/etc/clang/other',b'B')
            ledger=self.g['_Ledger']();ledger.advances=self.g['_FILES']-remaining
            with fs.effects(self.g):
                if remaining==3:
                    self.assertEqual([Path('/etc/clang/a.cfg')],self.g['_config_inputs'](Path('/etc/clang'),ledger=ledger))
                else:
                    with self.assertRaisesRegex(ValueError,'scan advance'):self.g['_config_inputs'](Path('/etc/clang'),ledger=ledger)
            self.assertEqual(remaining,fs.iterators[0].advances)
            self.assertTrue(all(i.closed for i in fs.iterators));self.assertFalse(fs.fds)
        fs=_PinFilesystem();fs.add('/etc/clang',mode=stat.S_IFDIR|0o700);ledger=self.g['_Ledger']()
        with fs.effects(self.g):self.g['_config_inputs'](Path('/etc/clang'),ledger=ledger)
        fs.add('/etc/clang/new.cfg',b'A')
        with fs.effects(self.g),self.assertRaisesRegex(ValueError,'inventory changed'):
            self.g['_config_inputs'](Path('/etc/clang'),ledger=ledger)
        self.assertFalse(fs.fds)

    def test_pin_writer_owns_exact_encoding_short_writes_and_never_reopens_replacement(self):
        import hashlib,stat
        fs=_PinFilesystem();fs.add('/fixture',mode=stat.S_IFDIR|0o700);fs.write_size=2
        value={'unicode':'\u2603','line':'one\ntwo'};expected=(json.dumps(value,indent=2)+'\n').encode('utf8')
        changed=[]
        def replace(owner,entry):
            if not changed:changed.append(True);owner.add('/fixture/out',mode=stat.S_IFIFO|0o600)
        fs.after_write=replace;ledger=self.g['_Ledger']()
        with fs.effects(self.g):result=self.g['_write_pin']('out',value,root=Path('/fixture'),ledger=ledger)
        self.assertEqual(hashlib.sha256(expected).hexdigest(),result)
        self.assertEqual(1,len([e for e in fs.events if e[0]=='open' and e[1]=='/fixture/out']))
        self.assertFalse([e for e in fs.events if e[0]=='read']);self.assertFalse(fs.fds)
        self.assertTrue([e for e in fs.events if e[0]=='chmod' and e[2]==0o600])

    def test_pin_writer_overflow_zero_write_late_and_close_failure_cannot_succeed(self):
        import stat
        fs=_PinFilesystem();fs.add('/fixture',mode=stat.S_IFDIR|0o700)
        with patch.dict(self.g,_SMALL=8),fs.effects(self.g),self.assertRaisesRegex(ValueError,'output'):
            self.g['_write_pin']('out',{'long':'value'},root=Path('/fixture'),ledger=self.g['_Ledger']())
        self.assertFalse(fs.events)
        fs.add('/fixture/out',b'authored original')
        with fs.effects(self.g),self.assertRaises(FileExistsError):
            self.g['_write_pin']('out',{},root=Path('/fixture'),ledger=self.g['_Ledger']())
        self.assertEqual(b'authored original',bytes(fs.nodes['/fixture/out']['data']));self.assertFalse(fs.fds)
        for fault in ('zero','late','late-close','close'):
            fs=_PinFilesystem();fs.add('/fixture',mode=stat.S_IFDIR|0o700);ledger=self.g['_Ledger'](5.0)
            if fault=='zero':fs.write_size=0
            elif fault=='late':fs.after_write=lambda owner,entry:setattr(owner,'now',5.0)
            elif fault=='late-close':fs.after_close=lambda owner,fd:setattr(owner,'now',5.0)
            else:fs.close_error=OSError('authored writer close')
            with self.subTest(fault=fault),fs.effects(self.g),self.assertRaises((ValueError,TimeoutError,OSError)):
                self.g['_write_pin']('out',{},root=Path('/fixture'),ledger=ledger,deadline=5.0)
            self.assertFalse(fs.fds)

    def test_pin_actual_orchestration_keeps_five_bindings_four_recipes_two_profiles_and_proof(self):
        import hashlib,stat
        fs=_PinFilesystem();root=Path('/fixture');work=root/'toolchain-001'
        fs.add('/etc',mode=stat.S_IFDIR|0o700)
        source=root/'record_identity_probe.cpp';schema=root/'contracts/helper-schema.json';binary=work/'record_identity_probe'
        for path,data in ((source,b'authored source'),(schema,b'{}'),(binary,b'authored ELF'),(work/'build_helper.py',b'authored builder'),
                          (Path(self.g['__file__']),b'authored pinner'),(work/'helper-dependencies.d',('output: '+str(source)).encode())):
            fs.add(path,data)
        # The REAL authenticated proof parser remains available in a cold cache;
        # these are exact public bytes, never a completion/predicate stub.
        fs.add(ROOT/'worker_exec_proof.py',(ROOT/'worker_exec_proof.py').read_bytes())
        build=gate.public_result(completed_result(phase='helper-build'))
        build.update(schemaVersion=3,sourceSha256=hashlib.sha256(b'authored source').hexdigest(),
                     helperSchemaSha256=hashlib.sha256(b'{}').hexdigest(),binarySha256=hashlib.sha256(b'authored ELF').hexdigest())
        fs.add(work/'build.json',json.dumps(build).encode())
        binding={'environmentPinSha256':'a'*64,'dependencies':[]}
        for role,data in (('bash',b'\x7fELFbash'),('script',b'#!/bin/bash\n# inert'),('cache',b'cache')):
            path=root/role;fs.add(path,data);binding[role+'Path']=str(path);binding[role+'Sha256']=hashlib.sha256(data).hexdigest()
            binding['dependencies'].append({'path':str(path),'sha256':hashlib.sha256(data).hexdigest()})
        for name in ('/usr/lib/llvm/23/bin/clang','/usr/lib/llvm/23/bin/clang++','/usr/bin/ld','/usr/bin/as'):fs.add(name,b'host tool')
        fs.add('/z-a',b'first');fs.add('/z/file',b'second')
        result=completed_result(phase='elf-inspection');result['stdout']=b'/z-a /z/file\n'
        # Keep proof hash truthful after changing the untrusted stream only.
        profile,profile_sha=gate.load_profile_with_digest()
        def row(path):
            node=fs.metadata(fs.nodes[str(path)])
            return {'device':node.st_dev,'inode':node.st_ino,'mode':stat.S_IMODE(node.st_mode),
                    'sha256':hashlib.sha256(bytes(fs.nodes[str(path)]['data'])).hexdigest()}
        target=(binding['bashPath'],row(binding['bashPath']))
        results=[_producer_execution({str(path):row(path)},phase='elf-inspection',target=target,
                    profile_sha=profile_sha,stdout=result['stdout'])for path in (binary,Path('/usr/lib/llvm/23/bin/clang'))]
        runner=Mock(side_effect=results);loader=Mock(return_value=binding);profiles=Mock(side_effect=[profile,(profile,profile_sha)])
        class Leaf:
            path=root/'inspection'
            def __enter__(self):return self
            def __exit__(self,*args):return False
            def run(self,operation,*args,**kwargs):return operation(*args,**kwargs)
        recipe=self.g['inspection_recipe'];recipes=Mock(wraps=recipe);ledger=self.g['_Ledger']()
        with fs.effects(self.g),patch.dict(self.g,ROOT=root,load_profile=profiles,load_profile_with_digest=profiles,load_inspection_binding=loader,
                owned_worker_leaf=Mock(return_value=Leaf()),bounded_run=runner,contained_command=Mock(return_value=['NOT-EXECUTED']),inspection_recipe=recipes,_Ledger=Mock(return_value=ledger)):
            value=self.g['pin']('pin.json','build.json')
        self.assertEqual(5,loader.call_count);self.assertEqual(4,recipes.call_count);self.assertEqual(2,profiles.call_count)
        self.assertEqual(2,runner.call_count)
        self.assertTrue(all(c.kwargs['timeout']==10 and 'phase_deadline' not in c.kwargs for c in runner.call_args_list))
        self.assertEqual(build['sourceSha256'],value['sourceSha256']);self.assertEqual(2,len(value['inspections']))
        self.assertEqual(['/z/file','/z-a'],[name for name in value['dependencies'] if name in ('/z-a','/z/file')])
        self.assertEqual(hashlib.sha256(json.dumps(build).encode()).hexdigest(),value['buildReceiptSha256'])
        self.assertEqual(value,json.loads(bytes(fs.nodes[str(work/'pin.json')]['data'])))
        by_role={record.role:record for record in ledger.records.values()}
        self.assertEqual(65536,by_role['schema'].maximum);self.assertEqual(8388608,by_role['build-receipt'].maximum)
        self.assertEqual(16777216,by_role['helper-binary'].maximum);self.assertEqual(1048576,by_role['depfile'].maximum)
        self.assertEqual(536870912,by_role['host-tool'].maximum)
        self.assertGreater(ledger.bytes,sum(record.size for record in ledger.records.values()))
        self.assertFalse(fs.fds)


    def test_pin_open_reserves_storage_before_acquisition_and_closes_prior_owners_once(self):
        fs=_PinFilesystem();fs.add('/fixture/input',b'x');ledger=self.g['_Ledger']()
        allocation=MemoryError('authored ownership storage failure');secondary=OSError('authored terminal close')
        class NoStorage(list):
            def append(self,value):raise allocation
        with fs.effects(self.g):
            prior=[]
            for name in ('/','/fixture/input'):self.g['_open'](name,0,prior,ledger)
            owned=NoStorage(prior);fs.close_error=secondary;primary=None
            with self.assertRaises(MemoryError) as caught:
                try:self.g['_open']('/fixture/input',0,owned,ledger)
                except BaseException as error:primary=error;raise
                finally:self.g['_close_all'](owned,primary,ledger)
        self.assertIs(allocation,caught.exception);self.assertIs(secondary,allocation.pinInputCloseFailure)
        self.assertEqual(2,len([e for e in fs.events if e[0]=='open']))
        self.assertEqual(list(reversed(prior)),[e[1]for e in fs.events if e[0]=='close'])
        self.assertEqual([None,None],owned);self.assertFalse(fs.fds)

    def test_pin_open_failed_acquisition_has_no_phantom_close_and_late_acquisition_closes_once(self):
        for fault in ('open','late'):
            fs=_PinFilesystem();fs.add('/fixture/input',b'x');owned=[];ledger=self.g['_Ledger'](5.0);primary=None
            failure=OSError('authored acquisition failure')
            if fault=='open':fs.open_error=failure
            else:fs.after_open=lambda owner,name:setattr(owner,'now',5.0)
            with self.subTest(fault=fault),fs.effects(self.g),self.assertRaises((OSError,TimeoutError)) as caught:
                try:self.g['_open']('/fixture/input',0,owned,ledger)
                except BaseException as error:primary=error;raise
                finally:self.g['_close_all'](owned,primary,ledger)
            if fault=='open':self.assertIs(failure,caught.exception)
            else:self.assertIsInstance(caught.exception,TimeoutError)
            self.assertEqual(0 if fault=='open' else 1,len([e for e in fs.events if e[0]=='close']))
            self.assertEqual([None],owned);self.assertFalse(fs.fds)

    def test_pin_capture_terminal_publication_refuses_late_new_original_and_preserves_valid_original(self):
        fs=_PinFilesystem();fs.add('/fixture/input',b'A');ledger=self.g['_Ledger'](5.0)
        class LateRecords(dict):
            def setdefault(self,key,value):
                result=super().setdefault(key,value);fs.now=5.0;return result
        ledger.records=LateRecords()
        with self.assertRaises(TimeoutError):self.capture(fs,ledger=ledger,deadline=5.0)
        self.assertEqual({},ledger.records);self.assertFalse(fs.fds)
        closed=[e[1]for e in fs.events if e[0]=='close'];self.assertEqual(len(closed),len(set(closed)))
        publication=MemoryError('authored publication allocation failure')
        class FailedPublication(dict):
            def setdefault(self,key,value):
                super().setdefault(key,value);raise publication
        fs.now=0.0;ledger.records=FailedPublication()
        with self.assertRaises(MemoryError) as caught:self.capture(fs,ledger=ledger,deadline=5.0)
        self.assertIs(publication,caught.exception);self.assertEqual({},ledger.records);self.assertFalse(fs.fds)
        fs.now=0.0;ledger.records={}
        original,_=self.capture(fs,ledger=ledger,deadline=5.0)
        key=('/fixture/input','authored');self.assertIs(original,ledger.records[key])
        ledger.records=LateRecords(ledger.records)
        with fs.effects(self.g),self.assertRaises(TimeoutError):
            self.g['_revalidate'](original,ledger=ledger,deadline=5.0)
        self.assertIs(original,ledger.records[key]);self.assertFalse(fs.fds)
        fs.now=0.0;fs.nodes['/fixture/input']['mtime']+=1
        with fs.effects(self.g),self.assertRaisesRegex(ValueError,'original input version'):
            self.g['_revalidate'](original,ledger=ledger,deadline=5.0)
        self.assertIs(original,ledger.records[key]);self.assertFalse(fs.fds)
        closed=[e[1]for e in fs.events if e[0]=='close'];self.assertEqual(len(closed),len(set(closed)))

    def test_pin_recipe_terminal_construction_uses_original_end_and_none_compatibility(self):
        import hashlib
        for deadline in (5.0,None):
            fs=_PinFilesystem();binding={'dependencies':[]};target=[];constructed=[]
            for role,data in (('bash',b'\x7fELFbash'),('script',b'#!/bin/bash\n# inert'),('cache',b'cache')):
                name='/fixture/'+role;fs.add(name,data);binding[role+'Path']=name
                binding[role+'Sha256']=hashlib.sha256(data).hexdigest()
            fs.add('/fixture/tool',b'authored tool');ledger=self.g['_Ledger'](deadline)
            capture=self.g['_capture']
            def actual_capture(*args,**kwargs):
                record=capture(*args,**kwargs)
                if record.role=='host-tool':target.append(record)
                return record
            def observed_path(value):
                result=Path(value)
                if target and value is target[0].canonical:
                    constructed.append(result);fs.now=5.0
                return result
            with self.subTest(deadline=deadline),fs.effects(self.g),patch.dict(self.g,_capture=actual_capture,Path=observed_path):
                if deadline is None:
                    result=self.g['inspection_recipe'](binding,Path('/fixture/tool'),ledger=ledger)
                    self.assertEqual(['/usr/bin/ldd','/fixture/tool'],result[0])
                    self.assertEqual(['/fixture/bash','/fixture/script','/fixture/tool'],result[1])
                    self.assertEqual((Path('/fixture/tool'),Path('/fixture/script'),Path('/fixture/cache')),result[2])
                else:
                    with self.assertRaises(TimeoutError):
                        self.g['inspection_recipe'](binding,Path('/fixture/tool'),ledger=ledger,deadline=deadline)
            self.assertEqual([Path('/fixture/tool')],constructed);self.assertEqual(5.0,fs.now)
            self.assertEqual(4,len(ledger.records));self.assertFalse(fs.fds)
            closed=[e[1]for e in fs.events if e[0]=='close'];self.assertEqual(len(closed),len(set(closed)))


class ProducerLaunchInputJoins(unittest.TestCase):
    def setUp(self):
        self.builder=runpy.run_path(str(ROOT/'toolchain-001/build_helper.py'),run_name='inert_import')['build']
        self.pinner=runpy.run_path(str(ROOT/'toolchain-001/pin_helper.py'),run_name='inert_import')['pin']

    def mutate_input(self,inputs,name,mutation):
        if mutation=='sha':inputs[name]['sha256']='1'*64
        elif mutation=='inode':inputs[name]['inode']+=1
        elif mutation=='mode':inputs[name]['mode']^=0o100
        elif mutation=='missing':inputs.pop(name)
        elif mutation=='rekeyed':inputs['/authored/unrelated-input']=inputs.pop(name)
        elif mutation=='unrelated':
            inputs['/authored/unrelated-input']=copy.deepcopy(inputs[name]);inputs[name]['sha256']='1'*64
        elif mutation=='bool':inputs[name]['device']=True
        elif mutation=='extra':inputs[name]['unreviewed']=True
        elif mutation=='row-type':inputs[name]=[]

    def build_vector(self,mutation=None,*,exit_code=0):
        import bounded_runtime as runtime
        import struct
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root=Path(directory);(root/'toolchain-001').mkdir();(root/'contracts').mkdir()
            source=root/'record_identity_probe.cpp';source.write_bytes(b'authored source A')
            (root/'contracts/helper-schema.json').write_bytes(b'{}')
            original=runtime._pin_files([source]);profile_sha=gate.load_profile_with_digest()[1]
            elf=bytearray(120);elf[:7]=b'ELF';struct.pack_into('<HHI',elf,16,3,62,1)
            struct.pack_into('<Q',elf,32,64);struct.pack_into('<HHH',elf,52,64,56,1)
            returned=[]
            def run(argv,cwd,environment,**kwargs):
                inputs=copy.deepcopy(original)
                if mutation=='restored':
                    source.write_bytes(b'authored source B');inputs=runtime._pin_files([source]);source.write_bytes(b'authored source A')
                else:self.mutate_input(inputs,str(source),mutation)
                if mutation=='post-mode':source.chmod(source.stat().st_mode^0o100)
                value=_producer_execution(inputs,phase='compiler' if mutation=='phase' else 'helper-build',
                    profile_sha='f'*64 if mutation=='profile' else profile_sha,exit_code=exit_code)
                if mutation=='incomplete':value['workerExecVerified']=False
                if mutation=='cleanup':value['cleanupVerified']=False
                if mutation=='raw-proof':value['workerProofRaw']=b'not a worker proof'
                expected_complete=mutation not in ('bool','extra','row-type','incomplete','cleanup','raw-proof')
                self.assertEqual(expected_complete,gate._complete_execution(value))
                self.assertEqual('/usr/lib/llvm/23/bin/clang++',argv[0])
                self.assertNotEqual((original[str(source)]['device'],original[str(source)]['inode']),
                    (value['workerProofBindings']['expected']['targetDevice'],value['workerProofBindings']['expected']['targetInode']))
                Path(argv[argv.index('-o')+1]).write_bytes(elf)
                Path(argv[argv.index('-MF')+1]).write_bytes(b'output: '+str(source).encode())
                returned.append(value);return value
            g=self.builder.__globals__;reader=g['read_output'];publisher=g['publish']
            with patch.dict(g,ROOT=root,contained_command=lambda argv,*args,**kwargs:argv,bounded_run=run), \
                    patch.dict(g,read_output=Mock(wraps=reader),publish=Mock(wraps=publisher)):
                error=result=None
                try:result=self.builder('result.json')
                except ValueError as failure:error=failure
                read_calls=g['read_output'].call_count;publish_calls=g['publish'].call_count
            self.assertEqual(1,len(returned));execution=returned[0]
            if mutation is None:
                self.assertIsNone(error);self.assertEqual(original[str(source)]['sha256'],result['sourceSha256'])
                self.assertEqual(exit_code,result['exitCode']);self.assertTrue((root/'toolchain-001/result.json').is_file())
                self.assertEqual(exit_code==0,result['publication']['published'])
                self.assertEqual(2 if exit_code==0 else 0,read_calls);self.assertEqual(2 if exit_code==0 else 0,publish_calls)
                self.assertEqual(exit_code==0,(root/'toolchain-001/record_identity_probe').exists())
                if exit_code!=0:self.assertIsNone(result['binarySha256'])
            else:
                self.assertIsNotNone(error);self.assertEqual(0,read_calls);self.assertEqual(0,publish_calls)
                self.assertFalse((root/'toolchain-001/result.json').exists());self.assertFalse((root/'toolchain-001/record_identity_probe').exists())
                if mutation=='post-mode':self.assertEqual('helper build source/schema drift',str(error))
                else:
                    self.assertIs(execution,error.bounded_result)
                    self.assertEqual('producer launch input differs from independent admission' if
                        mutation not in ('bool','extra','row-type','incomplete','cleanup','raw-proof') else
                        'incomplete helper build execution',str(error))
                if mutation=='cleanup':self.assertTrue(execution['leafCleanup']['retained'])
            return original,execution

    def test_actual_build_join_refuses_resealed_input_B_and_restored_A_before_outputs(self):
        for mutation in ('restored','sha','inode','mode','missing','rekeyed','unrelated','phase','profile','post-mode'):
            with self.subTest(mutation=mutation):self.build_vector(mutation)

    def test_actual_build_join_preserves_real_proof_rejections_and_complete_nonzero_receipts(self):
        for mutation in ('bool','extra','row-type','incomplete','cleanup','raw-proof'):
            with self.subTest(mutation=mutation):self.build_vector(mutation)
        for exit_code in (0,7,-9):
            with self.subTest(exit_code=exit_code):self.build_vector(exit_code=exit_code)

    def pin_vector(self,mutation=None,*,failed_tool=0):
        import hashlib,stat
        fs=_PinFilesystem();root=Path('/fixture');work=root/'toolchain-001';g=self.pinner.__globals__
        fs.add('/etc',mode=stat.S_IFDIR|0o700)
        source=root/'record_identity_probe.cpp';schema=root/'contracts/helper-schema.json';binary=work/'record_identity_probe'
        clang=Path('/usr/lib/llvm/23/bin/clang')
        for path,data in ((source,b'source A'),(schema,b'{}'),(binary,b'helper A'),(clang,b'clang A'),
                (work/'build_helper.py',b'builder'),(Path(g['__file__']),b'pinner'),
                (work/'helper-dependencies.d',('output: '+str(source)).encode()),
                (ROOT/'worker_exec_proof.py',(ROOT/'worker_exec_proof.py').read_bytes())):fs.add(path,data)
        def row(path):
            node=fs.metadata(fs.nodes[str(path)])
            return {'device':node.st_dev,'inode':node.st_ino,'mode':stat.S_IMODE(node.st_mode),
                    'sha256':hashlib.sha256(bytes(fs.nodes[str(path)]['data'])).hexdigest()}
        originals={str(tool):row(tool)for tool in (binary,clang)}
        profile,profile_sha=gate.load_profile_with_digest()
        build=_producer_execution({str(source):row(source)},phase='helper-build',profile_sha=profile_sha)
        self.assertTrue(gate._complete_execution(build))
        build=gate.public_result(build);build.update(schemaVersion=3,sourceSha256=row(source)['sha256'],
            helperSchemaSha256=row(schema)['sha256'],binarySha256=row(binary)['sha256'])
        fs.add(work/'build.json',json.dumps(build).encode())
        binding={'environmentPinSha256':'a'*64,'dependencies':[]}
        for role,data in (('bash',b'ELFbash'),('script',b'#!/bin/bash\n# inert'),('cache',b'cache')):
            path=root/role;fs.add(path,data);binding[role+'Path']=str(path);binding[role+'Sha256']=row(path)['sha256']
            binding['dependencies'].append({'path':str(path),'sha256':row(path)['sha256']})
        for name in ('/usr/lib/llvm/23/bin/clang++','/usr/bin/ld','/usr/bin/as'):fs.add(name,b'host tool')
        for name in ('/observed/helper','/observed/clang'):fs.add(name,b'selected inert dependency')
        target=(binding['bashPath'],row(binding['bashPath']));executions=[];selected=[];commands=[]
        class Leaf:
            path=root/'inspection'
            def __enter__(self):return self
            def __exit__(self,*args):return False
            def run(self,operation,*args,**kwargs):return operation(*args,**kwargs)
        def command(argv,cwd,**kwargs):
            commands.append((argv,kwargs));return argv
        def run(argv,*args,**kwargs):
            index=len(executions);tool=(binary,clang)[index];name=str(tool);inputs={name:copy.deepcopy(originals[name])}
            current_mutation=mutation if index==failed_tool else None
            if current_mutation=='restored':
                node=fs.nodes[name];old=bytes(node['data']);node['data']=bytearray(b'input B');node['size']=7
                inputs[name]=row(tool);node['data']=bytearray(old);node['size']=len(old)
            else:self.mutate_input(inputs,name,current_mutation)
            value=_producer_execution(inputs,phase='runtime' if current_mutation=='phase' else 'elf-inspection',
                profile_sha='f'*64 if current_mutation=='profile' else profile_sha,target=target,
                stdout=b'/forbidden/selection\n' if current_mutation is not None else
                    b'/observed/helper\n' if index==0 else b'/observed/clang\n',
                exit_code=7 if current_mutation=='nonzero' else 0)
            if current_mutation=='incomplete':value['workerExecVerified']=False
            if current_mutation=='cleanup':value['cleanupVerified']=False
            if current_mutation=='raw-proof':value['workerProofRaw']=b'not a worker proof'
            expected_complete=current_mutation not in ('bool','extra','row-type','incomplete','cleanup','raw-proof')
            self.assertEqual(expected_complete,gate._complete_execution(value))
            self.assertEqual(binding['bashPath'],argv[0]);self.assertEqual(str(tool),argv[2])
            self.assertNotEqual((originals[name]['device'],originals[name]['inode']),
                (value['workerProofBindings']['expected']['targetDevice'],value['workerProofBindings']['expected']['targetInode']))
            executions.append(value);return value
        parse=g['_stdout_paths']
        def actual_paths(raw,ledger):selected.append(raw);return parse(raw,ledger)
        loader=Mock(return_value=binding);profiles=Mock(side_effect=[profile,(profile,profile_sha)])
        recipes=Mock(wraps=g['inspection_recipe'])
        with fs.effects(g),patch.dict(g,ROOT=root,load_profile=profiles,load_profile_with_digest=profiles,
                load_inspection_binding=loader,owned_worker_leaf=Mock(return_value=Leaf()),bounded_run=run,
                contained_command=command,inspection_recipe=recipes,_stdout_paths=actual_paths):
            error=result=None
            try:result=self.pinner('pin.json','build.json')
            except ValueError as failure:error=failure
        if mutation is None:
            self.assertIsNone(error);self.assertEqual(2,len(executions));self.assertEqual(2,len(selected))
            self.assertEqual(5,loader.call_count);self.assertEqual(4,recipes.call_count);self.assertEqual(2,profiles.call_count)
            self.assertEqual(row(binary)['sha256'],result['binarySha256']);self.assertIn('/observed/helper',result['dependencies'])
            self.assertIn('/observed/clang',result['dependencies']);self.assertIn(str(work/'pin.json'),fs.nodes)
        else:
            self.assertIsNotNone(error);self.assertIs(executions[-1],error.bounded_result)
            self.assertEqual(failed_tool+1,len(executions));self.assertEqual(failed_tool,len(selected))
            self.assertNotIn(str(work/'pin.json'),fs.nodes)
            self.assertFalse(any(event[0]=='read' and event[1]=='/forbidden/selection'for event in fs.events))
            self.assertEqual('producer launch input differs from independent admission' if
                mutation not in ('bool','extra','row-type','incomplete','cleanup','raw-proof','nonzero') else
                'incomplete helper dependency inspection',str(error))
        self.assertFalse(fs.fds)
        return originals,executions

    def test_actual_inspections_join_helper_and_clang_separately_from_bash_before_stdout(self):
        self.pin_vector()
        for failed_tool in (0,1):
            for mutation in ('restored','sha','inode','mode','missing','rekeyed','unrelated','phase','profile'):
                with self.subTest(tool=failed_tool,mutation=mutation):self.pin_vector(mutation,failed_tool=failed_tool)

    def test_actual_inspections_keep_real_proof_cleanup_and_zero_exit_requirements(self):
        for failed_tool in (0,1):
            for mutation in ('bool','extra','row-type','incomplete','cleanup','raw-proof','nonzero'):
                with self.subTest(tool=failed_tool,mutation=mutation):self.pin_vector(mutation,failed_tool=failed_tool)

    def test_producer_local_joins_require_closed_independent_rows_and_exact_canonical_key(self):
        row={'device':19,'inode':20,'mode':0o600,'sha256':'2'*64};name='/authored/source'
        execution=_producer_execution({name:row},phase='helper-build')
        self.assertTrue(gate._complete_execution(execution));profile_sha=execution['bounds']['profileSha256']
        for producer in (self.builder,self.pinner):
            join=producer.__globals__['_require_input_join']
            join(execution,name,copy.deepcopy(row),'helper-build',profile_sha)
            for field,value in (('device',True),('inode',-1),('mode',0o10000),('sha256','G'*64)):
                original=copy.deepcopy(row);original[field]=value
                with self.subTest(producer=producer.__name__,field=field),self.assertRaisesRegex(ValueError,'independent admission') as caught:
                    join(execution,name,original,'helper-build',profile_sha)
                self.assertIs(execution,caught.exception.bounded_result)
            for other_name in ('relative','/authored/../source','//authored/source','/authored/./source','/authored/missing'):
                with self.assertRaisesRegex(ValueError,'independent admission'):
                    join(execution,other_name,row,'helper-build',profile_sha)


class _InspectionOperationalFixture:
    """Authored static closure; only Resolver('/') is transported to local files."""
    def __init__(self,base,module):
        import hashlib,shlex
        self.base=base;self.root=base.parent/'operational-files';self.root.mkdir(mode=0o700)
        self.module=module;self.instances=[];self.roots=[]
        self.original_resolver=module.link_inputs.Resolver
        for name in ('/usr/bin/gcc','/tools/cc1','/tools/collect2','/tools/as','/tools/ld'):
            self.write(name,bytes.fromhex('7f454c46')+b' inert tool')
        self.write('/etc/gcc/specs',b'authored specs')
        for name in ('crti.o','crtn.o','crtbeginS.o','crtendS.o','libgcc_s.so'):
            self.write('/gcc/lib/'+name,bytes.fromhex('7f454c46')+b' inert input')
        self.write('/gcc/lib/libgcc.a',b'!<arch>'+bytes([10])+b'inert')
        self.write('/lib/libc.so',b'GROUP ( /lib/libc.so.6 )')
        self.write('/lib/libc.so.6',bytes.fromhex('7f454c46')+b' inert libc')
        for name in ('/runtime/monitor','/bin/bash'):
            self.write(name,self.elf(needed=('libfixture.so.1',),interpreter='/runtime/ld-runtime.so'))
        self.write('/runtime/libfixture.so.1',self.elf(soname='libfixture.so.1'))
        self.write('/runtime/ld-runtime.so',self.elf(soname='ld-runtime.so'))
        self.write('/usr/bin/ldd',b'#!/bin/bash'+bytes([10])+b'# authored inert fixture'+bytes([10]))
        self.write('/etc/ld.so.cache',b'authored inert cache');self.write('/headers/stdio.h',b'authored header')
        public={'sourcePath':str(base/'worker_exec_monitor.c'),'parserPath':str(base/'worker_exec_proof.py'),
                'protocolPath':str(base/'contracts/worker-exec-proof-schema.json'),
                'buildScriptPath':str(base/'toolchain-001/build_worker_monitor.py'),
                'provisioningManifestPath':str(base/'toolchain-001/worker-exec-monitor.json')}
        for key,name in public.items():
            if key!='provisioningManifestPath':self.write(name,('authored public '+key).encode())
        monitor={'schemaVersion':1,'binaryPath':'/runtime/monitor',**public,
            'buildInputs':[{'role':role,'path':name}for role,name in (('header','/headers/stdio.h'),
                ('tool','/usr/bin/gcc'),('startup','/gcc/lib/crti.o'),('library','/lib/libc.so.6'),('configuration','/etc/gcc/specs'))],
            'runtimeLibraries':[{'soname':'libfixture.so.1','path':'/runtime/libfixture.so.1'}],'cachePath':'/etc/ld.so.cache'}
        digest=lambda name:hashlib.sha256(self.path(name).read_bytes()).hexdigest()
        provision={'schemaVersion':1,'status':'provisioning-only-unqualified','binaryPath':monitor['binaryPath'],
            **{field:digest(monitor[key])for field,key in (('binarySha256','binaryPath'),('sourceSha256','sourcePath'),
                ('parserSha256','parserPath'),('protocolSha256','protocolPath'))},'dependencies':[],
            'buildCommand':['/usr/bin/gcc','-D_GNU_SOURCE','-std=c11','-O2','-Wall','-Wextra','-Werror',
                '-Wl,-z,relro,-z,now,-z,noexecstack',monitor['sourcePath'],'-o',monitor['binaryPath']],'execution':{}}
        self.write(monitor['provisioningManifestPath'],json.dumps(provision).encode())
        argv=['/tools/collect2','-shared','-m','elf_x86_64','-o','/work/libcandidate.so','-L/gcc/lib','-L/lib',
              '/gcc/lib/crti.o','/gcc/lib/crtbeginS.o','/work/candidate.o','-lgcc','-lgcc_s','-lc',
              '/gcc/lib/crtendS.o','/gcc/lib/crtn.o']
        self.manifest={'schemaVersion':3,'driverArgv':['/usr/bin/gcc','-shared',
            '-Wl,-z,relro,-z,now,-z,noexecstack,--no-undefined','/work/candidate.o','-o','/work/libcandidate.so'],
            'dryRun':'Using built-in specs.'+chr(10)+' '+shlex.join(argv)+chr(10),'workingDirectory':'/work',
            'environment':{'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C','TMPDIR':'/tmp'},
            'tools':dict(gcc='/usr/bin/gcc',cc1='/tools/cc1',collect2='/tools/collect2',
                         **{'as':'/tools/as','ld':'/tools/ld'}),
            'specs':['/etc/gcc/specs'],'configurationRoots':['/etc/gcc'],
            'generatedFiles':['/work/candidate.o','/work/libcandidate.so'],'monitor':monitor,
            'inspection':{'schemaVersion':1,'bashPath':'/bin/bash','scriptPath':'/usr/bin/ldd',
                'cachePath':'/etc/ld.so.cache','runtimeLibraries':copy.deepcopy(monitor['runtimeLibraries'])}}

    def path(self,name):return self.root/name.lstrip('/')

    def write(self,name,data):
        path=self.path(name);path.parent.mkdir(mode=0o700,parents=True,exist_ok=True);path.write_bytes(data)

    @staticmethod
    def elf(needed=(),soname=None,interpreter=None):
        import struct
        base=0x400000;raw=bytearray(1024);strings=bytearray(bytes([0]));tags=[]
        for name in needed:tags.append((1,len(strings)));strings.extend(name.encode()+bytes([0]))
        if soname is not None:tags.append((14,len(strings)));strings.extend(soname.encode()+bytes([0]))
        tags.extend(((5,base+0x300),(10,len(strings)),(0,0)))
        raw[:16]=bytes.fromhex('7f454c46020101')+bytes(9)
        struct.pack_into('<HHIQQQIHHHHHH',raw,16,2 if interpreter else 3,62,1,0,64,0,0,64,56,3 if interpreter else 2,0,0,0)
        struct.pack_into('<IIQQQQQQ',raw,64,1,4,0,base,base,1024,1024,4096)
        struct.pack_into('<IIQQQQQQ',raw,120,2,4,0x200,base+0x200,base+0x200,len(tags)*16,len(tags)*16,8)
        if interpreter:
            value=interpreter.encode()+bytes([0]);raw[0x180:0x180+len(value)]=value
            struct.pack_into('<IIQQQQQQ',raw,176,3,4,0x180,base+0x180,base+0x180,len(value),len(value),1)
        for index,row in enumerate(tags):struct.pack_into('<qQ',raw,0x200+index*16,*row)
        raw[0x300:0x300+len(strings)]=strings
        return bytes(raw)

    def transport(self,module):
        # Only the constructor's exact root operand changes; every original
        # Resolver method/limit and actual collect/revalidate/JSON body remains.
        original=module.link_inputs.Resolver
        def local_root(root):
            if root!=Path('/'):raise AssertionError('unexpected operational resolver root')
            self.roots.append(root);instance=original(self.root);self.instances.append(instance);return instance
        module.link_inputs.Resolver=local_root
        return module

    def record(self):
        import hashlib
        self.transport(self.module)
        value=self.module.collect_pin(self.manifest,Path('/'))
        raw=json.dumps(value,sort_keys=True,separators=(',',':')).encode()
        output=self.base/'toolchain-001/environment-pin.json';output.write_bytes(raw)
        return value,raw,{'toolchainEnvironmentPinSha256':hashlib.sha256(raw).hexdigest()}


class InspectionLoaderAuthentication(unittest.TestCase):
    def setUp(self):
        import bounded_runtime as runtime
        # Trusted stdlib imports are not repository policy authentication.
        import argparse,io,posixpath,shlex,struct
        from contextlib import ExitStack
        self.effects=ExitStack();self.addCleanup(self.effects.close)
        for name in ('Popen','run','call','check_call','check_output'):
            self.effects.enter_context(patch.object(runtime.subprocess,name,side_effect=AssertionError('no native subprocess')))
        for name in ('kill','killpg','pidfd_open'):
            self.effects.enter_context(patch.object(runtime.os,name,side_effect=AssertionError('no signal/process authority')))
        self.runtime=runtime
        self.functions=runpy.run_path(str(ROOT/'toolchain-001/pin_helper.py'),run_name='inert_import')
        self.g=self.functions['pin'].__globals__;self.wrapper=self.functions['load_inspection_binding']
        self.sources={relative:(ROOT/relative).read_bytes()for relative,_,_ in runtime._MONITOR_LOADER_SOURCES}

    def tree(self):
        temporary=tempfile.TemporaryDirectory(prefix='.inspection-loader-',dir=ROOT);self.addCleanup(temporary.cleanup)
        base=Path(temporary.name)/'policy';(base/'toolchain-001').mkdir(parents=True,mode=0o700)
        for relative,raw in self.sources.items():(base/relative).write_bytes(raw)
        return base

    def storage(self,paths=None):
        paths=paths or {'bash':'/bin/bash','script':'/usr/bin/ldd','cache':'/etc/ld.so.cache'}
        record={'bashPath':'/bin/bash','scriptPath':'/usr/bin/ldd','cachePath':'/etc/ld.so.cache'}
        files={record[key+'Path']:{'realpath':paths[key],'sha256':str(index)*64}
               for index,key in enumerate(('bash','script','cache'),1)}
        return {'inspectionClosure':{'record':record,'files':files}}

    def test_loader_wrapper_authenticates_every_source_before_any_compile_or_policy(self):
        runtime=self.runtime
        for relative,size,_ in runtime._MONITOR_LOADER_SOURCES:
            for mutation in ('missing','empty','oversize','same-length-hostile'):
                with self.subTest(source=relative,mutation=mutation):
                    base=self.tree();path=base/relative
                    if mutation=='missing':path.unlink()
                    else:path.write_bytes(b'' if mutation=='empty' else b'X'*(size+1) if mutation=='oversize' else
                        (b'raise AssertionError(123)'+bytes([10])).ljust(size,b' '))
                    with patch.object(runtime,'BASE',base),patch.dict(self.g,ROOT=base), \
                            patch.object(runtime,'compile',create=True,side_effect=AssertionError('no compile before all hashes')) as compiling, \
                            patch.object(runtime,'exec',create=True,side_effect=AssertionError('no exec before all hashes')) as executing:
                        with self.assertRaises((OSError,ValueError)):self.wrapper({})
                    compiling.assert_not_called();executing.assert_not_called()

    def test_loader_executes_only_captured_whole_globals_despite_source_cache_and_ambient_replacement(self):
        import importlib.util,types,hashlib
        runtime=self.runtime;base=self.tree();captured=[];real_capture=runtime._capture_monitor_source
        cache=base/'toolchain-001/__pycache__';cache.mkdir()
        for name in ('pin_environment','link_inputs','monitor_inputs'):
            (cache/(name+'.'+sys.implementation.cache_tag+'.pyc')).write_bytes(b'inert poisoned cache')
        def capture(path,size,deadline):
            raw=real_capture(path,size,deadline);captured.append(Path(path).name)
            if len(captured)==3:
                for relative,original in self.sources.items():
                    (base/relative).write_bytes((b'raise AssertionError(456)'+bytes([10])).ljust(len(original),b' '))
            return raw
        ambient={name:types.ModuleType(name)for name in ('_v3_monitor_link_inputs','_v3_monitor_inputs',
            '_v3_monitor_pin_environment','callable_v3_link_inputs','callable_v3_monitor_inputs')}
        previous=sys.modules.get('_v3_monitor_link_inputs')
        try:
            with patch.object(runtime,'BASE',base),patch.object(runtime,'_capture_monitor_source',side_effect=capture), \
                    patch.object(importlib.util,'spec_from_file_location',side_effect=AssertionError('no pathname/pyc loader')), \
                    patch.dict(sys.modules,ambient):module=runtime._authenticated_monitor_loader()
            self.assertEqual(['pin_environment.py','link_inputs.py','monitor_inputs.py'],captured)
            self.assertIsNot(module.link_inputs,ambient['_v3_monitor_link_inputs'])
            self.assertIs(module.link_inputs,module._runtime_dependencies['link_inputs'])
            self.assertIs(module.monitor_inputs,module._runtime_dependencies['monitor_inputs'])
            self.assertIs(module.collect_pin.__globals__['link_inputs'],module.link_inputs)
            self.assertEqual('/leaf',module.link_inputs.logical('leaf'))
            resolver=module.link_inputs.Resolver('/authored');resolver.tick();self.assertEqual(1,resolver.work)
            self.assertEqual(20000,module.link_inputs.MAX_FILES);self.assertEqual(16777216,module.monitor_inputs.MAX_IMAGE)
            self.assertEqual(hashlib.sha256(b'authored').hexdigest(),module.link_inputs.sha(b'authored'))
            self.assertEqual({},module.monitor_inputs.strict_json(b'{}',module.link_inputs))
            with self.assertRaises(module.link_inputs.Refusal):module.monitor_inputs.path('/bad/../path',module.link_inputs)
            self.assertIs(sys.modules.get('_v3_monitor_link_inputs'),previous)
        finally:
            for relative,raw in self.sources.items():(base/relative).write_bytes(raw)

    def test_wrapper_checks_exact_root_interface_none_and_same_original_end_around_policy(self):
        runtime=self.runtime;actual_loader=runtime._authenticated_monitor_loader
        for mutation in (None,'file','base','name','interface','loader-late','policy-late','policy-error'):
            with self.subTest(mutation=mutation):
                base=self.tree();now=[0.0];ends=[];modules=[];primary=ValueError('authored policy refusal')
                def loaded(end):
                    ends.append(end);module=actual_loader(end);modules.append(module)
                    module._load_operational=Mock(return_value=(self.storage(),'a'*64))
                    policy=module.load_inspection_binding
                    def binding(profile):
                        if mutation=='policy-error':raise primary
                        value=policy(profile)
                        if mutation=='policy-late':now[0]=10.0
                        return value
                    module.load_inspection_binding=binding
                    if mutation=='file':module.__file__=str(base/'other.py')
                    elif mutation=='base':module.BASE=base/'other'
                    elif mutation=='name':module.__name__='_wrong_name'
                    elif mutation=='interface':module.load_inspection_binding=None
                    elif mutation=='loader-late':now[0]=10.0
                    return module
                with patch.object(runtime,'BASE',base),patch.dict(self.g,ROOT=base,_authenticated_monitor_loader=loaded), \
                        patch.object(runtime.time,'monotonic',side_effect=lambda:now[0]):
                    if mutation is None:
                        value=self.wrapper({},deadline=10.0);self.assertEqual('a'*64,value['environmentPinSha256'])
                    else:
                        with self.assertRaises((ValueError,TimeoutError,TypeError)) as caught:self.wrapper({},deadline=10.0)
                        if mutation=='policy-error':self.assertIs(primary,caught.exception)
                self.assertEqual([10.0],ends)
                if mutation in ('file','base','name','interface','loader-late'):modules[0]._load_operational.assert_not_called()
        base=self.tree();ends=[]
        def no_end(end):
            ends.append(end);module=actual_loader(end)
            module._load_operational=Mock(return_value=(self.storage(),'a'*64));return module
        with patch.object(runtime,'BASE',base),patch.dict(self.g,ROOT=base,_authenticated_monitor_loader=no_end), \
                patch.object(runtime.time,'monotonic',side_effect=AssertionError('None adds no timer')):
            self.assertEqual('a'*64,self.wrapper({})['environmentPinSha256'])
        self.assertEqual([None],ends)
        for invalid in (True,float('nan'),float('inf'),'10'):
            with patch.dict(self.g,_authenticated_monitor_loader=Mock(side_effect=AssertionError('before loader'))), \
                    self.assertRaises(ValueError):self.wrapper({},deadline=invalid)

    def test_actual_loader_late_capture_hash_compile_exec_refuses_and_closes_owned_descriptors_once(self):
        import builtins
        runtime=self.runtime
        for stage in ('capture','hash','compile','exec','close'):
            with self.subTest(stage=stage):
                base=self.tree();now=[0.0];active=set();acquired=[];closed=[]
                capture=runtime._capture_monitor_source;hashing=runtime.hashlib.sha256
                opening=runtime.os.open;closing=runtime.os.close
                def opened(*args,**kwargs):
                    descriptor=opening(*args,**kwargs);self.assertNotIn(descriptor,active)
                    active.add(descriptor);acquired.append(descriptor);return descriptor
                def close(descriptor):
                    self.assertIn(descriptor,active);active.remove(descriptor);closed.append(descriptor);closing(descriptor)
                    if stage=='close':now[0]=10.0
                def captured(*args,**kwargs):
                    value=capture(*args,**kwargs)
                    if stage=='capture':now[0]=10.0
                    return value
                def hashed(value=b'',*args,**kwargs):
                    result=hashing(value,*args,**kwargs)
                    if stage=='hash' and value in self.sources.values():now[0]=10.0
                    return result
                def compiled(*args,**kwargs):
                    value=builtins.compile(*args,**kwargs)
                    if stage=='compile':now[0]=10.0
                    return value
                def executed(*args,**kwargs):
                    value=builtins.exec(*args,**kwargs)
                    if stage=='exec':now[0]=10.0
                    return value
                with patch.object(runtime,'BASE',base),patch.dict(self.g,ROOT=base), \
                        patch.object(runtime.time,'monotonic',side_effect=lambda:now[0]), \
                        patch.object(runtime.os,'open',side_effect=opened),patch.object(runtime.os,'close',side_effect=close), \
                        patch.object(runtime,'_capture_monitor_source',side_effect=captured), \
                        patch.object(runtime.hashlib,'sha256',side_effect=hashed), \
                        patch.object(runtime,'compile',create=True,side_effect=compiled),patch.object(runtime,'exec',create=True,side_effect=executed):
                    with self.assertRaises(TimeoutError):self.wrapper({},deadline=10.0)
                self.assertFalse(active);self.assertEqual(len(acquired),len(closed))

    def test_real_operational_policy_uses_actual_json_collect_revalidate_resolver_and_binding(self):
        runtime=self.runtime;base=self.tree()
        with patch.object(runtime,'BASE',base):module=runtime._authenticated_monitor_loader()
        fixture=_InspectionOperationalFixture(base,module);original,raw,profile=fixture.record()
        real_loader=runtime._authenticated_monitor_loader;modules=[]
        def loaded(end):
            fresh=real_loader(end);modules.append(fresh);return fixture.transport(fresh)
        with patch.object(runtime,'BASE',base),patch.dict(self.g,ROOT=base,_authenticated_monitor_loader=loaded):
            binding=self.wrapper(profile)
        self.assertEqual(profile['toolchainEnvironmentPinSha256'],binding['environmentPinSha256'])
        self.assertEqual('/bin/bash',binding['bashPath']);self.assertEqual('/usr/bin/ldd',binding['scriptPath'])
        self.assertEqual('/etc/ld.so.cache',binding['cachePath'])
        self.assertEqual({'/bin/bash','/usr/bin/ldd','/etc/ld.so.cache','/runtime/ld-runtime.so','/runtime/libfixture.so.1'},
            {row['path']for row in binding['dependencies']})
        self.assertEqual(original['inspectionClosure'],binding['closure'])
        self.assertEqual('static-recording-unqualified',original['status'])
        self.assertTrue(all(root==Path('/')for root in fixture.roots));self.assertEqual(2,len(fixture.instances))
        self.assertIsNot(modules[0],module);self.assertIsNot(modules[0].link_inputs,module.link_inputs)
        self.assertTrue(all(instance.work<=200000 and instance.io_bytes<=536870912 for instance in fixture.instances))
        self.assertEqual(raw,(base/'toolchain-001/environment-pin.json').read_bytes())

    def test_real_operational_policy_rejects_missing_tampered_json_and_changed_runtime_without_policy_stubs(self):
        import hashlib
        runtime=self.runtime
        for mutation in ('missing','wrong-hash','duplicate-json','malformed-json','changed-runtime','wrong-public-path'):
            with self.subTest(mutation=mutation):
                base=self.tree()
                with patch.object(runtime,'BASE',base):module=runtime._authenticated_monitor_loader()
                fixture=_InspectionOperationalFixture(base,module)
                if mutation=='wrong-public-path':
                    fixture.manifest['monitor']['sourcePath']='/authored/wrong-public-source'
                    fixture.write('/authored/wrong-public-source',b'authored wrong source')
                    provision=json.loads(fixture.path(fixture.manifest['monitor']['provisioningManifestPath']).read_bytes())
                    provision['sourceSha256']=hashlib.sha256(b'authored wrong source').hexdigest()
                    provision['buildCommand'][-3]='/authored/wrong-public-source'
                    fixture.write(fixture.manifest['monitor']['provisioningManifestPath'],json.dumps(provision).encode())
                original,raw,profile=fixture.record();path=base/'toolchain-001/environment-pin.json'
                if mutation=='missing':path.unlink()
                elif mutation=='wrong-hash':path.write_bytes(raw+b' ')
                elif mutation in ('duplicate-json','malformed-json'):
                    data=b'{"x":1,"x":2}' if mutation=='duplicate-json' else b'{'
                    path.write_bytes(data);profile['toolchainEnvironmentPinSha256']=hashlib.sha256(data).hexdigest()
                elif mutation=='changed-runtime':fixture.write('/runtime/libfixture.so.1',fixture.path('/runtime/libfixture.so.1').read_bytes()+b'changed')
                actual=runtime._authenticated_monitor_loader
                def loaded(end):return fixture.transport(actual(end))
                with patch.object(runtime,'BASE',base),patch.dict(self.g,ROOT=base,_authenticated_monitor_loader=loaded):
                    with self.assertRaises(ValueError):self.wrapper(profile)
                if mutation in ('missing','wrong-hash','duplicate-json','malformed-json'):self.assertEqual(1,len(fixture.instances))


    def pinner_loader_vector(self,deadline,attack=None):
        import hashlib,stat
        runtime=self.runtime;profile,profile_sha=gate.load_profile_with_digest()
        fs=_PinFilesystem();root=Path('/fixture');work=root/'toolchain-001'
        fs.add('/etc',mode=stat.S_IFDIR|0o700)
        source=root/'record_identity_probe.cpp';schema=root/'contracts/helper-schema.json';binary=work/'record_identity_probe'
        clang=Path('/usr/lib/llvm/23/bin/clang')
        for path,data in ((source,b'authored source'),(schema,b'{}'),(binary,b'helper A'),(clang,b'clang A'),
                (work/'build_helper.py',b'builder'),(Path(self.g['__file__']),b'pinner'),
                (work/'helper-dependencies.d',('output: '+str(source)).encode()),
                (root/'worker_exec_proof.py',(ROOT/'worker_exec_proof.py').read_bytes())):fs.add(path,data)
        for relative,raw in self.sources.items():fs.add(root/relative,raw)
        def row(path):
            node=fs.metadata(fs.nodes[str(path)])
            return {'device':node.st_dev,'inode':node.st_ino,'mode':stat.S_IMODE(node.st_mode),
                    'sha256':hashlib.sha256(bytes(fs.nodes[str(path)]['data'])).hexdigest()}
        with patch.object(runtime,'BASE',root):
            build=_producer_execution({str(source):row(source)},phase='helper-build',profile_sha=profile_sha)
        build=gate.public_result(build);build.update(schemaVersion=3,sourceSha256=row(source)['sha256'],
            helperSchemaSha256=row(schema)['sha256'],binarySha256=row(binary)['sha256'])
        fs.add(work/'build.json',json.dumps(build).encode())
        paths={};record={'bashPath':'/bin/bash','scriptPath':'/usr/bin/ldd','cachePath':'/etc/ld.so.cache'};files={}
        for role,data in (('bash',bytes.fromhex('7f454c46')+b'bash'),
                ('script',b'#!/bin/bash'+bytes([10])+b'# inert'),('cache',b'cache')):
            path=root/role;paths[role]=str(path);fs.add(path,data)
            files[record[role+'Path']]={'realpath':str(path),'sha256':row(path)['sha256']}
        for name in ('/usr/lib/llvm/23/bin/clang++','/usr/bin/ld','/usr/bin/as'):fs.add(name,b'host tool')
        fs.add('/selected/dependency',b'authored selected input')
        operational={'inspectionClosure':{'record':record,'files':files}}
        actual_loader=runtime._authenticated_monitor_loader;modules=[];ends=[];order=[];parses=[]
        def loaded(end):
            order.append('load');ends.append(end);module=actual_loader(end);modules.append(module)
            # This integration case isolates authenticated policy selection;
            # real operational JSON/revalidation is exercised separately above.
            module._load_operational=Mock(return_value=(operational,profile['toolchainEnvironmentPinSha256']))
            return module
        def corrupt():
            name=root/'toolchain-001/pin_environment.py';node=fs.nodes[str(name)]
            node['data']=bytearray((b'raise AssertionError(789)'+bytes([10])).ljust(node['size'],b' '))
        if attack=='before-load':corrupt()
        executions=[]
        def run(argv,*args,**kwargs):
            order.append('worker')
            tool=(binary,clang)[len(executions)]
            self.assertEqual(paths['bash'],argv[0]);self.assertEqual(str(tool),argv[2])
            if deadline is None:self.assertNotIn('phase_deadline',kwargs)
            else:self.assertEqual(deadline,kwargs['phase_deadline'])
            result=_producer_execution({str(tool):row(tool)},phase='elf-inspection',profile_sha=profile_sha,
                target=(paths['bash'],row(paths['bash'])),stdout=b'/selected/dependency'+bytes([10]))
            executions.append(result)
            if attack=='post-worker-load':corrupt()
            return result
        class Leaf:
            path=root/'inspection'
            def __enter__(self):return self
            def __exit__(self,*args):return False
            def run(self,operation,*args,**kwargs):return operation(*args,**kwargs)
        actual_recipe=self.g['inspection_recipe'];actual_paths=self.g['_stdout_paths']
        def recipe(*args,**kwargs):order.append('recipe');return actual_recipe(*args,**kwargs)
        def parsed(raw,ledger):parses.append(raw);return actual_paths(raw,ledger)
        profiles=Mock(side_effect=[profile,(profile,profile_sha)]);recipes=Mock(side_effect=recipe)
        with patch.object(runtime,'BASE',root),fs.effects(self.g), \
                patch.object(runtime.os,'lstat',side_effect=lambda path,*args,**kwargs:fs.stat(path,**kwargs)), \
                patch.dict(self.g,ROOT=root,load_profile=profiles,load_profile_with_digest=profiles,
                    _authenticated_monitor_loader=loaded,owned_worker_leaf=Mock(return_value=Leaf()),
                    contained_command=lambda argv,*args,**kwargs:argv,bounded_run=run,inspection_recipe=recipes,_stdout_paths=parsed):
            error=result=None
            try:result=self.functions['pin']('pin.json','build.json',**({'deadline':deadline}if deadline is not None else {}))
            except ValueError as failure:error=failure
        if attack is not None:
            self.assertIsNotNone(error);self.assertEqual('authenticated monitor loader source bytes differ',str(error))
            self.assertIsNone(result);self.assertNotIn(str(work/'pin.json'),fs.nodes);self.assertEqual([],parses)
            self.assertEqual(0 if attack=='before-load' else 1,len(executions))
            if attack=='post-worker-load':self.assertIs(executions[0],error.bounded_result)
            self.assertFalse(fs.fds);return
        self.assertIsNone(error)
        self.assertEqual([deadline]*5,ends);self.assertEqual(5,len(modules));self.assertEqual(4,recipes.call_count)
        self.assertEqual(2,profiles.call_count);self.assertEqual(2,len(executions))
        self.assertEqual(['load','load','recipe','worker','load','recipe','load','recipe','worker','load','recipe'],order)
        self.assertEqual(2,len(parses))
        self.assertEqual(5,len({id(module)for module in modules}))
        self.assertTrue(all(module.link_inputs is module._runtime_dependencies['link_inputs']for module in modules))
        self.assertTrue(all(module._load_operational.call_count==1 for module in modules))
        self.assertIn('/selected/dependency',result['dependencies']);self.assertIn(str(work/'pin.json'),fs.nodes)
        policy_names={str(root/relative)for relative in self.sources}
        reads=[event for event in fs.events if event[0]=='read' and event[1]in policy_names]
        self.assertEqual(318155,sum(event[2]for event in reads if event[2]>1))
        self.assertEqual(15,sum(event[2]==1 for event in reads));self.assertFalse(fs.fds)

    def test_actual_pinner_uses_five_real_authenticated_loads_with_explicit_storage_boundary(self):
        for deadline in (None,10.0):
            for attack in (None,'before-load','post-worker-load'):
                with self.subTest(deadline=deadline,attack=attack):self.pinner_loader_vector(deadline,attack)


class _PublicationFilesystem:
    """Injected metadata/stream transport; never opens a host FD or path."""
    def __init__(self):
        import stat
        self.nodes=[];self.entries={};self.fds={};self.events=[];self.streams=[]
        self.hook=None;self.next_fd=100;self.short=None
        self.slash=self.node(stat.S_IFDIR|0o755)
        self.root=self.node(stat.S_IFDIR|0o755)
        self.directory=self.node(stat.S_IFDIR|0o755)
        self.entries[(self.slash['ino'],'fixture')]=self.root
        self.entries[(self.root['ino'],'toolchain-001')]=self.directory

    def node(self,mode,data=b''):
        node={'dev':1,'ino':len(self.nodes)+1,'mode':mode,'uid':42,'gid':43,
              'nlink':1,'size':len(data),'mtime':1,'ctime':1,'data':bytearray(data)}
        self.nodes.append(node);return node

    def event(self,kind,*facts):
        self.events.append((kind,)+facts)
        if self.hook is not None:self.hook(kind,*facts)

    def metadata(self,node):
        from types import SimpleNamespace
        return SimpleNamespace(st_dev=node['dev'],st_ino=node['ino'],st_mode=node['mode'],
            st_uid=node['uid'],st_gid=node['gid'],st_nlink=node['nlink'],st_size=node['size'],
            st_mtime_ns=node['mtime'],st_ctime_ns=node['ctime'])

    def lookup(self,name,dir_fd=None):
        if dir_fd is None:
            if name!='/':raise AssertionError('unexpected absolute pathname lookup')
            return self.slash
        return self.entries[(self.fds[dir_fd]['ino'],name)]

    def open(self,name,flags,mode=0o777,*,dir_fd=None):
        import os,stat
        self.event('open',name,flags,mode,dir_fd)
        if flags&os.O_CREAT:
            if dir_fd is None:raise AssertionError('publication must be relative to held A')
            key=(self.fds[dir_fd]['ino'],name)
            if key in self.entries:raise FileExistsError(name)
            node=self.node(stat.S_IFREG|mode);self.entries[key]=node
        else:
            node=self.lookup(name,dir_fd)
            if flags&os.O_DIRECTORY and not stat.S_ISDIR(node['mode']):raise OSError('nofollow directory refusal')
        self.next_fd+=1;fd=self.next_fd;self.fds[fd]=node
        self.events.append(('acquired',fd,node['ino']));return fd

    def fstat(self,fd):
        self.event('fstat',fd,self.fds[fd]);return self.metadata(self.fds[fd])

    def stat(self,name,*,dir_fd=None,follow_symlinks=True):
        if follow_symlinks:raise AssertionError('nofollow metadata required')
        self.event('stat',name,dir_fd);return self.metadata(self.lookup(name,dir_fd))

    def chmod(self,fd,mode):
        import stat
        self.event('chmod',fd,mode);node=self.fds[fd]
        node['mode']=stat.S_IFMT(node['mode'])|mode;node['ctime']+=1

    def replace(self,source,destination,*,src_dir_fd=None,dst_dir_fd=None):
        self.event('replace',source,destination,src_dir_fd,dst_dir_fd)
        if src_dir_fd is None or dst_dir_fd!=src_dir_fd:raise AssertionError('same held directory required')
        inode=self.fds[src_dir_fd]['ino'];node=self.entries.pop((inode,source))
        self.events.append(('renamed-source',node['ino']))
        self.entries[(inode,destination)]=node;node['ctime']+=1
        self.event('replaced',source,destination,src_dir_fd,dst_dir_fd)

    def close(self,fd):
        node=self.fds.pop(fd);self.event('close',fd,node)

    def fdopen(self,fd,mode,*,closefd):
        if closefd:raise AssertionError('only enclosing FD owner may close')
        self.event('fdopen',fd,mode);fs=self
        class Stream:
            def __init__(self):self.closed=False
            def write(self,value):
                fs.event('write',fd,value)
                count=len(value) if fs.short is None else min(fs.short,len(value))
                block=value[:count];raw=block.encode('utf-8') if type(block)is str else block
                node=fs.fds[fd];node['data'].extend(raw);node['size']+=len(raw);node['mtime']+=1
                return count
            def flush(self):fs.event('flush',fd)
            def fileno(self):return fd
            def close(self):
                if self.closed:raise AssertionError('stream closed twice')
                self.closed=True;fs.event('stream-close',fd)
        stream=Stream();self.streams.append(stream);return stream

    def effects(self,module):
        from contextlib import ExitStack
        stack=ExitStack();ops=module['os']
        for name,operation in (('open',self.open),('fstat',self.fstat),('stat',self.stat),
                ('fchmod',self.chmod),('replace',self.replace),('close',self.close),('fdopen',self.fdopen)):
            stack.enter_context(patch.object(ops,name,side_effect=operation))
        stack.enter_context(patch.object(ops,'getuid',return_value=42))
        stack.enter_context(patch.object(ops,'unlink',side_effect=AssertionError('no namespace deletion authority')))
        stack.enter_context(patch.object(module['uuid'],'uuid4',return_value=Mock(hex='a'*32)))
        return stack


class HelperPublicationDirectory(unittest.TestCase):
    def setUp(self):
        self.module=runpy.run_path(str(ROOT/'toolchain-001/build_helper.py'),run_name='inert_import')
        self.directory=self.module['_PublicationDirectory'];self.publish=self.module['publish']

    def assert_closed_once(self,fs):
        acquired=[e[1]for e in fs.events if e[0]=='acquired']
        closed=[e[1]for e in fs.events if e[0]=='close']
        self.assertEqual(sorted(acquired),sorted(closed));self.assertEqual(len(closed),len(set(closed)))
        self.assertFalse(fs.fds);self.assertTrue(all(stream.closed for stream in fs.streams))

    def test_publication_same_A_bytes_modes_receipt_and_progress_use_only_retained_descriptors(self):
        import os
        fs=_PublicationFilesystem();fs.short=2
        with fs.effects(self.module):
            with self.directory(Path('/fixture')) as directory:
                chosen=directory.fd
                self.publish(directory,'helper-dependencies.d',b'authored dependencies',0o600)
                self.publish(directory,'record_identity_probe',b'authored binary',0o700)
                result={'schemaVersion':3,'publication':{'published':True},'unicode':'☃'}
                # Text receipt uses the original JSON stream, not the short binary-write vector.
                fs.short=None;directory.receipt('result.json',result)
        parent=fs.directory['ino'];dependency=fs.entries[(parent,'helper-dependencies.d')]
        binary=fs.entries[(parent,'record_identity_probe')];receipt=fs.entries[(parent,'result.json')]
        self.assertEqual(b'authored dependencies',bytes(dependency['data']))
        self.assertEqual(b'authored binary',bytes(binary['data']))
        self.assertEqual(0o600,dependency['mode']&0o7777);self.assertEqual(0o700,binary['mode']&0o7777)
        self.assertEqual((json.dumps(result,indent=2)+'\n').encode(),bytes(receipt['data']))
        publications=[event for event in fs.events if event[0]=='replace']
        self.assertEqual(['helper-dependencies.d','record_identity_probe'],[event[2]for event in publications])
        self.assertTrue(all(event[3:]==(chosen,chosen)for event in publications))
        files=[e for e in fs.events if e[0]=='open'and e[2]&os.O_CREAT]
        self.assertEqual(3,len(files));self.assertTrue(all(e[4]==chosen for e in files))
        for event in files:
            for flag in (os.O_EXCL,os.O_NOFOLLOW,os.O_NONBLOCK,os.O_CLOEXEC):self.assertTrue(event[2]&flag)
        self.assertEqual(0o666,files[-1][3]);self.assert_closed_once(fs)
        # Existing real raw-proof build vectors still exercise complete/nonzero routing.
        case=ProducerLaunchInputJoins(methodName='runTest');case.setUp()
        case.build_vector();case.build_vector(exit_code=3)

    def test_publication_admission_refuses_symlink_uid_and_original_parent_replacement(self):
        import stat
        for attack in ('root-symlink','child-symlink','root-uid','child-uid','replaced-before-create'):
            fs=_PublicationFilesystem()
            if attack=='root-symlink':fs.root['mode']=stat.S_IFLNK|0o777
            elif attack=='child-symlink':fs.directory['mode']=stat.S_IFLNK|0o777
            elif attack=='root-uid':fs.root['uid']=99
            elif attack=='child-uid':fs.directory['uid']=99
            with self.subTest(attack=attack),fs.effects(self.module):
                with self.assertRaises((ValueError,OSError)):
                    with self.directory(Path('/fixture')) as directory:
                        fs.entries[(fs.root['ino'],'toolchain-001')]=fs.node(stat.S_IFDIR|0o755)
                        self.publish(directory,'record_identity_probe',b'not credited',0o700)
            self.assertFalse(any(e[0]=='write'for e in fs.events));self.assert_closed_once(fs)
        for root in (Path('relative'),Path('/fixture/../other'),Path('/'+'/'.join(['x']*128)),Path('/'+'x'*4096)):
            fs=_PublicationFilesystem()
            with self.subTest(root=root),fs.effects(self.module),self.assertRaises(ValueError):
                with self.directory(root):self.fail('invalid path admitted')
            self.assertEqual([],fs.events)

    def test_publication_parent_swap_at_write_rename_between_outputs_and_receipt_never_rebases(self):
        import stat
        for stage in ('write','rename','between-outputs','before-receipt'):
            fs=_PublicationFilesystem();replacement=fs.node(stat.S_IFDIR|0o755)
            def swapped():fs.entries[(fs.root['ino'],'toolchain-001')]=replacement
            fired=[]
            def hook(kind,*facts):
                if not fired and ((stage=='write'and kind=='write')or(stage=='rename'and kind=='replace')):
                    fired.append(True);swapped()
            fs.hook=hook
            with self.subTest(stage=stage),fs.effects(self.module):
                with self.assertRaisesRegex(ValueError,'named publication parent changed'):
                    with self.directory(Path('/fixture')) as directory:
                        self.publish(directory,'helper-dependencies.d',b'dependencies',0o600)
                        if stage=='between-outputs':swapped()
                        self.publish(directory,'record_identity_probe',b'binary',0o700)
                        if stage=='before-receipt':swapped()
                        directory.receipt('result.json',{'publication':{'published':True}})
            self.assertFalse(any(parent==replacement['ino']for parent,name in fs.entries))
            self.assertFalse(any(e[0]=='open'and e[1]=='result.json'for e in fs.events))
            self.assert_closed_once(fs)

    def test_publication_temp_entry_check_is_not_same_uid_atomic_rename_authority(self):
        import stat
        for restored in (False,True):
            fs=_PublicationFilesystem();different=fs.node(stat.S_IFREG|0o700,b'B')
            original=[]
            def hook(kind,*facts):
                if kind=='stat'and facts[0].startswith('.helper-publish-')and not restored:
                    fs.entries[(fs.directory['ino'],facts[0])]=different
                if kind=='replace'and restored:
                    key=(fs.directory['ino'],facts[0]);original.append(fs.entries[key]);fs.entries[key]=different
                if kind=='replaced'and restored:
                    fs.entries[(fs.directory['ino'],facts[1])]=original[0]
            fs.hook=hook
            with self.subTest(restored=restored),fs.effects(self.module):
                with self.directory(Path('/fixture')) as directory:
                    if restored:
                        # Counterexample: B really was selected by rename; later A observation is not exclusion.
                        self.publish(directory,'record_identity_probe',b'A',0o700)
                    else:
                        with self.assertRaisesRegex(ValueError,'temporary entry changed'):
                            self.publish(directory,'record_identity_probe',b'A',0o700)
            renamed=[e[1]for e in fs.events if e[0]=='renamed-source']
            self.assertEqual([different['ino']]if restored else [],renamed)
            self.assert_closed_once(fs)

    def test_publication_actual_faults_preserve_primary_and_once_close_without_name_cleanup(self):
        for stage in ('open-file','fstat-file','fdopen','write','flush','chmod','replace','stream-close','close-file'):
            fs=_PublicationFilesystem();primary=MemoryError('authored '+stage);fired=[]
            def hook(kind,*facts):
                is_file=(kind=='open'and facts[0].startswith('.helper-publish-'))
                match=(stage=='open-file'and is_file or stage=='fstat-file'and kind=='fstat'and 'data'in facts[1]and
                    facts[1]['mode']&0o170000==0o100000 or stage==kind or
                    stage=='close-file'and kind=='close'and facts[1]['mode']&0o170000==0o100000)
                if match and not fired:fired.append(True);raise primary
            fs.hook=hook
            with self.subTest(stage=stage),fs.effects(self.module):
                with self.assertRaises(MemoryError)as caught:
                    with self.directory(Path('/fixture')) as directory:
                        self.publish(directory,'record_identity_probe',b'authored',0o700)
            self.assertIs(primary,caught.exception);self.assertEqual([True],fired);self.assert_closed_once(fs)
            self.assertLessEqual(sum(e[0]=='replace'for e in fs.events),1)
        for progress in (0,False,None,999999):
            fs=_PublicationFilesystem()
            with self.subTest(progress=progress),fs.effects(self.module):
                with self.assertRaisesRegex(ValueError,'invalid progress'):
                    with self.directory(Path('/fixture')) as directory:
                        original=fs.fdopen
                        def stream(*args,**kwargs):
                            value=original(*args,**kwargs);value.write=Mock(return_value=progress);return value
                        with patch.object(self.module['os'],'fdopen',side_effect=stream):
                            self.publish(directory,'record_identity_probe',b'authored',0o700)
            self.assertFalse(any(e[0]=='replace'for e in fs.events));self.assert_closed_once(fs)
        fs=_PublicationFilesystem()
        with fs.effects(self.module):
            with self.directory(Path('/fixture')) as directory:
                temporary='.helper-publish-'+'a'*32
                fs.entries[(fs.directory['ino'],temporary)]=fs.node(0o100600,b'other')
                with self.assertRaises(FileExistsError):self.publish(directory,'record_identity_probe',b'authored',0o700)
        self.assertEqual(1,sum(e[0]=='open'and e[1]==temporary for e in fs.events));self.assert_closed_once(fs)

    def test_publication_partial_depfile_then_binary_or_receipt_failure_never_rolls_back(self):
        for target in ('binary','receipt'):
            fs=_PublicationFilesystem();primary=OSError('authored partial failure')
            def hook(kind,*facts):
                if target=='binary'and kind=='replace'and facts[1]=='record_identity_probe':raise primary
                if target=='receipt'and kind=='open'and facts[0]=='result.json':raise primary
            fs.hook=hook;returned=[]
            with self.subTest(target=target),fs.effects(self.module):
                with self.assertRaises(OSError)as caught:
                    with self.directory(Path('/fixture')) as directory:
                        self.publish(directory,'helper-dependencies.d',b'dependencies',0o600)
                        self.publish(directory,'record_identity_probe',b'binary',0o700)
                        directory.receipt('result.json',{'publication':{'published':True}})
                        returned.append(True)
            self.assertIs(primary,caught.exception);self.assertEqual([],returned)
            self.assertEqual(b'dependencies',bytes(fs.entries[(fs.directory['ino'],'helper-dependencies.d')]['data']))
            self.assertNotIn((fs.directory['ino'],'result.json'),fs.entries);self.assert_closed_once(fs)

    def test_publication_close_failures_do_not_replace_body_or_claim_error_atomic_receipts(self):
        class DeniedNotes(ValueError):
            def add_note(self,*args):raise AssertionError('diagnostic annotation denied')
            def __setattr__(self,*args):raise AssertionError('diagnostic attribute denied')
        for body_fails in (False,True):
            fs=_PublicationFilesystem();body=DeniedNotes('original body');cleanup=OSError('close uncertain');fired=[]
            def hook(kind,*facts):
                if kind=='close'and not fired:fired.append(True);raise cleanup
            with self.subTest(body_fails=body_fails),fs.effects(self.module):
                with self.assertRaises((DeniedNotes,OSError))as caught:
                    with self.directory(Path('/fixture')) as directory:
                        directory.receipt('result.json',{'publication':{'published':True}})
                        fs.hook=hook
                        if body_fails:raise body
            self.assertIs(body if body_fails else cleanup,caught.exception)
            # A complete-looking receipt is retained after a later refusal, not authenticated success.
            raw=bytes(fs.entries[(fs.directory['ino'],'result.json')]['data'])
            self.assertTrue(json.loads(raw)['publication']['published']);self.assert_closed_once(fs)
            acquired=[e[1]for e in fs.events if e[0]=='acquired'][:3]
            closed=[e[1]for e in fs.events if e[0]=='close'][-3:]
            self.assertEqual(list(reversed(acquired)),closed)

    def test_publication_receipt_lexical_utf8_and_exclusive_rules_refuse_before_work(self):
        validate=self.module['_receipt_component']
        for name in (None,1,'','.', '..','a/b','a/../b','/absolute','bad\0name',
                     'helper-dependencies.d','record_identity_probe','x'*256,'é'*128,'\ud800'):
            with self.subTest(name=name),self.assertRaises((ValueError,UnicodeError)):validate(name)
        for name in ('result.json','é'*127+'a','x'*255):self.assertEqual(name,validate(name))
        for mode in (0o100600,0o120777):
            fs=_PublicationFilesystem();existing=fs.node(mode,b'unchanged')
            fs.entries[(fs.directory['ino'],'result.json')]=existing
            with self.subTest(mode=mode),fs.effects(self.module):
                with self.directory(Path('/fixture')) as directory:
                    with self.assertRaises(FileExistsError):directory.receipt('result.json',{})
            self.assertEqual(b'unchanged',bytes(existing['data']));self.assert_closed_once(fs)
        build=self.module['build'];profile=Mock(side_effect=AssertionError('invalid name before profile or filesystem'))
        with patch.dict(build.__globals__,load_profile_with_digest=profile):
            with self.assertRaises(ValueError):build('../escape')
        profile.assert_not_called()

    def test_publication_stable_directory_identity_allows_own_work_nlink_but_refuses_identity_changes(self):
        for change in (None,'dev','ino','mode','uid','gid'):
            fs=_PublicationFilesystem()
            with self.subTest(change=change),fs.effects(self.module):
                with self.directory(Path('/fixture')) as directory:
                    # First owned worker-work mkdir and ordinary publication metadata must be allowed.
                    for node in (fs.root,fs.directory):
                        node['nlink']+=1;node['size']+=4096;node['mtime']+=1;node['ctime']+=1
                    directory.check()
                    if change is None:
                        self.publish(directory,'record_identity_probe',b'authored',0o700)
                    else:
                        old=fs.directory[change];fs.directory[change]+=1
                        with self.assertRaisesRegex(ValueError,'held publication parent changed'):directory.check()
                        fs.directory[change]=old
            self.assert_closed_once(fs)


if __name__ == '__main__':
    unittest.main()
