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
                result=completed_result(exit_code=1)
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
                return completed_result()
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
        profile=gate.load_profile();runner=Mock(return_value=result);loader=Mock(return_value=binding);profiles=Mock(return_value=profile)
        class Leaf:
            path=root/'inspection'
            def __enter__(self):return self
            def __exit__(self,*args):return False
            def run(self,operation,*args,**kwargs):return operation(*args,**kwargs)
        recipe=self.g['inspection_recipe'];recipes=Mock(wraps=recipe);ledger=self.g['_Ledger']()
        with fs.effects(self.g),patch.dict(self.g,ROOT=root,load_profile=profiles,load_inspection_binding=loader,
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


if __name__ == '__main__':
    unittest.main()
