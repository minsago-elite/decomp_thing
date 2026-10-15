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
                result=completed_result(json.dumps(refusal).encode(),exit_code=2,target_sha=helper_sha)
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


if __name__ == '__main__':
    unittest.main()
