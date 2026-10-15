"""V3 inert profile/command regressions. Native qualification is a later gate."""
from pathlib import Path
from contextlib import contextmanager, ExitStack
from types import SimpleNamespace
import hashlib
import stat
import sys
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from build_contract import load_profile, validate_profile
import build_contract as contract
from evaluate_candidate_v3 import phase_command,runtime_command


class Contracts(unittest.TestCase):
    def test_profile_is_closed_without_tool_launch(self):
        value=load_profile();self.assertEqual(value['schemaVersion'],3)
        value['candidateCalled']=True
        with self.assertRaises(ValueError):validate_profile(value)
    def test_candidate_build_mounts_only_own_work(self):
        command=phase_command(Path('/synthetic/candidate'),['/usr/bin/gcc','-E','/work/candidate.c'])
        self.assertIn('/synthetic/candidate',command)
        self.assertNotIn('/synthetic/expected',command)
        self.assertIn('--unshare-all',command)
    def test_runtime_mounts_caller_and_library_without_private_sources(self):
        command=runtime_command(Path('/synthetic/caller'),Path('/synthetic/library'),0)
        self.assertIn('--clearenv',command);self.assertIn('/caller',command)
        self.assertNotIn('original.c',' '.join(command));self.assertNotIn('original.h',' '.join(command))


class JsonSnapshots(unittest.TestCase):
    @contextmanager
    def snapshot(self, data=b'{"value":1}', fault=None, size=None, mode=stat.S_IFREG, *, leafname='document.json'):
        facts={'opened':[], 'closed':[], 'reads':[], 'offset':0, 'eof':False}
        def metadata(directory=False, changed=False):
            return SimpleNamespace(st_dev=1,st_ino=(9 if changed else 2) if directory else (8 if changed else 3),
                st_mode=(stat.S_IFDIR|0o755) if directory else (mode|0o600),st_uid=1000,st_gid=1000,
                st_nlink=1,st_size=0 if directory else (len(data) if size is None else size),
                st_mtime_ns=4,st_ctime_ns=5)
        def opened(name,flags,**kwargs):
            facts['opened'].append((name,flags,kwargs))
            if fault=='parent-symlink' and name=='fixture':raise OSError('authored parent link refusal')
            if fault=='leaf-symlink' and name==leafname:raise OSError('authored leaf link refusal')
            return {'/':10,'fixture':11,leafname:12}[name]
        def observed(fd):
            if fault=='metadata' and fd==12:raise OSError('authored metadata refusal')
            return metadata(fd!=12, fault=='version' and fd==12 and facts['eof'])
        def named(name,**kwargs):
            self.assertIs(False,kwargs['follow_symlinks'])
            changed=((fault=='before-replacement' and name==leafname) or
                     facts['eof'] and ((fault=='replacement' and name==leafname) or
                                      (fault=='parent-replacement' and name=='fixture')))
            return metadata(name!=leafname,changed)
        def read(fd,count):
            self.assertEqual(12,fd);self.assertLessEqual(count,65536);facts['reads'].append(count)
            if fault=='read-error':raise OSError('authored read refusal')
            if fault in ('truncate','truncate-close'):
                return b''
            offset=facts['offset'];block=data[offset:offset+count];facts['offset']+=len(block)
            if not block:
                facts['eof']=True
                if fault=='growth':return b'x'
            return block
        def close(fd):
            facts['closed'].append(fd)
            if fault in ('close','truncate-close') and fd==12:raise OSError('authored close refusal')
        with ExitStack() as stack:
            for name,value in (('open',opened),('fstat',observed),('stat',named),('read',read),('close',close)):
                stack.enter_context(patch.object(contract.os,name,side_effect=value))
            yield facts

    def test_exact_bound_same_bytes_and_chunk_ceiling(self):
        data=b'"'+b'a'*65536+b'"'
        with self.snapshot(data) as facts:
            value,digest=contract._read_json(Path('/fixture/document.json'),len(data))
        self.assertEqual('a'*65536,value);self.assertEqual(hashlib.sha256(data).hexdigest(),digest)
        self.assertEqual([65536,2,1],facts['reads']);self.assertEqual([12,11,10],facts['closed'])
        leaf=facts['opened'][-1]
        self.assertEqual(contract.os.O_RDONLY|contract.os.O_NOFOLLOW|contract.os.O_NONBLOCK|contract.os.O_CLOEXEC,leaf[1])
        self.assertEqual({'dir_fd':11},leaf[2])
        self.assertTrue(all(flags & contract.os.O_DIRECTORY and flags & contract.os.O_NOFOLLOW
                            for _,flags,_ in facts['opened'][:-1]))

    def test_special_and_oversize_admitted_before_read(self):
        for mode,size in ((stat.S_IFIFO,0),(stat.S_IFCHR,0),(stat.S_IFREG,9)):
            with self.subTest(mode=mode,size=size),self.snapshot(size=size,mode=mode) as facts:
                with self.assertRaisesRegex(ValueError,'regular file byte bound'):
                    contract._read_json(Path('/fixture/document.json'),8)
            self.assertEqual([],facts['reads']);self.assertEqual([12,11,10],facts['closed'])

    def test_links_and_metadata_failures_close_every_acquired_handle(self):
        for fault,closed in (('parent-symlink',[10]),('leaf-symlink',[11,10]),('metadata',[12,11,10])):
            with self.subTest(fault=fault),self.snapshot(fault=fault) as facts:
                with self.assertRaises(OSError):contract._read_json(Path('/fixture/document.json'),1024)
            self.assertEqual(closed,facts['closed']);self.assertEqual([],facts['reads'])

    def test_named_leaf_replacement_before_read_is_not_consumed(self):
        with self.snapshot(fault='before-replacement') as facts:
            with self.assertRaisesRegex(ValueError,'changed before read'):
                contract._read_json(Path('/fixture/document.json'),1024)
        self.assertEqual([],facts['reads']);self.assertEqual([12,11,10],facts['closed'])

    def test_growth_truncation_version_and_parent_leaf_replacement_refuse(self):
        for fault,reason in (('growth','grew'),('truncate','truncated'),('version','changed during'),
                             ('replacement','changed during'),('parent-replacement','named parent changed')):
            with self.subTest(fault=fault),self.snapshot(fault=fault) as facts:
                with self.assertRaisesRegex(ValueError,reason):contract._read_json(Path('/fixture/document.json'),1024)
            self.assertEqual([12,11,10],facts['closed'])

    def test_close_failure_refuses_success_and_preserves_existing_primary(self):
        with self.snapshot(fault='close') as facts:
            with self.assertRaisesRegex(OSError,'close refusal'):contract._read_json(Path('/fixture/document.json'),1024)
        self.assertEqual([12,11,10],facts['closed'])
        # An exception handled by the caller is not this reader's primary failure.
        try:
            raise ValueError('authored outer handled exception')
        except ValueError:
            with self.snapshot(fault='close'):
                with self.assertRaisesRegex(OSError,'close refusal'):
                    contract._read_json(Path('/fixture/document.json'),1024)
        with self.snapshot(fault='truncate-close') as facts:
            with self.assertRaisesRegex(ValueError,'truncated') as caught:
                contract._read_json(Path('/fixture/document.json'),1024)
        self.assertEqual(['contract descriptor cleanup failures: 1'],caught.exception.__notes__)
        self.assertEqual([12,11,10],facts['closed'])
        with self.snapshot(fault='read-error') as facts:
            with self.assertRaisesRegex(OSError,'read refusal'):contract._read_json(Path('/fixture/document.json'),1024)
        self.assertEqual([12,11,10],facts['closed'])

    def test_json_policy_and_empty_input_preserved(self):
        for raw,reason in ((b'{"x":1,"x":2}','duplicate'),(b'NaN','nonfinite'),
                           (b'{','invalid contract JSON'),(b'\xff','invalid contract JSON'),(b'','invalid contract JSON')):
            with self.subTest(raw=raw),self.snapshot(raw) as facts:
                with self.assertRaisesRegex(ValueError,reason):contract._read_json(Path('/fixture/document.json'),1024)
            self.assertEqual([12,11,10],facts['closed'])

    def test_path_and_maximum_bounds_refuse_before_open(self):
        for path,maximum in ((Path('/fixture/../document.json'),1),(Path('/'+'/'.join(['a']*128)+'/x'),1),
                             (Path('/'+'a'*4096),1),(Path('/fixture/document.json'),-1),
                             (Path('/fixture/document.json'),True)):
            with self.subTest(path=path,maximum=maximum),patch.object(contract.os,'open') as opened:
                with self.assertRaises(ValueError):contract._read_json(path,maximum)
                opened.assert_not_called()


    @contextmanager
    def visible_prompt(self, *, raw=None, exactcap=False, fault=None, size=None, mode=stat.S_IFREG):
        # Authored contract/render bytes; no host GCC/profile reads and no prompt JSON parse.
        value={'target':'authored UTF-8 café',
               'commands':{'preprocess':['authored','-E'],'compile':['authored','-c'],'link':['authored','-shared']},
               'exports':'authored exports'}
        if exactcap:
            value['exports']=''
            # Each ordinary export character appears twice in _render. A newline
            # contributes three bytes across the direct and JSON spellings.
            if (contract.MAXIMUM_VISIBLE_BYTES-len(contract._render(value).encode('utf-8'))) % 2:
                value['exports']='\n'
            remaining=contract.MAXIMUM_VISIBLE_BYTES-len(contract._render(value).encode('utf-8'))
            self.assertGreaterEqual(remaining,0);self.assertEqual(0,remaining % 2)
            value['exports']+='x'*(remaining//2)
        expected=contract._render(value).encode('utf-8')
        if exactcap:self.assertEqual(contract.MAXIMUM_VISIBLE_BYTES,len(expected))
        digest='a'*64
        manifest={'schemaVersion':3,'profile':value,'profileSha256':digest}
        def read_manifest(path,maximum):
            self.assertEqual(Path('/fixture/visible-manifest.json'),path)
            self.assertEqual(contract.MAXIMUM_VISIBLE_BYTES,maximum)
            return manifest,'b'*64
        with self.snapshot(expected if raw is None else raw,fault,size,mode,leafname='prompt.txt') as facts, \
                patch.object(contract,'_visible_snapshot',return_value=(value,digest)) as profile, \
                patch.object(contract,'_read_json',side_effect=read_manifest) as reading_manifest, \
                patch.object(Path,'open',side_effect=AssertionError('prompt must not use blocking pathname stream')), \
                patch.object(contract,'digest',side_effect=AssertionError('authored visible control forbids host tool reads')):
            facts['expectedPrompt']=expected
            yield facts
            profile.assert_called_once_with()
            reading_manifest.assert_called_once_with(Path('/fixture/visible-manifest.json'),contract.MAXIMUM_VISIBLE_BYTES)

    def test_verify_visible_uses_bounded_snapshot_for_utf8_and_exact_prompt_cap(self):
        for exactcap in (False,True):
            with self.subTest(exactcap=exactcap),self.visible_prompt(exactcap=exactcap) as facts:
                contract.verify_visible(Path('/fixture'))
            self.assertEqual(len(facts['expectedPrompt']),facts['offset'])
            self.assertEqual([12,11,10],facts['closed']);self.assertEqual(1,facts['reads'][-1])
            if exactcap:self.assertEqual([65536,65536,1],facts['reads'])
            else:self.assertIn('café'.encode('utf-8'),facts['expectedPrompt'])
            leaf=facts['opened'][-1]
            self.assertEqual('prompt.txt',leaf[0]);self.assertEqual({'dir_fd':11},leaf[2])
            self.assertEqual(contract.os.O_RDONLY|contract.os.O_NOFOLLOW|contract.os.O_NONBLOCK|contract.os.O_CLOEXEC,leaf[1])
            self.assertTrue(all(flags & contract.os.O_DIRECTORY and flags & contract.os.O_NOFOLLOW
                                for _,flags,_ in facts['opened'][:-1]))

    def test_verify_visible_rejects_fifo_special_and_oversize_before_prompt_read(self):
        for mode,size in ((stat.S_IFIFO,0),(stat.S_IFCHR,0),(stat.S_IFLNK,0),
                          (stat.S_IFREG,contract.MAXIMUM_VISIBLE_BYTES+1)):
            with self.subTest(mode=mode,size=size),self.visible_prompt(mode=mode,size=size) as facts:
                with self.assertRaisesRegex(ValueError,'regular file byte bound'):
                    contract.verify_visible(Path('/fixture'))
            self.assertEqual([],facts['reads']);self.assertEqual([12,11,10],facts['closed'])
            self.assertEqual(('prompt.txt',contract.os.O_RDONLY|contract.os.O_NOFOLLOW|contract.os.O_NONBLOCK|contract.os.O_CLOEXEC,
                              {'dir_fd':11}),facts['opened'][-1])

    def test_verify_visible_link_growth_truncation_and_leaf_parent_drift_refuse(self):
        cases=(('parent-symlink',OSError,'parent link refusal',[10]),
               ('leaf-symlink',OSError,'leaf link refusal',[11,10]),
               ('metadata',OSError,'metadata refusal',[12,11,10]),
               ('before-replacement',ValueError,'changed before read',[12,11,10]),
               ('growth',ValueError,'grew',[12,11,10]),
               ('truncate',ValueError,'truncated',[12,11,10]),
               ('version',ValueError,'changed during read',[12,11,10]),
               ('replacement',ValueError,'changed during read',[12,11,10]),
               ('parent-replacement',ValueError,'named parent changed',[12,11,10]),
               ('read-error',OSError,'read refusal',[12,11,10]))
        for fault,error,reason,closed in cases:
            with self.subTest(fault=fault),self.visible_prompt(fault=fault) as facts:
                with self.assertRaisesRegex(error,reason):contract.verify_visible(Path('/fixture'))
            self.assertEqual(closed,facts['closed'])
            self.assertEqual(len(closed),len(set(facts['closed'])))
            if fault in ('parent-symlink','leaf-symlink','metadata','before-replacement'):
                self.assertEqual([],facts['reads'])

    def test_verify_visible_preserves_raw_byte_comparison_and_cleanup_primary(self):
        for raw in (b'different authored prompt',b'\xff'):
            with self.subTest(raw=raw),self.visible_prompt(raw=raw) as facts:
                with self.assertRaisesRegex(ValueError,'visible prompt/profile disagreement'):
                    contract.verify_visible(Path('/fixture'))
            self.assertEqual([12,11,10],facts['closed'])
        with self.visible_prompt(fault='close') as facts:
            with self.assertRaisesRegex(OSError,'close refusal'):contract.verify_visible(Path('/fixture'))
        self.assertEqual([12,11,10],facts['closed'])
        with self.visible_prompt(fault='truncate-close') as facts:
            with self.assertRaisesRegex(ValueError,'truncated') as caught:contract.verify_visible(Path('/fixture'))
        self.assertEqual(['contract descriptor cleanup failures: 1'],caught.exception.__notes__)
        self.assertEqual([12,11,10],facts['closed'])



def authored_profile_bytes(label='A', *, compact=False):
    """Pure declared inputs, never host GCC observations or execution authority."""
    value=json.loads(json.dumps(contract._IMMUTABLE))
    value.update(gccIdentity={'executable':'/usr/bin/gcc','realpath':'/authored/gcc-'+label,
                 'sha256':'a'*64,'target':'x86_64-pc-linux-gnu','version':label},
                 toolchainEnvironmentPinSha256='b'*64 if label=='A' else 'c'*64)
    return (json.dumps(value,sort_keys=True,indent=None if compact else 2)+'\n').encode()


class ProfileCarry(unittest.TestCase):
    def test_original_wire_digest_immutable_bytes_and_fresh_loader_aliases(self):
        import bounded_runtime as runtime
        import interface_gate_v3 as gate
        import evaluate_candidate_v3 as evaluator
        raw=authored_profile_bytes();snapshot=contract._ProfileSnapshot(raw)
        compact=authored_profile_bytes(compact=True)
        self.assertEqual(json.loads(raw),json.loads(compact))
        self.assertNotEqual(hashlib.sha256(raw).hexdigest(),hashlib.sha256(compact).hexdigest())
        with contract.profile_scope(snapshot),patch.object(contract,'_bounded_json_snapshot',side_effect=AssertionError('context must not reread pathname')):
            for loader in (contract.load_profile_with_digest,runtime.load_profile_with_digest,gate.load_profile_with_digest,evaluator.load_profile_with_digest):
                value,digest=loader()
                self.assertEqual('A',value['gccIdentity']['version'])
                self.assertEqual(hashlib.sha256(raw).hexdigest(),digest)
                value['gccIdentity']['version']='mutated'
                value['commands']['compile'].clear()
                fresh=loader()[0]
                self.assertEqual('A',fresh['gccIdentity']['version'])
                self.assertTrue(fresh['commands']['compile'])
            self.assertEqual('A',evaluator.load_profile()['gccIdentity']['version'])
            with self.assertRaises(AttributeError):snapshot.raw=b'changed'
            with self.assertRaises(AttributeError):del snapshot.sha256
            with self.assertRaises(AttributeError):snapshot.__init__(authored_profile_bytes('B'))
            # Exercise the actual completion consumer, not just the loader aliases.
            from test_process_results import receipt
            with patch.object(evaluator, 'digest', return_value=snapshot.sha256):
                execution=receipt()
            with patch.object(evaluator, 'bounded_run', return_value=execution) as launched, \
                    patch.object(evaluator, 'digest', side_effect=AssertionError('completion must not rehash profile pathname')):
                status,result=evaluator._run(['/usr/bin/bwrap','authored'],Path('/authored/work'),timeout=5,phase='runtime')
            self.assertEqual('passed',status['status']);self.assertIs(execution,result)
            launched.assert_called_once()
            self.assertEqual(65536,launched.call_args.kwargs['output_limit'])
        self.assertEqual(raw,snapshot.raw)

    def test_nested_visible_admission_bypasses_outer_context_and_explicit_path_is_independent(self):
        raw_a=authored_profile_bytes('A');raw_b=authored_profile_bytes('B',compact=True)
        snapshot_a=contract._ProfileSnapshot(raw_a)
        value_b=json.loads(raw_b);visible=Path('/authored/visible');explicit=Path('/authored/independent.json')
        digest_b=hashlib.sha256(raw_b).hexdigest();reads=[]
        def capture(path,maximum):
            reads.append((path,maximum))
            if path in (contract.PROFILE_PATH,explicit):return raw_b
            self.assertEqual(visible/'prompt.txt',path)
            return contract._render(value_b).encode('utf-8')
        def manifest(path,maximum):
            self.assertEqual((visible/'visible-manifest.json',contract.MAXIMUM_VISIBLE_BYTES),(path,maximum))
            return {'schemaVersion':3,'profile':value_b,'profileSha256':digest_b},'d'*64
        with contract.profile_scope(snapshot_a),patch.object(contract,'_bounded_json_snapshot',side_effect=capture),patch.object(contract,'_read_json',side_effect=manifest),patch.object(contract,'_revalidate_gcc',side_effect=lambda value:value):
            snapshot_b=contract.verified_visible_snapshot(visible)
            self.assertEqual(raw_b,snapshot_b.raw);self.assertEqual(digest_b,snapshot_b.sha256)
            self.assertEqual('A',contract.load_profile()['gccIdentity']['version'])
            independent,independent_digest=contract.load_profile_with_digest(explicit)
            self.assertEqual('B',independent['gccIdentity']['version']);self.assertEqual(digest_b,independent_digest)
            with contract.profile_scope(snapshot_b):self.assertEqual('B',contract.load_profile()['gccIdentity']['version'])
            self.assertEqual('A',contract.load_profile()['gccIdentity']['version'])
        self.assertEqual([(contract.PROFILE_PATH,contract.MAXIMUM_PROFILE_BYTES),
                          (visible/'prompt.txt',contract.MAXIMUM_VISIBLE_BYTES),
                          (explicit,contract.MAXIMUM_PROFILE_BYTES)],reads)

    def test_scoped_profile_still_revalidates_actual_gcc_identity_and_rejects_drift(self):
        snapshot=contract._ProfileSnapshot(authored_profile_bytes())
        with contract.profile_scope(snapshot),patch.object(Path,'resolve',return_value=Path('/authored/gcc-A')) as resolved,patch.object(contract,'digest',return_value='a'*64) as hashed,patch.object(contract,'_bounded_json_snapshot',side_effect=AssertionError('no profile reopen')):
            self.assertEqual('A',contract.profile()['gccIdentity']['version'])
            hashed.assert_called_once_with(Path('/authored/gcc-A'));resolved.assert_called_once_with()
            hashed.return_value='f'*64
            with self.assertRaisesRegex(ValueError,'GCC executable differs'):contract.profile()
            self.assertEqual('A',contract.load_profile()['gccIdentity']['version'])

    def test_nested_context_failure_restores_each_token_without_changing_json_policy(self):
        a=contract._ProfileSnapshot(authored_profile_bytes('A'));b=contract._ProfileSnapshot(authored_profile_bytes('B'))
        before=contract._PROFILE_SNAPSHOT.get();failure=ValueError('authored nested failure')
        with contract.profile_scope(a):
            with self.assertRaises(ValueError) as caught:
                with contract.profile_scope(b):
                    self.assertEqual('B',contract.load_profile()['gccIdentity']['version']);raise failure
            self.assertIs(failure,caught.exception);self.assertIs(a,contract._PROFILE_SNAPSHOT.get())
        self.assertIs(before,contract._PROFILE_SNAPSHOT.get())
        for raw in (b'{"schemaVersion":3,"schemaVersion":3}',b'NaN',b'\xff',b'',b' '*(contract.MAXIMUM_PROFILE_BYTES+1)):
            with self.subTest(raw=raw[:32]),self.assertRaises(ValueError):contract._ProfileSnapshot(raw)


if __name__=='__main__':unittest.main()
