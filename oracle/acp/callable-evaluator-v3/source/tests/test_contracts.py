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
    def snapshot(self, data=b'{"value":1}', fault=None, size=None, mode=stat.S_IFREG):
        facts={'opened':[], 'closed':[], 'reads':[], 'offset':0, 'eof':False}
        def metadata(directory=False, changed=False):
            return SimpleNamespace(st_dev=1,st_ino=(9 if changed else 2) if directory else (8 if changed else 3),
                st_mode=(stat.S_IFDIR|0o755) if directory else (mode|0o600),st_uid=1000,st_gid=1000,
                st_nlink=1,st_size=0 if directory else (len(data) if size is None else size),
                st_mtime_ns=4,st_ctime_ns=5)
        def opened(name,flags,**kwargs):
            facts['opened'].append((name,flags,kwargs))
            if fault=='parent-symlink' and name=='fixture':raise OSError('authored parent link refusal')
            if fault=='leaf-symlink' and name=='document.json':raise OSError('authored leaf link refusal')
            return {'/':10,'fixture':11,'document.json':12}[name]
        def observed(fd):
            if fault=='metadata' and fd==12:raise OSError('authored metadata refusal')
            return metadata(fd!=12, fault=='version' and fd==12 and facts['eof'])
        def named(name,**kwargs):
            self.assertIs(False,kwargs['follow_symlinks'])
            changed=((fault=='before-replacement' and name=='document.json') or
                     facts['eof'] and ((fault=='replacement' and name=='document.json') or
                                      (fault=='parent-replacement' and name=='fixture')))
            return metadata(name!='document.json',changed)
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


if __name__=='__main__':unittest.main()
