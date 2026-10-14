"""Owned fake-JDK controls. No downloads, namespace changes, model or authentication calls."""
from pathlib import Path
import hashlib
import importlib.util
import json
import os
import stat
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('owned_jdk', ROOT / 'scripts/ci-owned-jdk.py')
fixture = importlib.util.module_from_spec(spec); spec.loader.exec_module(fixture)

class OwnedJdkTest(unittest.TestCase):
    def setUp(self):
        base = ROOT / 'build/owned-jdk-controls'; base.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=base)
        self.repo = Path(self.temp.name)
        self.source = self.repo / 'selected'; (self.source / 'bin').mkdir(parents=True)
        (self.source / 'lib').mkdir()
        self.java = self.source / 'bin/java'; self.java.write_bytes(b'fixed owned fake launcher'); self.java.chmod(0o777)
        (self.source / 'release').write_text('JAVA_VERSION="21.0.12"\nIMPLEMENTOR="owned inert fixture"\n')
        (self.source / 'lib/modules').write_bytes(b'inert modules')
        (self.source / 'lib/internal-link').symlink_to('modules')
    def tearDown(self): self.temp.cleanup()
    def test_0777_source_unchanged_and_independent_clone_0755(self):
        before = fixture.identity(self.java.stat()); digest = hashlib.sha256(self.java.read_bytes()).hexdigest()
        result = fixture.provision(self.repo, self.source)
        copied = Path(result['home']) / 'bin/java'
        self.assertEqual(before, fixture.identity(self.java.stat()))
        self.assertEqual(0o777, stat.S_IMODE(self.java.stat().st_mode))
        self.assertEqual(0o755, stat.S_IMODE(copied.stat().st_mode))
        self.assertNotEqual((copied.stat().st_dev, copied.stat().st_ino), before[:2])
        self.assertEqual(digest, hashlib.sha256(copied.read_bytes()).hexdigest())
        self.assertEqual('modules', os.readlink(Path(result['home']) / 'lib/internal-link'))
        self.assertEqual(os.geteuid(), copied.stat().st_uid); self.assertEqual(1, copied.stat().st_nlink)
        fixture.verify_source(result)
        second = fixture.provision(self.repo, self.source)
        self.assertNotEqual(result['home'], second['home'])
    def test_absolute_external_and_same_prefix_links_refused_before_copy(self):
        sibling = self.repo/'selected-sibling';sibling.mkdir();(sibling/'ambient').write_bytes(b'outside')
        for target in ('/does-not-exist/ambient', str(self.source/'lib/modules'), '../selected-sibling/ambient', '../../selected-sibling/ambient'):
            link=self.source/'escape';link.symlink_to(target)
            with self.subTest(target=target), mock.patch.object(fixture.os,'symlink',side_effect=AssertionError('copy before graph admission')), self.assertRaises(ValueError):
                fixture.provision(self.repo,self.source)
            link.unlink()

    def test_internal_relative_chains_and_directory_components_stay_inside_clone(self):
        (self.source/'alias-lib').symlink_to('lib')
        (self.source/'lib/chain').symlink_to('../alias-lib/internal-link')
        (self.source/'lib/root').symlink_to('..')
        result=fixture.provision(self.repo,self.source);clone=Path(result['home'])
        self.assertEqual(clone/'lib/modules',(clone/'lib/chain').resolve(strict=True))
        self.assertEqual(b'inert modules',(clone/'lib/chain').read_bytes())
        self.assertEqual(clone,(clone/'lib/root').resolve(strict=True))
        fixture.verify_source(result)

    def test_chained_escape_cycles_dangling_and_non_directory_refused(self):
        cases=[{'a':'../selected-sibling/ambient','b':'a'}, {'a':'b','b':'a'},
               {'a':'missing'}, {'a':'lib/modules/child'}, {'a':'lib/modules/..'},
               {'a':'lib/modules/'}, {'a':'../selected/lib/modules'}]
        for links in cases:
            with self.subTest(links=links):
                for name,target in links.items():(self.source/name).symlink_to(target)
                with mock.patch.object(fixture.os,'symlink',side_effect=AssertionError('copy before graph admission')), self.assertRaises(ValueError):
                    fixture.provision(self.repo,self.source)
                for name in links:(self.source/name).unlink()

    def test_link_resolution_work_and_chain_limits_refuse_without_external_reads(self):
        for number in range(fixture.MAX_DEPTH+1):
            (self.source/f'chain{number}').symlink_to(f'chain{number+1}' if number<fixture.MAX_DEPTH else 'lib/modules')
        with self.assertRaisesRegex(ValueError,'chain/cycle bound'):fixture.provision(self.repo,self.source)
        (self.source/'chain0').unlink()
        self.assertTrue(Path(fixture.provision(self.repo,self.source)['home']).is_dir())
        with mock.patch.object(fixture,'MAX_ENTRIES',2), mock.patch.object(fixture,'MAX_DEPTH',2), self.assertRaisesRegex(ValueError,'work bound'):
            fixture.validate_link_graph({'a':{'kind':'link','target':'./././././file'},'file':{'kind':'file'}})

    def test_link_change_after_preflight_refused_and_descriptors_recovered(self):
        original=fixture.inventory_links
        before=len(os.listdir('/proc/self/fd'))
        def replaced(fd):
            result=original(fd)
            link=self.source/'lib/internal-link'
            link.unlink();link.symlink_to('/does-not-exist/ambient')
            return result
        with mock.patch.object(fixture,'inventory_links',replaced), self.assertRaises(ValueError):
            fixture.provision(self.repo,self.source)
        self.assertEqual(before,len(os.listdir('/proc/self/fd')))

    def test_chmod_never_targets_any_source_inode(self):
        sources = {(p.lstat().st_dev, p.lstat().st_ino) for p in [self.source, *self.source.rglob('*')]}
        original = os.fchmod
        def checked(fd, mode):
            value = os.fstat(fd)
            self.assertNotIn((value.st_dev, value.st_ino), sources)
            return original(fd, mode)
        with mock.patch.object(fixture.os, 'fchmod', checked): fixture.provision(self.repo, self.source)
    def test_partial_open_failure_recovers_descriptors(self):
        before = len(os.listdir('/proc/self/fd')); original = os.open
        def failed(path, flags, *args, **kwargs):
            if flags & os.O_CREAT: raise OSError('inert copied-file allocation failure')
            return original(path, flags, *args, **kwargs)
        with mock.patch.object(fixture.os, 'open', failed), self.assertRaises(OSError): fixture.provision(self.repo, self.source)
        self.assertEqual(before, len(os.listdir('/proc/self/fd')))
    def test_symlink_launcher_refused_without_changing_target(self):
        self.java.unlink(); target = self.source / 'lib/target'; target.write_bytes(b'unchanged'); target.chmod(0o777)
        self.java.symlink_to('../lib/target')
        with self.assertRaises(ValueError): fixture.provision(self.repo, self.source)
        self.assertEqual(0o777, stat.S_IMODE(target.stat().st_mode)); self.assertEqual(b'unchanged', target.read_bytes())
    def test_special_source_file_refused(self):
        os.mkfifo(self.source / 'pipe')
        with self.assertRaises(ValueError): fixture.provision(self.repo, self.source)
    def test_symlink_build_refused(self):
        other = self.repo / 'other'; other.mkdir(); (self.repo / 'build').symlink_to(other)
        with self.assertRaises(ValueError): fixture.provision(self.repo, self.source)
        self.assertEqual([], list(other.iterdir()))
    def test_changed_source_refused(self):
        result = fixture.provision(self.repo, self.source); self.java.chmod(0o755)
        with self.assertRaises(ValueError): fixture.verify_source(result)
    def test_changed_owned_launcher_refused(self):
        result = fixture.provision(self.repo, self.source); (Path(result['home']) / 'bin/java').write_bytes(b'substitute')
        with self.assertRaises(ValueError): fixture.verify_source(result)
    def test_complete_clone_inventory_is_pinned_after_normalization(self):
        result=fixture.provision(self.repo,self.source)
        self.assertEqual(set(result['sourceEntries']),set(result['cloneEntries']))
        self.assertEqual(0o755,result['cloneEntries']['bin/java']['identity'][4])
        self.assertEqual(result['launcherIdentity'],result['cloneEntries']['bin/java']['identity'])
        for key,entry in result['cloneEntries'].items():
            if entry['kind']=='file':self.assertEqual(result['sourceEntries'][key]['sha256'],entry['sha256'])
        fixture.verify_source(result)

    def test_same_size_modules_tamper_with_restored_mtime_rejected_by_hash(self):
        result=fixture.provision(self.repo,self.source);path=Path(result['home'])/'lib/modules'
        before=path.stat();path.write_bytes(b'x'*before.st_size)
        os.utime(path,ns=(before.st_atime_ns,before.st_mtime_ns))
        self.assertEqual(tuple(result['cloneEntries']['lib/modules']['identity']),fixture.identity(path.stat()))
        self.assertEqual(b'inert modules',(self.source/'lib/modules').read_bytes())
        with self.assertRaisesRegex(ValueError,'owned JDK content changed'):fixture.verify_source(result)

    def test_post_command_module_tamper_keeps_both_unchanged_facts_false(self):
        containers=[]
        def fake_command(command,cwd,env):
            home=Path(env['JAVA_HOME']);containers.append(home.parent)
            path=home/'lib/modules';before=path.stat();path.write_bytes(b'x'*before.st_size)
            os.utime(path,ns=(before.st_atime_ns,before.st_mtime_ns))
            return mock.Mock(returncode=0)
        with mock.patch.object(fixture,'UNIX_SOCKET_PATH_BYTES',4096), \
             mock.patch.object(fixture.subprocess,'run',side_effect=fake_command) as command, \
             mock.patch.object(fixture,'verify_jvms',side_effect=AssertionError('must refuse before worker qualification')):
            with self.assertRaisesRegex(ValueError,'owned JDK content changed'):
                fixture.run(self.repo,self.source,['inert-never-executed'])
        command.assert_called_once()
        final=json.loads((containers[0]/'final.json').read_text())
        self.assertEqual(0,final['exitCode']);self.assertFalse(final['sourceUnchanged'])
        self.assertFalse(final['cloneUnchanged']);self.assertEqual(0,final['actualTestJvms'])

    def test_cloned_configuration_change_rejected(self):
        (self.source/'conf').mkdir();(self.source/'conf/runtime.conf').write_bytes(b'fixed configuration')
        result=fixture.provision(self.repo,self.source)
        (Path(result['home'])/'conf/runtime.conf').write_bytes(b'altered configuration')
        with self.assertRaises(ValueError):fixture.verify_source(result)

    def test_clone_extra_missing_replaced_mode_and_hardlink_changes_refused_without_fd_leak(self):
        def extra(home):(home/'lib/extra').write_bytes(b'extra')
        def missing(home):(home/'lib/modules').unlink()
        def replace(home):
            path=home/'lib/modules';data=path.read_bytes();path.unlink();path.write_bytes(data)
        def mode(home):(home/'lib').chmod(0o777)
        def hardlink(home):os.link(home/'lib/modules',self.repo/'outside-alias')
        for mutation in [extra,missing,replace,mode,hardlink]:
            with self.subTest(mutation=mutation.__name__):
                result=fixture.provision(self.repo,self.source);home=Path(result['home']);mutation(home)
                before=len(os.listdir('/proc/self/fd'))
                try:
                    with self.assertRaises(ValueError):fixture.verify_source(result)
                    self.assertEqual(before,len(os.listdir('/proc/self/fd')))
                finally:
                    alias=self.repo/'outside-alias'
                    if alias.exists():alias.unlink()

    def test_changed_clone_symlink_refused_without_following_external_target(self):
        result=fixture.provision(self.repo,self.source);home=Path(result['home'])
        target=self.repo/'external-canary';target.write_bytes(b'unchanged')
        link=home/'lib/internal-link';link.unlink();link.symlink_to(target)
        with self.assertRaises(ValueError):fixture.verify_source(result)
        self.assertEqual(b'unchanged',target.read_bytes())

    def test_absolute_link_refusal_identifies_relative_path_and_target_before_copy(self):
        (self.source/'lib/hosted-link').symlink_to('/trusted-selected-jdk/absolute')
        with mock.patch.object(fixture.os,'symlink',side_effect=AssertionError('copy before admission')):
            with self.assertRaises(ValueError) as caught:fixture.provision(self.repo,self.source)
        self.assertIn('JDK absolute symlink refused',str(caught.exception))
        self.assertIn('path=lib/hosted-link',str(caught.exception))
        self.assertIn('target=/trusted-selected-jdk/absolute',str(caught.exception))

    def test_chained_absolute_link_reports_actual_offending_link(self):
        with self.assertRaises(ValueError) as caught:
            fixture.validate_link_graph({'alias':{'kind':'link','target':'offending'},
                                         'offending':{'kind':'link','target':'/absolute'}})
        self.assertIn('path=offending target=/absolute',str(caught.exception))

    def test_link_diagnostic_is_escaped_bounded_and_commits_truncated_metadata(self):
        path='lib/'+('x'*2000);target='/'+('é\n'*2000)
        text=str(fixture.symlink_refusal('JDK absolute symlink refused',path,target))
        self.assertLess(len(text),900);self.assertNotIn('\n',text)
        self.assertIn('pathSha256='+hashlib.sha256(os.fsencode(path)).hexdigest(),text)
        self.assertIn('targetSha256='+hashlib.sha256(os.fsencode(target)).hexdigest(),text)

    def test_full_caller_credentials_are_authority(self):
        result = fixture.credentials('Pid:\t123\nUid:\t10 11 12 13\nGid:\t20 21 22 23\n', 123)
        self.assertEqual({'Uid':'10,11,12,13','Gid':'20,21,22,23'}, result)
        actual = fixture.caller_credentials(); self.assertEqual(list(os.getresuid()), list(map(int, actual['Uid'].split(',')))[:3])
    def test_unknown_duplicate_wrong_pid_credentials_refused(self):
        for text in ['Pid: 124\nUid: 1 1 1 1\nGid: 1 1 1 1\n',
                     'Pid: 123\nUid: 1 1 1\nGid: 1 1 1 1\n',
                     'Pid: 123\nUid: 1 1 1 1\nUid: 2 2 2 2\nGid: 1 1 1 1\n', 'x' * 65537]:
            with self.subTest(text=text[:20]), self.assertRaises(ValueError): fixture.credentials(text,123)
    def test_socket_budget_is_encoded_bytes_and_accepts_hosted_root_only(self):
        hosted = Path('/home/runner/work/decomp_thing/decomp_thing')
        self.assertEqual(63, len(fixture.SOCKET_FIXTURE_SUFFIX.encode('ascii')))
        self.assertEqual(106, len(os.fsencode(hosted)) + 63)
        # Exercise actual canonical ownership independently of this checkout's length.
        with mock.patch.object(fixture, 'UNIX_SOCKET_PATH_BYTES', 4096):
            result = fixture.socket_scratch(ROOT)
            self.assertEqual(str(ROOT), result['path'])
            self.assertEqual(os.geteuid(), result['uid'])
        for path in [Path('/' + 'x' * 44), Path('/' + 'é' * 22)]:
            with self.assertRaisesRegex(ValueError, 'byte budget'):
                fixture.socket_scratch(path)
        with mock.patch.object(fixture, 'secure_directory', return_value=os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY)):
            self.assertEqual(str(hosted), fixture.socket_scratch(hosted)['path'])
        with self.assertRaisesRegex(ValueError, 'byte budget'):
            fixture.socket_scratch(hosted / 't')
    def test_socket_scratch_refuses_symlink_or_writable_directory(self):
        # Keep this independent of the checkout's actual path length.
        with mock.patch.object(fixture, 'UNIX_SOCKET_PATH_BYTES', 4096):
            target = self.repo / 'scratch'; target.mkdir(); alias = self.repo / 'alias'; alias.symlink_to(target)
            with self.assertRaises(ValueError): fixture.socket_scratch(alias)
            target.chmod(0o777)
            with self.assertRaises(ValueError): fixture.socket_scratch(target)

    def test_missing_actual_test_jvm_proof_refused(self):
        with self.assertRaises(ValueError): fixture.verify_jvms(fixture.provision(self.repo, self.source))
    def test_actual_worker_scratch_must_equal_exact_repository(self):
        result = fixture.provision(self.repo, self.source); container = Path(result['container'])
        expected = fixture.parse_properties(container / 'provision.properties')
        props = {k: v for k,v in expected.items() if k not in ('java','receipts')}
        props.update(command=result['home'] + '/bin/java', pid='123', task=':test', scratch=str(self.repo))
        file = container / 'receipts/test.properties'
        def write(): file.write_text(''.join(k+'='+v+'\n' for k,v in props.items()))
        write(); file.with_suffix('.closed').write_text('closed\n')
        (container / 'selections/test.properties').write_text('task=:test\nhome='+result['home']+'\njava='+result['home']+'/bin/java\n')
        self.assertEqual(1, fixture.verify_jvms(result))
        for substitute in [str(self.repo.parent), '/home/june']:
            props['scratch'] = substitute; write()
            with self.assertRaisesRegex(ValueError, 'identity mismatch'): fixture.verify_jvms(result)

    def test_byte_equal_command_at_source_cannot_substitute_clone(self):
        result = fixture.provision(self.repo, self.source); container = Path(result['container'])
        expected = fixture.parse_properties(container / 'provision.properties')
        props = {k: v for k,v in expected.items() if k not in ('java','receipts')}
        props.update(command=str(self.java), pid='123', task=':test')
        file = container / 'receipts/test.properties'; file.write_text(''.join(k+'='+v+'\n' for k,v in props.items()))
        file.with_suffix('.closed').write_text('closed\n')
        (container / 'selections/test.properties').write_text('task=:test\nhome='+result['home']+'\njava='+result['home']+'/bin/java\n')
        with self.assertRaises(ValueError): fixture.verify_jvms(result)

if __name__ == '__main__': unittest.main()
