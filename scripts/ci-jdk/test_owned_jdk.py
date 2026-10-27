"""Owned fake-JDK controls. No downloads, namespace changes, model or authentication calls."""
from pathlib import Path
import hashlib
import importlib.util
import json
import types
from contextlib import contextmanager, ExitStack
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

    def host_ca_tree(self):
        root=self.repo/'host-authority'
        if not root.exists():
            target=root/fixture.HOST_CA_TARGET.removeprefix('/')
            target.parent.mkdir(parents=True);target.write_bytes(b'fixed inert host CA bytes');target.chmod(0o644)
        return root,root/fixture.HOST_CA_TARGET.removeprefix('/')

    @contextmanager
    def host_ca_io(self, wrong_uid=(), after_read=None):
        # All production '/' and relative target opens resolve into this repository-only fake tree.
        root,target=self.host_ca_tree();fds={}
        real_open,real_stat,real_fstat,real_close,real_read=os.open,os.stat,os.fstat,os.close,os.read
        def view(value,path):
            fields={n:getattr(value,n) for n in ['st_dev','st_ino','st_uid','st_gid','st_mode','st_size','st_mtime_ns','st_nlink']}
            key='/' if path==root else path.relative_to(root).as_posix()
            fields['st_uid']=1001 if key in wrong_uid else 0
            return types.SimpleNamespace(**fields)
        def opened(path,flags,*args,**kwargs):
            if path=='/':actual=root
            else:
                self.assertFalse(Path(path).is_absolute(),'host absolute path open forbidden')
                self.assertIn(kwargs.get('dir_fd'),fds)
                actual=fds[kwargs['dir_fd']]/path
            fd=real_open(actual,flags);fds[fd]=actual;return fd
        def status(path,*args,**kwargs):
            if path=='/':actual=root
            else:
                self.assertFalse(Path(path).is_absolute(),'host absolute stat forbidden')
                self.assertIn(kwargs.get('dir_fd'),fds);actual=fds[kwargs['dir_fd']]/path
            return view(real_stat(actual,follow_symlinks=kwargs.get('follow_symlinks',True)),actual)
        def fstatus(fd):self.assertIn(fd,fds);return view(real_fstat(fd),fds[fd])
        def closed(fd):fds.pop(fd);return real_close(fd)
        def read(fd,size):
            self.assertIn(fd,fds);data=real_read(fd,size)
            if after_read is not None:after_read(data)
            return data
        with ExitStack() as stack:
            for name,callback in [('open',opened),('stat',status),('fstat',fstatus),('close',closed),('read',read)]:
                stack.enter_context(mock.patch.object(fixture.os,name,side_effect=callback))
            try:yield
            finally:self.assertEqual({},fds,'host reader must close every descriptor')

    def capture_fake_host_ca(self):
        reader=self._host_reader
        with self.host_ca_io():return reader()

    def declared_ca_source(self,target=None):
        directory=self.source/'lib/security';directory.mkdir(exist_ok=True)
        link=directory/'cacerts';link.symlink_to(fixture.HOST_CA_TARGET if target is None else target)
        self._host_reader=fixture.read_host_ca_input
        return link

    def test_host_ca_reader_uses_only_fake_nofollow_root_authority_and_bounded_bytes(self):
        _,target=self.host_ca_tree();expected=target.read_bytes()
        with self.host_ca_io():record,data=fixture.read_host_ca_input()
        self.assertEqual(expected,data);self.assertEqual(fixture.HOST_CA_TARGET,record['target'])
        self.assertEqual(hashlib.sha256(data).hexdigest(),record['sha256'])
        self.assertEqual(6,len(record['chain']));self.assertTrue(all(row['identity'][2]==0 for row in record['chain']))

    def test_host_ca_reader_rejects_wrong_owner_and_writable_chain_or_file(self):
        root,target=self.host_ca_tree()
        for key in ['/', 'etc', 'etc/ssl/certs', fixture.HOST_CA_TARGET.removeprefix('/')]:
            with self.subTest(owner=key),self.host_ca_io(wrong_uid={key}),self.assertRaises(ValueError):fixture.read_host_ca_input()
        for path in [root,root/'etc/ssl',target]:
            mode=stat.S_IMODE(path.stat().st_mode);path.chmod(mode|0o020)
            try:
                with self.subTest(writable=str(path)),self.host_ca_io(),self.assertRaises(ValueError):fixture.read_host_ca_input()
            finally:path.chmod(mode)

    def test_host_ca_reader_rejects_directory_and_file_links_special_and_size(self):
        root,target=self.host_ca_tree();directory=root/'etc/ssl';moved=root/'moved-ssl'
        directory.rename(moved);directory.symlink_to('../moved-ssl')
        try:
            with self.host_ca_io(),self.assertRaises(ValueError):fixture.read_host_ca_input()
        finally:directory.unlink();moved.rename(directory)
        original=target.read_bytes();target.unlink();target.symlink_to(self.source/'lib/modules')
        with self.host_ca_io(),self.assertRaises(ValueError):fixture.read_host_ca_input()
        target.unlink();os.mkfifo(target)
        with self.host_ca_io(),self.assertRaises(ValueError):fixture.read_host_ca_input()
        target.unlink();target.write_bytes(b'')
        with self.host_ca_io(),self.assertRaises(ValueError):fixture.read_host_ca_input()
        with target.open('wb') as file:file.truncate(fixture.MAX_HOST_CA_BYTES+1)
        with self.host_ca_io(),self.assertRaisesRegex(ValueError,'byte bound'):fixture.read_host_ca_input()
        target.write_bytes(original)

    def test_host_ca_reader_detects_changes_during_read_and_component_replacement(self):
        root,target=self.host_ca_tree();original=target.read_bytes();done=[]
        def changed(data):
            if data and not done:done.append(True);target.write_bytes(b'x'*len(original))
        with self.host_ca_io(after_read=changed),self.assertRaises(ValueError):fixture.read_host_ca_input()
        target.write_bytes(original);done.clear()
        def replace(data):
            if data and not done:
                done.append(True);(root/'etc').rename(root/'old-etc');(root/'etc').mkdir()
        with self.host_ca_io(after_read=replace),self.assertRaises(ValueError):fixture.read_host_ca_input()

    def test_declared_profile_materializes_regular_private_ca_and_preserves_source(self):
        link=self.declared_ca_source();_,target=self.host_ca_tree()
        with mock.patch.object(fixture,'read_host_ca_input',side_effect=self.capture_fake_host_ca):
            result=fixture.provision(self.repo,self.source,fixture.HOST_CA_SOURCE_PROFILE)
            clone=Path(result['home'])/fixture.HOST_CA_SLOT
            self.assertFalse(clone.is_symlink());self.assertEqual(target.read_bytes(),clone.read_bytes())
            self.assertEqual(0o444,stat.S_IMODE(clone.stat().st_mode));self.assertEqual(1,clone.stat().st_nlink)
            self.assertEqual(os.geteuid(),clone.stat().st_uid)
            self.assertEqual(fixture.HOST_CA_TARGET,os.readlink(link))
            self.assertEqual('link',result['sourceEntries'][fixture.HOST_CA_SLOT]['kind'])
            self.assertEqual('file',result['cloneEntries'][fixture.HOST_CA_SLOT]['kind'])
            self.assertEqual(sum(entry['identity'][5] for entry in result['sourceEntries'].values() if entry['kind']=='file')+len(target.read_bytes()),result['bytes'])
            fixture.verify_source(json.loads(json.dumps(result)))

    def test_default_strict_and_profile_wrong_slots_or_targets_never_read_host(self):
        link=self.declared_ca_source()
        with mock.patch.object(fixture,'read_host_ca_input',side_effect=AssertionError('host read before exact profile admission')):
            with self.assertRaises(ValueError):fixture.provision(self.repo,self.source)
            for alternate in ['/etc/ssl/certs/other','/etc/ssl/certs/adoptium/cacerts/../cacerts','../../../../outside']:
                link.unlink();link.symlink_to(alternate)
                with self.subTest(target=alternate),self.assertRaises(ValueError):fixture.provision(self.repo,self.source,fixture.HOST_CA_SOURCE_PROFILE)
            link.unlink();link.write_bytes(b'ordinary internal CA')
            outside=self.source/'lib/other';outside.symlink_to(fixture.HOST_CA_TARGET)
            with self.assertRaises(ValueError):fixture.provision(self.repo,self.source,fixture.HOST_CA_SOURCE_PROFILE)

    def test_regular_and_internal_ca_need_no_external_input_even_in_profile(self):
        directory=self.source/'lib/security';directory.mkdir();ca=directory/'cacerts'
        for relative in [False,True]:
            if ca.exists() or ca.is_symlink():ca.unlink()
            if relative:ca.symlink_to('../modules')
            else:ca.write_bytes(b'ordinary CA bytes')
            with mock.patch.object(fixture,'read_host_ca_input',side_effect=AssertionError('unneeded host read')):
                result=fixture.provision(self.repo,self.source,fixture.HOST_CA_SOURCE_PROFILE)
                self.assertIsNone(result['hostCaInput']);fixture.verify_source(result)

    def test_failed_host_capture_precedes_any_clone_file_copy_and_ca_counts_existing_budget(self):
        self.declared_ca_source();self.host_ca_tree()
        with mock.patch.object(fixture,'read_host_ca_input',side_effect=ValueError('inert authority denied')), \
             mock.patch.object(fixture.os,'write',side_effect=AssertionError('copy before authority')):
            with self.assertRaisesRegex(ValueError,'authority denied'):fixture.provision(self.repo,self.source,fixture.HOST_CA_SOURCE_PROFILE)
        source_bytes=sum(p.stat().st_size for p in [self.java,self.source/'release',self.source/'lib/modules'])
        with mock.patch.object(fixture,'read_host_ca_input',side_effect=self.capture_fake_host_ca),mock.patch.object(fixture,'MAX_BYTES',source_bytes):
            with self.assertRaisesRegex(ValueError,'JDK byte bound'):fixture.provision(self.repo,self.source,fixture.HOST_CA_SOURCE_PROFILE)

    def test_post_capture_external_source_and_clone_changes_are_independently_rejected(self):
        link=self.declared_ca_source();_,target=self.host_ca_tree()
        with mock.patch.object(fixture,'read_host_ca_input',side_effect=self.capture_fake_host_ca):
            result=fixture.provision(self.repo,self.source,fixture.HOST_CA_SOURCE_PROFILE)
            before=target.stat();original=target.read_bytes();target.write_bytes(b'x'*len(original));os.utime(target,ns=(before.st_atime_ns,before.st_mtime_ns))
            with self.assertRaisesRegex(ValueError,'host CA input changed'):fixture.verify_source(result)
            target.write_bytes(original);os.utime(target,ns=(before.st_atime_ns,before.st_mtime_ns))
            clone=Path(result['home'])/fixture.HOST_CA_SLOT;clone_before=clone.stat();clone.chmod(0o644);clone.write_bytes(b'z'*len(original));clone.chmod(0o444)
            os.utime(clone,ns=(clone_before.st_atime_ns,clone_before.st_mtime_ns))
            with self.assertRaisesRegex(ValueError,'owned JDK content changed'):fixture.verify_source(result)
            link.unlink();link.symlink_to('/different')
            with self.assertRaises(ValueError):fixture.verify_source(result)

    def test_post_capture_ca_replacement_and_authority_mode_drift_refused_even_with_same_bytes(self):
        self.declared_ca_source();_,target=self.host_ca_tree()
        with mock.patch.object(fixture,'read_host_ca_input',side_effect=self.capture_fake_host_ca):
            result=fixture.provision(self.repo,self.source,fixture.HOST_CA_SOURCE_PROFILE)
            mode=stat.S_IMODE(target.stat().st_mode);target.chmod(0o444)
            with self.assertRaisesRegex(ValueError,'host CA input changed'):fixture.verify_source(result)
            target.chmod(mode)
            result=fixture.provision(self.repo,self.source,fixture.HOST_CA_SOURCE_PROFILE)
            data=target.read_bytes();target.unlink();target.write_bytes(data)
            with self.assertRaisesRegex(ValueError,'host CA input changed'):fixture.verify_source(result)

    def test_declared_file_leaf_projection_cannot_admit_other_slots_or_strict_profile(self):
        candidate={'kind':'link','target':fixture.HOST_CA_TARGET,'externalInput':fixture.HOST_CA_SOURCE_PROFILE}
        with self.assertRaises(ValueError):fixture.source_link_graph({fixture.HOST_CA_SLOT:candidate},fixture.STRICT_SOURCE_PROFILE)
        with self.assertRaises(ValueError):fixture.source_link_graph({'lib/other':candidate},fixture.HOST_CA_SOURCE_PROFILE)
        wrong=dict(candidate,target='/other')
        with self.assertRaises(ValueError):fixture.source_link_graph({fixture.HOST_CA_SLOT:wrong},fixture.HOST_CA_SOURCE_PROFILE)
        self.assertEqual({'kind':'file'},fixture.source_link_graph({fixture.HOST_CA_SLOT:candidate},fixture.HOST_CA_SOURCE_PROFILE)[fixture.HOST_CA_SLOT])
        with self.assertRaises(ValueError):fixture.validate_link_graph({fixture.HOST_CA_SLOT:candidate})

    def test_mocked_post_command_external_change_keeps_all_unchanged_facts_false(self):
        self.declared_ca_source();_,target=self.host_ca_tree();containers=[]
        def command(argv,cwd,env):
            containers.append(Path(env['JAVA_HOME']).parent);target.write_bytes(b'changed inert host CA');return mock.Mock(returncode=0)
        with mock.patch.object(fixture,'read_host_ca_input',side_effect=self.capture_fake_host_ca), \
             mock.patch.object(fixture,'UNIX_SOCKET_PATH_BYTES',4096),mock.patch.object(fixture.subprocess,'run',side_effect=command), \
             mock.patch.object(fixture,'verify_jvms',side_effect=AssertionError('qualification before source proof')):
            with self.assertRaisesRegex(ValueError,'host CA input changed'):
                fixture.run(self.repo,self.source,['inert-never-executed'],fixture.HOST_CA_SOURCE_PROFILE)
        final=json.loads((containers[0]/'final.json').read_text())
        self.assertFalse(final['sourceUnchanged']);self.assertFalse(final['cloneUnchanged']);self.assertFalse(final['hostCaUnchanged'])

    def test_explicit_profile_cli_and_actions_callers_are_closed(self):
        self.assertEqual(('strict',['inert']),fixture.parse_command_arguments(['run','--','inert']))
        self.assertEqual((fixture.HOST_CA_SOURCE_PROFILE,['inert']),fixture.parse_command_arguments(['run','--source-profile',fixture.HOST_CA_SOURCE_PROFILE,'--','inert']))
        for args in [[],['run','--'],['run','--source-profile','unknown','--','inert'],['run','--source-profile',fixture.HOST_CA_SOURCE_PROFILE,'--']]:
            with self.assertRaises(ValueError):fixture.parse_command_arguments(args)
        callers=[]
        for path in [ROOT/'.github/workflows/ci.yml',ROOT/'.github/workflows/acp-contract.yml']:
            callers.extend(line for line in path.read_text().splitlines() if 'scripts/ci-owned-jdk.py run ' in line)
        self.assertEqual(5,len(callers));self.assertTrue(all('run --source-profile actions-host-ca-v1 --' in line for line in callers))

    def test_owned_test_jvm_and_isolated_worker_runtime_are_distinct(self):
        captured = {}
        def command(argv, cwd, env):
            captured.update(env)
            return mock.Mock(returncode=0)
        # Only intercept execution/evidence collection. Provisioning and the
        # post-command source/clone integrity checks still execute normally.
        with mock.patch.dict(os.environ, {'DECOMP_CI_WORKER_JAVA_HOME': '/stale/worker'}), \
             mock.patch.object(fixture, 'UNIX_SOCKET_PATH_BYTES', 4096), \
             mock.patch.object(fixture.subprocess, 'run', side_effect=command), \
             mock.patch.object(fixture, 'verify_jvms', return_value=1):
            fixture.run(self.repo, self.source, ['inert-never-executed'])
        self.assertEqual(str(self.source.resolve()), captured['DECOMP_CI_WORKER_JAVA_HOME'])
        clone = Path(captured['JAVA_HOME'])
        self.assertNotEqual(self.source, clone)
        self.assertEqual(str(clone), captured['ORG_GRADLE_PROJECT_ciAcpFixtureJdkHome'])
        self.assertNotEqual(self.java.stat().st_ino, (clone / 'bin/java').stat().st_ino)
        for path in [ROOT / 'src/test/kotlin/decompengine/oracle/fulltree/FullTreeFunctionObservationIsolatedRunnerTest.kt',
                     ROOT / 'src/test/kotlin/decompengine/oracle/gcc/GccCompilerEngineLiveContainmentControllerTest.kt']:
            self.assertIn('System.getenv("DECOMP_CI_WORKER_JAVA_HOME")', path.read_text())

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
