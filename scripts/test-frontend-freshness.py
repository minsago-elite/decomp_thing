#!/usr/bin/env python3
"""Authored injected vectors only: no Gradle/npm/child/network/real fixture work."""
import importlib.util
import io
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch, MagicMock
import unittest

spec=importlib.util.spec_from_file_location('frontend_freshness',Path(__file__).with_name('verify-frontend-freshness.py'))
f=importlib.util.module_from_spec(spec)
spec.loader.exec_module(f)


class MemoryFiles:
    def __init__(self,ledger): self.ledger=ledger; self.data={}; self.removed=[]
    def path(self,path): return Path(path)
    def read(self,path,maximum=16*1024**2):
        self.ledger.check(); data=self.data[str(path)]
        if len(data)>maximum: raise f.Refusal('read bound')
        return data
    def write(self,path,data,evidence=False):
        self.ledger.check(cleanup=evidence)
        if evidence:self.ledger.evidence(len(data))
        self.data[str(path)]=data
    def inventory(self,path,limits=f.OUTPUT,*,partitioned_ui=False,dist_assets=False):
        prefix=str(path)+'/'
        rows={name[len(prefix):]:{'bytes':len(data),'sha256':f.sha(data)} for name,data in sorted(self.data.items()) if name.startswith(prefix)}
        if dist_assets and len(rows)>2048:raise f.Refusal('dist asset file bound')
        return f.check_ui_partition(rows) if partitioned_ui else rows
    def remove(self,path):
        self.ledger.check(); prefix=str(path); self.removed.append(prefix)
        for name in list(self.data):
            if name==prefix or name.startswith(prefix+'/'):del self.data[name]


def build_output(mode):
    names=f.TASKS[:3] if mode=='drift' else f.TASKS
    labels={name:'' for name in names}
    if mode in ('unchanged','fresh','drift'):labels['frontendInstall']=' UP-TO-DATE'
    if mode=='unchanged':
        for name in ('frontendBuild','generateFrontendAssetManifest','stageFrontend'):labels[name]=' UP-TO-DATE'
    if mode=='drift':labels['frontendBuild']=' FAILED'
    output='\n'.join('> Task :'+name+labels[name] for name in names)+'\n'
    if mode=='drift':output+='Generated contract drift: authored module\n'
    return {'code':1 if mode=='drift' else 0,'output':output.encode(),'intervened':False,'reaped':True}


class ProducedFixture:
    """An authored producer derives closure bytes from current in-memory inputs."""
    def __init__(self,files,fixture,defect=None):
        self.fs=files; self.fixture=fixture; self.defect=defect; self.calls=[]
    def __call__(self,argv,cwd,env):
        self.calls.append((argv,env)); self.fs.ledger.check()
        if argv[-1]=='--check':
            checks=sum(a[-1]=='--check' for a,_ in self.calls)
            if self.defect=='drift-prep':return {'code':1,'output':b'wrong diagnostic','intervened':False,'reaped':True}
            if self.defect=='fresh-prep' and checks==3:self.fs.write(self.fixture/'frontend/src/app/mark.svg',b'no SVG anchor')
            return {'code':1,'output':b'Generated contract drift: authored module','intervened':False,'reaped':True}
        mode=('cold','unchanged','warm','drift','fresh')[sum(a[-1]!='--check' for a,_ in self.calls)-1]
        guard=self.fs.read(Path('/repo/work/graph.gradle'))
        if guard!=f.init_guard(f.TASKS[:3] if mode=='drift' else f.TASKS):raise AssertionError('wrong graph guard')
        if mode not in ('unchanged','drift'):self.produce(mode)
        if self.defect=='late' and mode=='cold':self.fs.ledger.clock.now=406
        result=build_output(mode)
        if self.defect=='cache':result['output']=result['output'].replace(b':frontendBuild\n',b':frontendBuild FROM-CACHE\n')
        return result
    def produce(self,mode):
        root=self.fixture; changed=str(root/'frontend/src/app/freshness-mark.svg') in self.fs.data
        source='freshness-mark.svg' if changed else 'mark.svg'
        data=self.fs.read(root/'frontend/src/app'/source)
        asset='assets/'+('freshness-mark-' if changed else 'mark-')+f.sha(data)[:8]+'.svg'
        vite={'index.html':{'file':'assets/app.js','isEntry':True,'assets':[asset]}}
        dist={'index.html':b'<script src="./assets/app.js"></script>',
              '.vite/manifest.json':f.canonical(vite),'assets/app.js':asset.encode(),asset:data}
        droot=root/'build/frontend/dist'; sroot=root/'build/generated/frontend-resources/decompengine/web/ui'
        if self.defect!='stale' or mode!='fresh':self.fs.remove(droot);self.fs.remove(sroot)
        for name,value in dist.items():self.fs.write(droot/name,value)
        rows=[{'path':name,'sizeBytes':len(value),'sha256':f.sha(value)} for name,value in sorted(dist.items())]
        payload={'schemaVersion':1,'applicationVersion':'0.1.0','entryScript':'assets/app.js','entryStyles':[],'files':rows}
        digest=f.sha((f.json.dumps(payload,separators=(',',':'))+'\n').encode())
        manifest=f.json.dumps({**payload,'buildId':digest},separators=(',',':')).encode()
        self.fs.write(root/'build/frontend/asset-manifest.json',manifest)
        for name in ('bundle-report.json','bundle-composition.json'):self.fs.write(root/'build/frontend'/name,f.canonical({'asset':asset}))
        for name,value in dist.items():self.fs.write(sroot/name,value)
        self.fs.write(sroot/'asset-manifest.json',manifest)
        if self.defect=='stage':self.fs.write(sroot/asset,b'wrong staged bytes')
        if self.defect=='warm' and mode=='warm':self.fs.write(root/'build/frontend/bundle-report.json',b'changed report')


class Clock:
    now=0
    def __call__(self):return self.now


class FreshnessControls(unittest.TestCase):
    def harness(self,defect=None):
        clock=Clock(); ledger=f.Ledger(clock); files=MemoryFiles(ledger)
        source=Path('/repo/source'); work=Path('/repo/work'); fixture=work/'fixture'
        originals={'frontend/src/app/mark.svg':b'<svg/>','frontend/src/app/App.tsx':b"import mark from './mark.svg';",
                   'frontend/src/api/generated.ts':b'authored types','frontend/src/api/generated-schema.ts':b'authored schema',
                   'contracts/web/v1/contract.schema.json':b'{"definitions":{}}'}
        for name,data in originals.items():files.write(source/name,data);files.write(fixture/name,data)
        baseline=[str(source/'build/frontend/dist'),str(source/'build/frontend/asset-manifest.json'),
                  str(source/'build/generated/frontend-resources/decompengine/web/ui')]
        files.write(source/'build/frontend/dist/index.html',b'original checkout UI')
        files.write(source/'build/frontend/dist/.vite/manifest.json',b'authored original Vite baseline')
        files.write(source/'build/frontend/asset-manifest.json',b'authored original private manifest')
        files.write(source/'build/generated/frontend-resources/decompengine/web/ui/index.html',b'original staged UI')
        files.write(source/'build/generated/frontend-resources/decompengine/web/ui/asset-manifest.json',b'authored original private manifest')
        manifest={'gradle':'/repo/cache/bin/gradle','gradleHome':'/repo/cache','nodeHome':'/repo/node','javaHome':'/repo/java','packagedBaseline':baseline}
        runner=ProducedFixture(files,fixture,defect)
        return f.Freshness(source,work,manifest,ledger,files,runner),runner,files,clock

    def test_complete_authored_producer_reaches_all_controls_and_stage_only_result(self):
        diagnostic,runner,files,_=self.harness(); result=diagnostic.run()
        self.assertEqual('PASSED_STAGE_ONLY',result['status'])
        self.assertEqual({'PASSED'},{row['status'] for row in result['phases'].values()})
        self.assertFalse(result['fullIssue651Accepted']);self.assertFalse(result['descendantAbsenceProven'])
        self.assertEqual(8,len(runner.calls)) # five Gradle calls plus three drift checks
        for argv,env in runner.calls:
            self.assertNotIn('--rerun-tasks',argv)
            self.assertEqual('/repo/work/npm-download-cache',env['NPM_CONFIG_CACHE'])
            self.assertEqual('/repo/cache',env['GRADLE_USER_HOME'])
        self.assertEqual('false',runner.calls[0][1]['NPM_CONFIG_OFFLINE'])
        self.assertTrue(all(env['NPM_CONFIG_OFFLINE']=='true' for _,env in runner.calls[1:]))
        self.assertEqual(b'original checkout UI',files.read('/repo/source/build/frontend/dist/index.html'))
        self.assertTrue(all('/repo/work/fixture/' in p for p in files.removed))

    def test_required_checkout_baselines_cannot_be_replaced_or_omitted(self):
        diagnostic,_,files,_=self.harness(); original=diagnostic.manifest['packagedBaseline']
        self.assertEqual(set(original),set(diagnostic.baseline()))
        for bad in (['/repo/unrelated']*3,original[:2],original[:2]+['/repo/unrelated'],original+[original[0]]):
            with self.subTest(paths=bad),self.assertRaises(f.Refusal):
                f.baseline_paths(diagnostic.source,diagnostic.work,bad,files)
        self.assertEqual(4,len(f.baseline_paths(diagnostic.source,diagnostic.work,original+['/repo/source/build/libs/app.jar'],files)))
        with self.assertRaises(f.Refusal):f.baseline_paths(diagnostic.source,diagnostic.work,original+['/repo/unrelated/app.jar'],files)
        optional='/repo/source/build/resources/main/decompengine/web/ui'
        files.write(Path(optional)/'index.html',b'authored packaged UI')
        files.write(Path(optional)/'asset-manifest.json',b'authored manifest')
        diagnostic.manifest['packagedBaseline']=original+[optional]
        self.assertIn(optional,diagnostic.baseline())
        files.remove(Path(optional)/'asset-manifest.json')
        with self.assertRaisesRegex(f.Refusal,'incomplete'):diagnostic.baseline()
        # Missing real required bytes cannot be substituted by an empty directory.
        diagnostic.manifest['packagedBaseline']=original
        files.remove(Path(original[0])/'index.html')
        with self.assertRaisesRegex(f.Refusal,'incomplete'):diagnostic.baseline()

    def test_staged_packaged_and_jar_baselines_enforce_separate_caps_with_metadata(self):
        mib=1024**2
        def row(size):return {'bytes':size,'sha256':'a'*64}
        boundary={name:row(16*mib) for name in ('index.html','assets/a.js','assets/b.js','assets/c.js')}
        boundary['asset-manifest.json']=row(mib)
        too_many_assets={**boundary,'assets/one-byte-over.js':row(1)}
        #64MiB+1 asset bytes plus a smaller manifest still fits the old combined65MiB check.
        too_many_assets['asset-manifest.json']=row(mib-1)
        too_large_manifest={'index.html':row(1),'asset-manifest.json':row(mib+1)}
        for selector in ('/repo/source/build/generated/frontend-resources/decompengine/web/ui',
                         '/repo/source/build/resources/main/decompengine/web/ui',
                         '/repo/source/build/libs/app.jar'):
            with self.subTest(selector=selector):
                diagnostic,_,files,_=self.harness(); original_inventory=files.inventory
                if selector not in diagnostic.manifest['packagedBaseline']:diagnostic.manifest['packagedBaseline'].append(selector)
                active=[boundary]
                def inventory(path,*args,**kwargs):
                    if str(path)==selector:return active[0]
                    return original_inventory(path,*args,**kwargs)
                # Only the bounded observer is supplied; actual baseline selectors/partition consumers run.
                with patch.object(files,'inventory',side_effect=inventory),patch.object(files,'jar_ui',side_effect=lambda _:active[0],create=True):
                    self.assertEqual(boundary,diagnostic.baseline()[selector])
                    for bad in (too_many_assets,too_large_manifest):
                        active[0]=bad
                        with self.assertRaises(f.Refusal):diagnostic.baseline()
        self.assertEqual(boundary,f.check_ui_partition(boundary))
        valid_count={'index.html':row(1),**{'assets/'+str(i)+'.js':row(1) for i in range(2047)},'asset-manifest.json':row(mib)}
        f.check_ui_partition(valid_count)
        with self.assertRaisesRegex(f.Refusal,'nonmanifest'):f.check_ui_partition({**valid_count,'assets/extra.js':row(1)})

    def test_partitioned_directory_and_jar_refuse_before_payload_and_close(self):
        files=f.Files.__new__(f.Files);files.ledger=f.Ledger(Clock());files.repository=Path('/repo')
        class Items:
            closed=False
            def __enter__(self):return self
            def __exit__(self,*args):self.closed=True
            def __next__(self):return SimpleNamespace(path='/repo/tree/asset-manifest.json',stat=lambda **_:SimpleNamespace(st_mode=f.stat.S_IFREG,st_size=1024**2+1))
        items=Items()
        with patch.object(files,'path',side_effect=lambda p:Path(p)),patch.object(files,'read') as read,patch.object(f.os,'scandir',return_value=items):
            with self.assertRaisesRegex(f.Refusal,'private manifest'):files.inventory(Path('/repo/tree'),(8192,16*1024**2,65*1024**2,16),partitioned_ui=True)
        read.assert_not_called();self.assertTrue(items.closed)
        # A small mocked central directory declares an oversized private member;
        # actual jar_ui must refuse its metadata before opening member payload.
        raw=f.struct.pack('<4s4H2IH',b'PK\x05\x06',0,0,1,1,0,0,0)
        class Stream(io.BytesIO):
            def fileno(self):return 42
        stream=Stream(raw)
        info=SimpleNamespace(filename='decompengine/web/ui/asset-manifest.json',file_size=1024**2+1,external_attr=f.stat.S_IFREG<<16,is_dir=lambda:False)
        archive=MagicMock();archive.__enter__.return_value=archive;archive.infolist.return_value=[info]
        with patch.object(files,'path',return_value=Path('/repo/app.jar')),patch.object(f.os,'open',return_value=42),patch.object(f.os,'fstat',return_value=SimpleNamespace(st_mode=f.stat.S_IFREG,st_size=len(raw))),patch.object(f.os,'fdopen',return_value=stream),patch.object(f.zipfile,'ZipFile',return_value=archive),patch.object(f.os,'close') as close:
            with self.assertRaisesRegex(f.Refusal,'private manifest'):files.jar_ui('/repo/app.jar')
        archive.open.assert_not_called();self.assertTrue(stream.closed);close.assert_not_called()

    def test_output_metadata_file_admission_precedes_extra_read_and_closes_scan(self):
        # No large payload: all entries have zero bytes. Source entry admission
        # remains independent; staged UI alone has one extra private-manifest slot.
        vectors=((2048,'dist',2048,False),(2049,'dist',2048,True),
                 (2049,'source',2049,False),(2049,'staged',2049,False),(2050,'staged',2049,True))
        for total,policy,reads,refused in vectors:
            with self.subTest(total=total,policy=policy):
                files=f.Files.__new__(f.Files);files.ledger=f.Ledger(Clock());files.repository=Path('/repo')
                class Items:
                    closed=False;index=0
                    def __enter__(self):return self
                    def __exit__(self,*args):self.closed=True
                    def __next__(self):
                        self.index+=1
                        if self.index>total:raise StopIteration
                        # The2049th dist file must not acquire a manifest exception.
                        name='asset-manifest.json' if self.index==2049 else 'asset-%04d.js'%self.index
                        return SimpleNamespace(path='/repo/tree/'+name,stat=lambda **_:SimpleNamespace(st_mode=f.stat.S_IFREG,st_size=0))
                items=Items();kwargs={'dist_assets':True} if policy=='dist' else {'partitioned_ui':True} if policy=='staged' else {}
                limits=f.SOURCE if policy=='source' else (8192,16*1024**2,65*1024**2,16) if policy=='staged' else f.OUTPUT
                with patch.object(files,'path',side_effect=lambda p:Path(p)),patch.object(files,'read',return_value=b'') as read,patch.object(f.os,'scandir',return_value=items):
                    if refused:
                        with self.assertRaises(f.Refusal):files.inventory(Path('/repo/tree'),limits,**kwargs)
                    else:self.assertEqual(total,len(files.inventory(Path('/repo/tree'),limits,**kwargs)))
                self.assertEqual(reads,read.call_count);self.assertTrue(items.closed)

    def test_real_baseline_and_snapshot_consumers_select_dist_and_staged_policies(self):
        diagnostic,_,files,_=self.harness(); inventory=files.inventory
        with patch.object(files,'inventory',wraps=inventory) as observed:
            diagnostic.baseline()
            call=next(c for c in observed.call_args_list if str(c.args[0])=='/repo/source/build/frontend/dist')
            self.assertIs(True,call.kwargs['dist_assets']);self.assertIs(False,call.kwargs['partitioned_ui'])
        diagnostic.build('cold')
        with patch.object(files,'inventory',wraps=inventory) as observed:
            diagnostic.snapshot()
            dist=next(c for c in observed.call_args_list if str(c.args[0]).endswith('/build/frontend/dist'))
            staged=next(c for c in observed.call_args_list if str(c.args[0]).endswith('/build/generated/frontend-resources/decompengine/web/ui'))
            self.assertIs(True,dist.kwargs['dist_assets'])
            self.assertIs(True,staged.kwargs['partitioned_ui'])
            self.assertNotIn('dist_assets',staged.kwargs)

    def test_prebuild_failure_attributes_only_its_current_phase(self):
        for defect,current,passed,later in (
                ('drift-prep','drift',('cold','unchanged','warm'),('fresh',)),
                ('fresh-prep','fresh',('cold','unchanged','warm','drift'),())):
            with self.subTest(defect=defect):
                diagnostic,_,_,_=self.harness(defect)
                with self.assertRaises(f.Refusal) as caught:diagnostic.run()
                result=diagnostic.failure(caught.exception)
                self.assertEqual('FAILED_OR_UNKNOWN',result['phases'][current]['status'])
                for name in passed:self.assertEqual('PASSED',result['phases'][name]['status'])
                for name in later:self.assertEqual('NOT_RUN',result['phases'][name]['status'])
                self.assertFalse(result['fullIssue651Accepted'])

    def test_byte_and_producer_outcome_defects_refuse(self):
        for defect in ('stage','warm','stale','cache','late'):
            with self.subTest(defect=defect):
                diagnostic,runner,files,_=self.harness(defect)
                with self.assertRaises(f.Refusal):diagnostic.run()
                self.assertLess(len(runner.calls),9)

    def test_false_success_missing_duplicate_skipped_cache_and_no_source_refuse(self):
        original=build_output('cold')
        for bad in (original['output'].replace(b'> Task :stageFrontend\n',b''),
                    original['output']+b'> Task :stageFrontend\n',
                    original['output'].replace(b':frontendBuild\n',b':frontendBuild FROM-CACHE\n'),
                    original['output'].replace(b':frontendBuild\n',b':frontendBuild SKIPPED\n'),
                    original['output'].replace(b':frontendBuild\n',b':frontendBuild NO-SOURCE\n')):
            with self.subTest(output=bad),self.assertRaises(f.Refusal):f.require_outcomes({**original,'output':bad},'cold')
        for change in ({'code':1},{'reaped':False},{'intervened':True}):
            with self.assertRaises(f.Refusal):f.require_outcomes({**original,**change},'cold')

    def test_intended_drift_requires_exact_reason_and_negative_task_not_generic_failure(self):
        self.assertEqual('FAILED',f.require_outcomes(build_output('drift'),'drift')[':frontendBuild'])
        for change in ({'code':0},{'output':build_output('drift')['output'].replace(b'Generated contract drift:',b'other failure:')}):
            with self.assertRaises(f.Refusal):f.require_outcomes({**build_output('drift'),**change},'drift')

    def test_original_end_reserve_and_late_zero_no_reset(self):
        clock=Clock();ledger=f.Ledger(clock);end=ledger.end
        clock.now=404;self.assertEqual(1,ledger.check())
        clock.now=405
        with self.assertRaises(f.Refusal):ledger.check()
        self.assertEqual(15,ledger.check(cleanup=True));self.assertEqual(end,ledger.end)
        clock.now=420
        with self.assertRaises(f.Refusal):ledger.check(cleanup=True)

    def test_log_and_evidence_limits_refuse_not_truncate(self):
        ledger=f.Ledger(Clock())
        with self.assertRaises(f.Refusal):ledger.output(2*1024**2+1,2*1024**2+1)
        ledger=f.Ledger(Clock())
        for _ in range(4):ledger.output(2*1024**2,2*1024**2)
        with self.assertRaises(f.Refusal):ledger.output(1,1)
        ledger=f.Ledger(Clock());ledger.evidence(16*1024**2)
        with self.assertRaises(f.Refusal):ledger.evidence(1)

    def test_actual_runner_late_zero_and_leftovers_fail_without_post_reap_signal(self):
        for defect in ('success','late-zero','leftover','timeout'):
            with self.subTest(defect=defect):
                clock=Clock();ledger=f.Ledger(clock);files=MemoryFiles(ledger);signals=[]
                state={'reaped':False,'closed':False,'registered':True}
                class Stream:
                    def fileno(self):return 42
                    def close(self):state['closed']=True
                class Child:
                    pid=123;stdout=Stream()
                    def wait(self,timeout):
                        state['reaped']=True
                        if defect=='late-zero':clock.now=406
                        return 0
                class Selector:
                    def __enter__(self):return self
                    def __exit__(self,*args):pass
                    def register(self,*args):pass
                    def get_map(self):return {'authored':True} if state['registered'] else {}
                    def select(self,timeout):
                        if defect=='timeout':clock.now=406
                        return [(SimpleNamespace(fileobj=Child.stdout),None)]
                    def unregister(self,*args):state['registered']=False
                def observe(*args):
                    if state['reaped']:raise ChildProcessError('already reaped')
                    return None
                def signal_group(pid,number):
                    if number and state['reaped']:raise AssertionError('destructive post-reap signal')
                    signals.append(number)
                    if number==0 and defect!='leftover':raise ProcessLookupError('absent')
                runner=f.Runner(ledger,files,Path('/repo/evidence'))
                with patch.object(f.signal,'getsignal',return_value=f.signal.SIG_DFL),patch.object(f.subprocess,'Popen',return_value=Child()) as launch,patch.object(f.selectors,'DefaultSelector',return_value=Selector()),patch.object(f.os,'set_blocking'),patch.object(f.os,'read',return_value=b''),patch.object(f.os,'waitid',side_effect=observe),patch.object(f.os,'killpg',side_effect=signal_group):
                    if defect=='success':
                        result=runner(['NOT_EXECUTED'],Path('/repo/work'),{})
                        self.assertEqual({'code':0,'output':b'','intervened':False,'reaped':True},result)
                    else:
                        with self.assertRaises(f.Refusal):runner(['NOT_EXECUTED'],Path('/repo/work'),{})
                self.assertEqual(1,launch.call_count);self.assertTrue(state['closed']);self.assertEqual(defect!='success',runner.uncertain)
                self.assertEqual([f.signal.SIGTERM] if defect=='timeout' else ([0] if defect in ('leftover','success') else []),signals)
                self.assertIn('/repo/evidence/command-01.log',files.data)

    def test_jar_descriptor_admission_refuses_special_or_oversize_before_stream(self):
        files=f.Files.__new__(f.Files);files.ledger=f.Ledger(Clock());files.repository=Path('/repo')
        for mode,size in ((f.stat.S_IFIFO,0),(f.stat.S_IFREG,256*1024**2+1)):
            with self.subTest(mode=mode,size=size),patch.object(files,'path',return_value=Path('/repo/app.jar')),patch.object(f.os,'open',return_value=42) as opened,patch.object(f.os,'fstat',return_value=SimpleNamespace(st_mode=mode,st_size=size)),patch.object(f.os,'fdopen') as stream,patch.object(f.os,'close') as close,patch.object(f.zipfile,'ZipFile') as allocated:
                with self.assertRaisesRegex(f.Refusal,'regular size'):files.jar_ui('/repo/app.jar')
                flags=opened.call_args.args[1]
                self.assertEqual(f.os.O_NONBLOCK|f.os.O_NOFOLLOW,flags&(f.os.O_NONBLOCK|f.os.O_NOFOLLOW))
                stream.assert_not_called();allocated.assert_not_called();close.assert_called_once_with(42)
        with patch.object(files,'path',return_value=Path('/repo/app.jar')),patch.object(f.os,'open',return_value=43),patch.object(f.os,'fstat',return_value=SimpleNamespace(st_mode=f.stat.S_IFREG,st_size=4)),patch.object(f.os,'fdopen',side_effect=OSError('authored stream refusal')),patch.object(f.os,'close') as close:
            with self.assertRaises(OSError):files.jar_ui('/repo/app.jar')
            close.assert_called_once_with(43)

    def test_admitted_inmemory_jar_reads_actual_ui_crc_and_closes_stream(self):
        data=io.BytesIO()
        with f.zipfile.ZipFile(data,'w',compression=f.zipfile.ZIP_STORED) as archive:
            archive.writestr('decompengine/web/ui/index.html',b'authored UI')
            archive.writestr('decompengine/web/ui/asset-manifest.json',b'authored manifest')
        raw=data.getvalue()
        class Stream(io.BytesIO):
            def fileno(self):return 42
        stream=Stream(raw)
        metadata=SimpleNamespace(st_dev=1,st_ino=2,st_mode=f.stat.S_IFREG|0o644,st_size=len(raw),st_mtime_ns=3,st_ctime_ns=4)
        files=f.Files.__new__(f.Files);files.ledger=f.Ledger(Clock());files.repository=Path('/repo')
        with patch.object(files,'path',return_value=Path('/repo/app.jar')),patch.object(f.os,'open',return_value=42),patch.object(f.os,'fstat',return_value=metadata),patch.object(f.os,'fdopen',return_value=stream),patch.object(Path,'stat',return_value=metadata),patch.object(f.os,'close') as close:
            rows=files.jar_ui('/repo/app.jar')
        self.assertEqual({'index.html','asset-manifest.json'},set(rows))
        self.assertEqual(f.sha(b'authored UI'),rows['index.html']['sha256'])
        self.assertTrue(stream.closed);close.assert_not_called()

    def test_cleanup_observation_expiry_never_signals_or_masks_primary(self):
        for late_observation in (1,2):
            with self.subTest(observation=late_observation):
                clock=Clock();ledger=f.Ledger(clock);files=MemoryFiles(ledger);calls=[]
                primary=f.Refusal('authored original failure');observations=[];closed=[]
                class Stream:
                    def fileno(self):return 42
                    def close(self):closed.append(True)
                class Child:
                    pid=123;stdout=Stream()
                    def wait(self,timeout):raise f.subprocess.TimeoutExpired('authored',timeout)
                class Selector:
                    def __enter__(self):return self
                    def __exit__(self,*args):pass
                    def register(self,*args):pass
                    def get_map(self):return {'pending':True}
                    def select(self,timeout):raise primary
                def observe(*args):
                    observations.append(1)
                    if len(observations)==late_observation:clock.now=421
                    return None
                def signal_group(pid,number):calls.append(number)
                runner=f.Runner(ledger,files,Path('/repo/evidence'))
                with patch.object(f.signal,'getsignal',return_value=f.signal.SIG_DFL),patch.object(f.subprocess,'Popen',return_value=Child()),patch.object(f.selectors,'DefaultSelector',return_value=Selector()),patch.object(f.os,'set_blocking'),patch.object(f.os,'waitid',side_effect=observe),patch.object(f.os,'killpg',side_effect=signal_group):
                    with self.assertRaises(f.Refusal) as caught:runner(['NOT_EXECUTED'],Path('/repo/work'),{})
                self.assertIs(primary,caught.exception);self.assertEqual([True],closed)
                self.assertEqual([] if late_observation==1 else [f.signal.SIGTERM],calls)
                self.assertEqual(420,ledger.end);self.assertTrue(runner.uncertain)
                self.assertNotIn('/repo/evidence/command-01.json',files.data)

    def test_duplicate_closed_manifest_json_is_not_silently_accepted(self):
        with self.assertRaises(f.Refusal):f.closed_json(b'{"sources":{},"sources":{}}')

    def test_source_fingerprint_each_existing_key_input_changes(self):
        original={name:'a'*64 for name in f.KEYS};original.update(os='linux',arch='x64')
        for name in original:
            changed={**original,name:'different'}
            self.assertNotEqual(f.sha(f.canonical(original)),f.sha(f.canonical(changed)))

    def test_inventory_entry_admission_and_iterator_closes(self):
        clock=Clock();ledger=f.Ledger(clock);files=f.Files.__new__(f.Files)
        files.ledger=ledger;files.repository=Path('/repo')
        class Items:
            closed=False
            def __enter__(self):return self
            def __exit__(self,*args):self.closed=True
            def __next__(self):return SimpleNamespace(path='/repo/tree/a',stat=lambda **_:SimpleNamespace(st_mode=f.stat.S_IFREG,st_size=1))
        items=Items()
        with patch.object(files,'path',side_effect=lambda p:Path(p)),patch.object(files,'read',return_value=b'x') as read,patch.object(f.os,'scandir',return_value=items):
            with self.assertRaises(f.Refusal):files.inventory(Path('/repo/tree'),(1,16,128,2))
        self.assertTrue(items.closed);self.assertEqual(1,read.call_count)

    def test_read_admits_special_file_before_read_and_closes_descriptor(self):
        files=f.Files.__new__(f.Files);files.ledger=f.Ledger(Clock());files.repository=Path('/repo')
        with patch.object(files,'path',return_value=Path('/repo/input')),patch.object(f.os,'open',return_value=42),patch.object(f.os,'fstat',return_value=SimpleNamespace(st_mode=f.stat.S_IFIFO,st_size=0)),patch.object(f.os,'read') as read,patch.object(f.os,'close') as close:
            with self.assertRaises(f.Refusal):files.read('/repo/input')
        read.assert_not_called();close.assert_called_once_with(42)


if __name__=='__main__':
    unittest.main()
