#!/usr/bin/env python3
"""Authored injected vectors only: no Gradle/npm/child/network/real fixture work."""
import importlib.util
from contextlib import ExitStack
import io
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch, MagicMock
import unittest

spec=importlib.util.spec_from_file_location('frontend_freshness',Path(__file__).with_name('verify-frontend-freshness.py'))
f=importlib.util.module_from_spec(spec)
spec.loader.exec_module(f)


class MemoryFiles:
    def __init__(self,ledger): self.ledger=ledger; self.data={}; self.modes={}; self.removed=[]; self.tool_kinds={}; self.tool_seeds=[]
    def path(self,path): return Path(path)
    def read(self,path,maximum=16*1024**2):
        self.ledger.check(); data=self.data[str(path)]
        if len(data)>maximum: raise f.Refusal('read bound')
        return data
    def npm_launcher(self,path):
        data=self.read(path,512)
        if data!=f.NPM_LINK.encode('ascii'):raise f.Refusal('fixed npm launcher link required')
        return data
    def write(self,path,data,evidence=False):
        self.ledger.check(cleanup=evidence)
        if evidence:self.ledger.evidence(len(data))
        self.data[str(path)]=data; self.modes.setdefault(str(path),0o644)
    def write_input(self,path,data,mode):
        self.write(path,data); self.modes[str(path)]=mode
    def inventory(self,path,limits=f.OUTPUT,*,partitioned_ui=False,dist_assets=False,input_sources=None):
        prefix=str(path)+'/'
        rows={name[len(prefix):]:{'bytes':len(data),'sha256':f.sha(data)} for name,data in sorted(self.data.items()) if name.startswith(prefix) and (input_sources is None or not any(name[len(prefix):].startswith(root+'/') for root in f.SOURCE_OUTPUTS))}
        if input_sources is not None:
            for name,row in rows.items():row['mode']=self.modes.get(prefix+name,0o644)
        if dist_assets and len(rows)>2048:raise f.Refusal('dist asset file bound')
        return f.check_ui_partition(rows) if partitioned_ui else rows
    def tool_inventory(self,roots,pins):
        names=set(self.tool_kinds)|set(self.data)
        names={name for name in names if any(Path(name).is_relative_to(Path(root)) for root in roots)}
        rows={}
        for name in sorted(names):
            if name not in pins:raise f.Refusal('unexpected tool input')
            kind=self.tool_kinds.get(name,'regular');row={'kind':kind,'mode':self.modes.get(name,0o755 if kind=='directory' else 0o644)}
            if kind!='directory':
                if name not in self.data:raise f.Refusal('missing tool input')
                data=self.read(name,pins[name].get('bytes',0))
                row.update(bytes=len(data),sha256=f.sha(data))
                if kind=='symlink':row['target']=data.decode()
            if row!=pins[name]:raise f.Refusal('tool input disagreement')
            rows[name]=row
        if rows!=pins:raise f.Refusal('missing tool input')
        return rows
    def seed_tool_cache(self,root,destination,pins):
        self.remove(destination);self.tool_seeds.append(f.sha(f.canonical(pins)))
        for name,pin in pins.items():
            if not Path(name).is_relative_to(Path(root)):continue
            target=str(Path(destination)/Path(name).relative_to(root))
            self.tool_kinds[target]=pin['kind'];self.modes[target]=pin['mode'] if pin['kind']=='symlink' else pin['mode']|(0o700 if pin['kind']=='directory' else 0o600)
            if pin['kind']=='directory':continue
            data=self.read(name,pin['bytes'])
            if f.sha(data)!=pin['sha256']:raise f.Refusal('tool cache seed changed')
            self.write(Path(destination)/Path(name).relative_to(root),data)

    def remove(self,path):
        self.ledger.check(); prefix=str(path); self.removed.append(prefix)
        for name in list(self.data):
            if name==prefix or name.startswith(prefix+'/'):
                del self.data[name];self.modes.pop(name,None)
        for name in list(self.tool_kinds):
            if name==prefix or name.startswith(prefix+'/'):
                del self.tool_kinds[name];self.modes.pop(name,None)


def build_output(mode):
    names=f.TASKS[:3] if mode=='drift' else f.TASKS
    labels={name:'' for name in names}
    if mode in ('unchanged','fresh','stale','drift'):labels['frontendInstall']=' UP-TO-DATE'
    if mode=='stale':labels['generateFrontendAssetManifest']=' UP-TO-DATE'
    if mode=='unchanged':
        for name in ('frontendBuild','generateFrontendAssetManifest','stageFrontend'):labels[name]=' UP-TO-DATE'
    if mode=='drift':labels['frontendBuild']=' FAILED'
    output='\n'.join('> Task :'+name+labels[name] for name in names)+'\n'
    if mode=='drift':output+='Generated contract drift: authored module\n'
    return {'code':1 if mode=='drift' else 0,'output':output.encode(),'intervened':False,'reaped':True}


class ProducedFixture:
    """An authored producer derives closure bytes from current in-memory inputs."""
    def __init__(self,files,fixture,defect=None):
        self.fs=files; self.fixture=fixture; self.defect=defect; self.calls=[]; self.observations=[]
    def __call__(self,argv,cwd,env):
        self.calls.append((argv,env)); self.fs.ledger.check()
        if argv[-1]=='--check':
            if self.defect=='drift-prep':return {'code':1,'output':b'wrong diagnostic','intervened':False,'reaped':True}
            return {'code':1,'output':b'Generated contract drift: authored module','intervened':False,'reaped':True}
        mode=('cold','unchanged','warm','fresh','stale','drift')[sum(a[-1]!='--check' for a,_ in self.calls)-1]
        guard=self.fs.read(Path('/repo/work/graph.gradle'))
        if guard!=f.init_guard(f.TASKS[:3] if mode=='drift' else f.TASKS):raise AssertionError('wrong graph guard')
        sentinel=any(str(self.fixture/part/'assets/freshness-obsolete.svg') in self.fs.data for part in ('build/frontend/dist','build/generated/frontend-resources/decompengine/web/ui'))
        self.observations.append((mode,sentinel))
        if mode not in ('unchanged','drift') and not (self.defect=='missing-source-input' and mode=='fresh'):self.produce(mode)
        if self.defect=='late' and mode=='cold':self.fs.ledger.clock.now=406
        result=build_output(mode)
        if self.defect=='missing-source-input' and mode=='fresh':result['output']=result['output'].replace(b':frontendBuild\n',b':frontendBuild UP-TO-DATE\n')
        if self.defect=='stale-manifest' and mode=='stale':self.fs.write(self.fixture/'build/frontend/asset-manifest.json',b'invalid authored manifest')
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
        if self.defect!='stale' or mode!='stale':self.fs.remove(droot);self.fs.remove(sroot)
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
        if defect=='fresh-prep':originals['frontend/src/app/mark.svg']=b'no SVG anchor'
        for name,data in originals.items():files.write(source/name,data);files.write(fixture/name,data)
        baseline=[str(source/'build/frontend/dist'),str(source/'build/frontend/asset-manifest.json'),
                  str(source/'build/generated/frontend-resources/decompengine/web/ui')]
        files.write(source/'build/frontend/dist/index.html',b'original checkout UI')
        files.write(source/'build/frontend/dist/.vite/manifest.json',b'authored original Vite baseline')
        files.write(source/'build/frontend/asset-manifest.json',b'authored original private manifest')
        files.write(source/'build/generated/frontend-resources/decompengine/web/ui/index.html',b'original staged UI')
        files.write(source/'build/generated/frontend-resources/decompengine/web/ui/asset-manifest.json',b'authored original private manifest')
        tools={}
        leaves=(('/repo/cache/bin/gradle',b'authored Gradle launcher',0o755,'regular'),
                ('/repo/cache/lib/gradle-launcher.jar',b'authored Gradle implementation',0o644,'regular'),
                ('/repo/cache/caches/modules/dependency.jar',b'authored offline dependency',0o644,'regular'),
                ('/repo/cache/init.d/trusted.gradle',b'authored reviewed initializer',0o644,'regular'),
                ('/repo/node/bin/node',b'authored Node executable',0o755,'regular'),
                ('/repo/node/bin/npm',f.NPM_LINK.encode('ascii'),0o777,'symlink'),
                ('/repo/node/lib/node_modules/npm/bin/npm-cli.js',b'// authored inert npm entry',0o644,'regular'),
                ('/repo/node/lib/node_modules/npm/lib/cli.js',b'// authored npm implementation',0o644,'regular'),
                ('/repo/java/bin/java',b'authored Java launcher',0o755,'regular'),
                ('/repo/java/lib/modules',b'authored Java runtime',0o644,'regular'))
        for name,data,mode,kind in leaves:
            files.write(name,data);files.modes[name]=mode;files.tool_kinds[name]=kind
            tools[name]={'kind':kind,'mode':mode,'bytes':len(data),'sha256':f.sha(data)}
            if kind=='symlink':tools[name]['target']=data.decode()
            for parent in Path(name).parents:
                if str(parent)=='/repo':break
                tools[str(parent)]={'kind':'directory','mode':0o755};files.tool_kinds[str(parent)]='directory';files.modes[str(parent)]=0o755
        manifest={'sources':{name:{'bytes':len(data),'sha256':f.sha(data),'mode':0o644} for name,data in originals.items()},'tools':tools,'gradle':'/repo/cache/bin/gradle','gradleHome':'/repo/cache','nodeHome':'/repo/node','javaHome':'/repo/java','packagedBaseline':baseline}
        runner=ProducedFixture(files,fixture,defect)
        return f.Freshness(source,work,manifest,ledger,files,runner),runner,files,clock

    def test_original_generated_checkout_comparison_remains_required(self):
        diagnostic,runner,files,_=self.harness(); original=diagnostic.runner
        def run(argv,cwd,env):
            result=original(argv,cwd,env)
            if argv[-1]=='--check' and sum(a[-1]=='--check' for a,_ in runner.calls)==3:
                files.write(diagnostic.source/'frontend/src/api/generated.ts',b'authored original-checkout mutation')
            return result
        diagnostic.runner=run
        with self.assertRaises(f.Refusal):diagnostic.run()
        self.assertEqual(3,sum(argv[-1]=='--check' for argv,_ in runner.calls))

    def test_every_gradle_phase_revalidates_all_copied_inputs(self):
        phases=('cold','unchanged','warm','fresh','stale','drift')
        for target in phases:
            with self.subTest(phase=target):
                diagnostic,runner,files,_=self.harness(); original=diagnostic.runner
                def run(argv,cwd,env):
                    result=original(argv,cwd,env)
                    if argv[-1]!='--check' and sum(a[-1]!='--check' for a,_ in runner.calls)==phases.index(target)+1:
                        files.write(diagnostic.fixture/'contracts/web/v1/contract.schema.json',b'{"definitions":{"unreviewed":{"type":"string"}}}')
                    return result
                diagnostic.runner=run
                with self.assertRaises(f.Refusal):diagnostic.run()
                self.assertEqual(phases.index(target)+1,sum(a[-1]!='--check' for a,_ in runner.calls))

    def test_every_api_check_rejects_mutation_of_another_copied_input(self):
        for index in range(3):
            with self.subTest(check=index):
                diagnostic,runner,files,_=self.harness(); original=diagnostic.runner
                def run(argv,cwd,env):
                    result=original(argv,cwd,env)
                    if argv[-1]=='--check' and sum(a[-1]=='--check' for a,_ in runner.calls)==index+1:
                        name='contracts/web/v1/contract.schema.json' if index<2 else 'frontend/src/app/App.tsx'
                        changed=b'{"definitions":{"unreviewed":{"type":"string"}}}' if index<2 else b"import mark from './unreviewed.svg';"
                        files.write(diagnostic.fixture/name,changed)
                    return result
                diagnostic.runner=run
                with self.assertRaises(f.Refusal):diagnostic.run()
                self.assertEqual(index+1,sum(a[-1]=='--check' for a,_ in runner.calls))

    def test_source_mutation_between_stale_snapshot_and_drift_cannot_become_original(self):
        diagnostic,runner,files,_=self.harness(); original=diagnostic.snapshot
        def snapshot():
            result=original()
            if diagnostic.active=='stale':files.write(diagnostic.fixture/'contracts/web/v1/contract.schema.json',b'{"definitions":{"late":{"type":"string"}}}')
            return result
        diagnostic.snapshot=snapshot
        with self.assertRaises(f.Refusal):diagnostic.run()
        self.assertFalse(any(argv[-1]=='--check' for argv,_ in runner.calls))

    def test_source_namespace_modes_and_manifest_alias_cannot_change_after_capture(self):
        for defect in ('extra','missing','mode','manifest-alias'):
            with self.subTest(defect=defect):
                diagnostic,runner,files,_=self.harness(); path=diagnostic.fixture/'contracts/web/v1/contract.schema.json'; original=diagnostic.runner
                def run(argv,cwd,env):
                    result=original(argv,cwd,env)
                    if len(runner.calls)==1:
                        if defect=='extra':files.write(diagnostic.fixture/'buildSrc/unreviewed.gradle.kts',b'authored unexpected code')
                        elif defect=='missing':files.remove(path)
                        elif defect=='mode':files.modes[str(path)]=0o755
                        else:
                            changed=b'{"definitions":{"aliased":{"type":"string"}}}';files.write(path,changed)
                            diagnostic.manifest['sources']['contracts/web/v1/contract.schema.json'].update(bytes=len(changed),sha256=f.sha(changed))
                    return result
                diagnostic.runner=run
                with self.assertRaises(f.Refusal):diagnostic.run()
                self.assertEqual(1,len(runner.calls))

    def test_owned_fresh_edits_preserve_pins_and_originals_without_extra_commands(self):
        diagnostic,runner,files,_=self.harness(); initial=f.canonical(diagnostic.manifest['sources']); result=diagnostic.run()
        self.assertEqual(initial,f.canonical(diagnostic.manifest['sources']))
        self.assertNotIn('frontend/src/app/mark.svg',diagnostic._inputs)
        fresh=diagnostic._inputs['frontend/src/app/freshness-mark.svg'];self.assertEqual(0o644,fresh['mode'])
        for name in ('frontend/src/api/generated.ts','frontend/src/api/generated-schema.ts','contracts/web/v1/contract.schema.json'):
            self.assertEqual(diagnostic.manifest['sources'][name],diagnostic._inputs[name])
        self.assertEqual(f.sha(f.canonical(diagnostic._inputs)),result['copiedInputSha256'])
        self.assertEqual(3,len(result['phases']['drift']['apiSourceChecks']))
        self.assertEqual(9,len(runner.calls));self.assertFalse(result['fullIssue651Accepted'])

    def test_input_inventory_refuses_unexpected_size_or_mode_before_payload(self):
        pin={'bytes':1,'sha256':f.sha(b'x'),'mode':0o644}
        for defect in ('unexpected','size','mode'):
            with self.subTest(defect=defect):
                files=f.Files.__new__(f.Files);files.ledger=f.Ledger(Clock());files.repository=Path('/repo')
                class Items:
                    closed=False;done=False
                    def __enter__(self):return self
                    def __exit__(self,*args):self.closed=True
                    def __next__(self):
                        if self.done:raise StopIteration
                        self.done=True
                        return SimpleNamespace(path='/repo/fixture/'+('unexpected' if defect=='unexpected' else 'input'),stat=lambda **_:SimpleNamespace(st_mode=f.stat.S_IFREG|(0o755 if defect=='mode' else 0o644),st_size=2 if defect=='size' else 1))
                items=Items()
                with patch.object(files,'path',side_effect=lambda p:Path(p)),patch.object(files,'read') as read,patch.object(f.os,'scandir',return_value=items):
                    with self.assertRaises(f.Refusal):files.inventory('/repo/fixture',f.SOURCE,input_sources={'input':pin})
                read.assert_not_called();self.assertTrue(items.closed)

    def test_complete_authored_producer_reaches_all_controls_and_stage_only_result(self):
        diagnostic,runner,files,_=self.harness(); result=diagnostic.run()
        self.assertEqual('PASSED_STAGE_ONLY',result['status'])
        self.assertEqual({'PASSED'},{row['status'] for row in result['phases'].values()})
        self.assertFalse(result['fullIssue651Accepted']);self.assertFalse(result['descendantAbsenceProven'])
        self.assertEqual(9,len(runner.calls)) # six Gradle calls plus three drift checks
        for argv,env in runner.calls:
            self.assertNotIn('--rerun-tasks',argv)
            self.assertEqual('/repo/work/npm-download-cache',env['NPM_CONFIG_CACHE'])
            self.assertEqual('/repo/work/gradle-home',env['GRADLE_USER_HOME'])
        self.assertEqual('false',runner.calls[0][1]['NPM_CONFIG_OFFLINE'])
        self.assertTrue(all(env['NPM_CONFIG_OFFLINE']=='true' for _,env in runner.calls[1:]))
        self.assertEqual(b'original checkout UI',files.read('/repo/source/build/frontend/dist/index.html'))
        self.assertTrue(all('/repo/work/fixture/' in p or p=='/repo/work/gradle-home' for p in files.removed))
        self.assertEqual(6,files.removed.count('/repo/work/gradle-home'))

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
        info=SimpleNamespace(orig_filename='decompengine/web/ui/asset-manifest.json',filename='decompengine/web/ui/asset-manifest.json',file_size=1024**2+1,external_attr=f.stat.S_IFREG<<16,is_dir=lambda:False)
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
                ('drift-prep','drift',('cold','unchanged','warm','fresh','stale'),()),
                ('fresh-prep','fresh',('cold','unchanged','warm'),('stale','drift'))):
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

    def cancellation_runner_vector(self, when, number, *, repeat=False):
        clock=Clock();ledger=f.Ledger(clock);files=MemoryFiles(ledger);events=[]
        state={'waited':False,'closed':False,'registered':True}
        primary=OSError('authored launch failure')
        class Stream:
            def fileno(self):return 42
            def close(self):state['closed']=True
        class Child:
            pid=123;stdout=Stream()
            def wait(self,timeout):
                self_test.assertFalse(state['waited']);state['waited']=True
                events.append(('wait',timeout));return 0
        self_test=self
        def launch(*args,**kwargs):
            events.append(('launch',dict(kwargs)))
            if when in ('launch','launch-error'):ledger.cancel(number,None)
            if when=='launch-error':raise primary
            return Child()
        class Selector:
            def __init__(self):
                if when=='after-owned':ledger.cancel(number,None)
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def register(self,*args):pass
            def get_map(self):return {1:True} if state['registered'] else {}
            def select(self,timeout):return [(SimpleNamespace(fileobj=Child.stdout),None)]
            def unregister(self,*args):state['registered']=False
        def observe(kind,pid,flags):
            self.assertFalse(state['waited']);events.append(('observe',pid))
            return SimpleNamespace(si_pid=123,si_code=f.os.CLD_EXITED)
        def send(pid,value):
            self.assertEqual(123,pid);events.append(('signal',value))
            if value:
                self.assertFalse(state['waited'])
                if repeat:ledger.cancel(f.signal.SIGINT,None)
            else:raise ProcessLookupError('authored absent group')
        runner=f.Runner(ledger,files,Path('/repo/evidence'));result=error=None
        if when=='before':ledger.cancel(number,None)
        with ExitStack() as stack:
            for obj,name,kwargs in ((f.signal,'getsignal',{'return_value':f.signal.SIG_DFL}),(f.subprocess,'Popen',{'side_effect':launch}),(f.selectors,'DefaultSelector',{'side_effect':Selector}),(f.os,'set_blocking',{}),(f.os,'read',{'return_value':b''}),(f.os,'waitid',{'side_effect':observe}),(f.os,'killpg',{'side_effect':send}),(runner,'group_members',{'return_value':()})):
                stack.enter_context(patch.object(obj,name,**kwargs))
            try:result=runner(['NOT_EXECUTED'],Path('/repo/work'),{})
            except BaseException as caught:error=caught
        return result,error,state,events,files,runner,ledger,primary

    def test_cancellation_during_launch_owns_and_reaps_before_failure(self):
        for number in (f.signal.SIGTERM,f.signal.SIGINT):
            with self.subTest(number=number):
                result,error,state,events,files,runner,ledger,_=self.cancellation_runner_vector('launch',number)
                self.assertIsNone(result);self.assertIsInstance(error,f.Refusal)
                self.assertRegex(str(error),'ordinary cancellation');self.assertTrue(runner.uncertain)
                self.assertTrue(state['waited']);self.assertTrue(state['closed'])
                self.assertEqual([f.signal.SIGTERM,0],[v for k,v in events if k=='signal'])
                facts=f.closed_json(files.data['/repo/evidence/command-01.json'])
                self.assertTrue(facts['launcherCreated']);self.assertTrue(facts['rootReaped'])
                self.assertTrue(facts['intervened']);self.assertFalse(facts['descendantAbsenceProven'])
                launch=next(v for k,v in events if k=='launch')
                self.assertEqual({'cwd':Path('/repo/work'),'env':{},'stdout':f.subprocess.PIPE,'stderr':f.subprocess.STDOUT,'start_new_session':True},launch)
                self.assertEqual(number,ledger.cancellation);self.assertEqual(420,ledger.end)

    def test_cancellation_after_ownership_uses_same_cleanup_path(self):
        for number in (f.signal.SIGTERM,f.signal.SIGINT):
            with self.subTest(number=number):
                result,error,state,events,files,runner,_,_=self.cancellation_runner_vector('after-owned',number)
                self.assertIsNone(result);self.assertIsInstance(error,f.Refusal)
                self.assertTrue(state['waited']);self.assertTrue(state['closed']);self.assertTrue(runner.uncertain)
                self.assertEqual([f.signal.SIGTERM,0],[v for k,v in events if k=='signal'])
                self.assertTrue(f.closed_json(files.data['/repo/evidence/command-01.json'])['rootReaped'])

    def test_cancellation_before_launch_creates_no_child_or_signal(self):
        result,error,state,events,files,runner,_,_=self.cancellation_runner_vector('before',f.signal.SIGTERM)
        self.assertIsNone(result);self.assertIsInstance(error,f.Refusal)
        self.assertEqual([],events);self.assertFalse(state['waited']);self.assertFalse(state['closed'])
        self.assertEqual({},files.data);self.assertFalse(runner.uncertain)

    def test_launch_error_is_not_masked_by_recorded_cancellation(self):
        result,error,state,events,files,runner,_,primary=self.cancellation_runner_vector('launch-error',f.signal.SIGTERM)
        self.assertIsNone(result);self.assertIs(primary,error);self.assertTrue(runner.uncertain)
        self.assertFalse(state['waited']);self.assertFalse(state['closed'])
        self.assertEqual(['launch'],[k for k,_ in events])
        facts=f.closed_json(files.data['/repo/evidence/command-01.json'])
        self.assertFalse(facts['launcherCreated']);self.assertFalse(facts['rootReaped'])
        self.assertTrue(facts['intervened']);self.assertFalse(facts['descendantAbsenceProven'])

    def test_repeated_cancellation_during_cleanup_still_reaps_owned_child(self):
        result,error,state,events,files,runner,ledger,_=self.cancellation_runner_vector('launch',f.signal.SIGTERM,repeat=True)
        self.assertIsNone(result);self.assertIsInstance(error,f.Refusal)
        self.assertTrue(state['waited']);self.assertTrue(state['closed']);self.assertTrue(runner.uncertain)
        self.assertEqual(f.signal.SIGTERM,ledger.cancellation)
        self.assertEqual([f.signal.SIGTERM,0],[v for k,v in events if k=='signal'])
        self.assertTrue(f.closed_json(files.data['/repo/evidence/command-01.json'])['rootReaped'])

    def test_cancellation_does_not_extend_work_end_or_cleanup_reserve(self):
        clock=Clock();ledger=f.Ledger(clock);ledger.cancel(f.signal.SIGTERM,None)
        with self.assertRaisesRegex(f.Refusal,'ordinary cancellation'):ledger.check()
        self.assertEqual(420,ledger.check(cleanup=True));clock.now=405
        self.assertEqual(15,ledger.check(cleanup=True));clock.now=420
        with self.assertRaisesRegex(f.Refusal,'original absolute work end'):ledger.check(cleanup=True)
        self.assertEqual(420,ledger.end)

    def test_main_records_both_signals_and_restores_handlers_on_failure(self):
        for number in (f.signal.SIGTERM,f.signal.SIGINT):
            with self.subTest(number=number):
                ledger=f.Ledger(Clock());files=MemoryFiles(ledger)
                files.data['/repo/manifest.json']=b'{}'
                previous={f.signal.SIGTERM:object(),f.signal.SIGINT:object()};installed={};changes=[]
                def set_handler(value,handler):installed[value]=handler;changes.append((value,handler))
                def prepare(*args):
                    self.assertEqual({f.signal.SIGTERM,f.signal.SIGINT},set(installed))
                    for handler in installed.values():self.assertEqual(ledger.cancel,handler)
                    installed[number](number,None);ledger.check()
                with patch.object(f,'Ledger',return_value=ledger),patch.object(f,'Files',return_value=files),patch.object(f,'prepare',side_effect=prepare),patch.object(f,'Runner') as runner,patch.object(f.signal,'getsignal',side_effect=previous.__getitem__),patch.object(f.signal,'signal',side_effect=set_handler),patch.object(Path,'exists',return_value=False),patch.object(Path,'is_dir',return_value=True):
                    code=f.main(['--repository','/repo','--source','/repo/source','--work','/repo/work','--provisioned-manifest','/repo/manifest.json'])
                self.assertEqual(1,code);runner.assert_not_called();self.assertEqual(previous,installed)
                self.assertEqual(4,len(changes));self.assertEqual(number,ledger.cancellation)
                result=f.closed_json(files.data['/repo/work/evidence/result.json'])
                self.assertEqual('FAILED_OR_UNKNOWN',result['status']);self.assertIn('ordinary cancellation',result['reason'])
                self.assertTrue(result['fixtureRetained']);self.assertFalse(result['fullIssue651Accepted'])

    def test_closed_toolchain_rejects_omitted_extra_changed_and_mode_inputs(self):
        leaves=('/repo/cache/lib/gradle-launcher.jar','/repo/cache/caches/modules/dependency.jar','/repo/cache/init.d/trusted.gradle','/repo/node/lib/node_modules/npm/lib/cli.js','/repo/java/lib/modules')
        for name in leaves:
            for defect in ('omitted','extra','changed','mode'):
                with self.subTest(name=name,defect=defect):
                    diagnostic,runner,files,_=self.harness()
                    if defect=='omitted':
                        del diagnostic.manifest['tools'][name];diagnostic._tools=f.Toolchain(diagnostic.manifest,files)
                    elif defect=='extra':files.write(name+'.unreviewed',b'unknown code')
                    elif defect=='changed':files.data[name]+=b'changed'
                    else:files.modes[name]^=0o100
                    with self.assertRaises(f.Refusal):diagnostic.run()
                    self.assertEqual([],runner.calls)

    def test_every_command_revalidates_full_tool_context_before_next_credit(self):
        for index in range(9):
            with self.subTest(command=index):
                diagnostic,runner,files,_=self.harness();original=diagnostic.runner
                def invoke(argv,cwd,env):
                    result=original(argv,cwd,env)
                    if len(runner.calls)==index+1:files.data['/repo/node/lib/node_modules/npm/lib/cli.js']+=b'changed'
                    return result
                diagnostic.runner=invoke
                with self.assertRaises(f.Refusal):diagnostic.run()
                self.assertEqual(index+1,len(runner.calls))

    def test_tool_manifest_alias_cannot_repin_mutated_runtime_inputs(self):
        diagnostic,runner,files,_=self.harness();name='/repo/cache/lib/gradle-launcher.jar'
        files.data[name]+=b'changed';diagnostic.manifest['tools'][name]['bytes']=len(files.data[name]);diagnostic.manifest['tools'][name]['sha256']=f.sha(files.data[name])
        diagnostic.manifest['gradle']='/repo/unknown-launcher';diagnostic.manifest['nodeHome']='/repo/unknown-node'
        with self.assertRaises(f.Refusal):diagnostic.run()
        self.assertEqual([],runner.calls);self.assertEqual('/repo/cache/bin/gradle',diagnostic._tools.gradle)

    def test_each_gradle_invocation_gets_reviewed_seed_not_prior_cache_writes(self):
        diagnostic,runner,files,_=self.harness();original=diagnostic.runner;seen=[]
        seed='/repo/work/gradle-home/caches/modules/dependency.jar';original_bytes=files.data['/repo/cache/caches/modules/dependency.jar']
        def invoke(argv,cwd,env):
            if argv[-1]!='--check':
                seen.append(files.read(seed));files.write(seed,b'authored prior invocation cache write')
            return original(argv,cwd,env)
        diagnostic.runner=invoke;result=diagnostic.run()
        self.assertEqual('PASSED_STAGE_ONLY',result['status']);self.assertEqual([original_bytes]*6,seen)
        self.assertEqual(original_bytes,files.read('/repo/cache/caches/modules/dependency.jar'))
        self.assertEqual(6,len(files.tool_seeds));self.assertEqual(1,len(set(files.tool_seeds)))
        self.assertEqual(9,len(runner.calls));self.assertEqual(3,sum(argv[-1]=='--check' for argv,_ in runner.calls))

    def test_closed_toolchain_pin_types_roots_and_internal_link_targets_refuse(self):
        for defect in ('missing-parent','overlap','escape-link','link-chain','unknown-field','non-executable','bad-digest','too-many'):
            with self.subTest(defect=defect):
                diagnostic,_,files,_=self.harness();manifest=diagnostic.manifest
                if defect=='missing-parent':del manifest['tools']['/repo/node/lib/node_modules/npm/lib']
                elif defect=='overlap':manifest['javaHome']='/repo/cache/java'
                elif defect in ('escape-link','link-chain'):
                    target='../../../outside' if defect=='escape-link' else 'npm'
                    row=manifest['tools']['/repo/node/bin/npm'];row.update(target=target,bytes=len(target),sha256=f.sha(target.encode()))
                elif defect=='unknown-field':manifest['tools']['/repo/java/lib/modules']['optional']=True
                elif defect=='non-executable':manifest['tools']['/repo/java/bin/java']['mode']=0o644
                elif defect=='bad-digest':manifest['tools']['/repo/java/lib/modules']['sha256']='x'*64
                else:manifest['tools']={str(i):{} for i in range(f.TOOLS[0]+1)}
                with self.assertRaises(f.Refusal):f.Toolchain(manifest,files)

    def test_actual_tool_inventory_refuses_unknown_size_or_mode_before_payload(self):
        def metadata(mode,size=0):return SimpleNamespace(st_dev=1,st_ino=2,st_mode=mode,st_size=size,st_mtime_ns=3,st_ctime_ns=4)
        for defect in ('unknown','size','mode'):
            with self.subTest(defect=defect):
                files=f.Files.__new__(f.Files);files.repository=Path('/repo');files.ledger=f.Ledger(Clock())
                directory=metadata(f.stat.S_IFDIR|0o755);leaf=metadata(f.stat.S_IFREG|(0o600 if defect=='mode' else 0o644),2 if defect=='size' else 1)
                class Entries:
                    def __init__(self):self.done=False;self.closed=False
                    def __enter__(self):return self
                    def __exit__(self,*args):self.closed=True
                    def __next__(self):
                        if self.done:raise StopIteration
                        self.done=True;return SimpleNamespace(name='input')
                entries=Entries();pins={'/repo/tools':{'kind':'directory','mode':0o755}}
                if defect!='unknown':pins['/repo/tools/input']={'kind':'regular','mode':0o644,'bytes':1,'sha256':f.sha(b'x')}
                with patch.object(files,'path',side_effect=Path),patch.object(Path,'lstat',autospec=True,side_effect=lambda path:directory if str(path)=='/repo/tools' else leaf),patch.object(f.os,'scandir',return_value=entries),patch.object(files,'read') as read:
                    with self.assertRaises(f.Refusal):files.tool_inventory(('/repo/tools',),pins)
                read.assert_not_called();self.assertTrue(entries.closed)

    def test_actual_tool_inventory_internal_links_races_deadline_and_scan_bound(self):
        for defect in ('positive','changed-link','raced-link','late-link','entry-limit'):
            with self.subTest(defect=defect):
                clock=Clock();files=f.Files.__new__(f.Files);files.repository=Path('/repo');files.ledger=f.Ledger(clock)
                pins={'/repo/tools':{'kind':'directory','mode':0o755},'/repo/tools/target':{'kind':'regular','mode':0o644,'bytes':1,'sha256':f.sha(b'x')},'/repo/tools/alias':{'kind':'symlink','mode':0o777,'target':'target','bytes':6,'sha256':f.sha(b'target')}}
                seen={}
                def metadata(path):
                    name=str(path);pin=pins[name];seen[name]=seen.get(name,0)+1
                    mode={'directory':f.stat.S_IFDIR,'regular':f.stat.S_IFREG,'symlink':f.stat.S_IFLNK}[pin['kind']]|pin['mode']
                    inode=3 if defect=='raced-link' and name.endswith('/alias') and seen[name]>1 else 2
                    return SimpleNamespace(st_dev=1,st_ino=inode,st_mode=mode,st_size=pin.get('bytes',0),st_mtime_ns=3,st_ctime_ns=4)
                class Entries:
                    def __init__(self):self.names=iter(('target','alias'));self.closed=False
                    def __enter__(self):return self
                    def __exit__(self,*args):self.closed=True
                    def __next__(self):return SimpleNamespace(name=next(self.names))
                entries=Entries()
                def link(path):
                    if defect=='late-link':clock.now=406
                    return 'changed' if defect=='changed-link' else 'target'
                with ExitStack() as stack:
                    stack.enter_context(patch.object(files,'path',side_effect=Path))
                    stack.enter_context(patch.object(Path,'lstat',autospec=True,side_effect=metadata))
                    stack.enter_context(patch.object(f.os,'scandir',return_value=entries))
                    stack.enter_context(patch.object(f.os,'readlink',side_effect=link))
                    read=stack.enter_context(patch.object(files,'read',return_value=b'x'))
                    if defect=='entry-limit':stack.enter_context(patch.object(f,'TOOLS',(3,*f.TOOLS[1:])))
                    if defect=='positive':self.assertEqual(pins,files.tool_inventory(('/repo/tools',),pins))
                    else:
                        with self.assertRaises(f.Refusal):files.tool_inventory(('/repo/tools',),pins)
                self.assertTrue(entries.closed);self.assertEqual(1,read.call_count)
                self.assertEqual(420,files.ledger.end)

    def test_tool_context_final_credit_revalidates_even_after_all_commands(self):
        diagnostic,runner,files,_=self.harness();original=diagnostic.baseline;calls=[]
        def baseline():
            result=original();calls.append(1)
            if len(calls)==2:files.data['/repo/java/lib/modules']+=b'late mutation'
            return result
        diagnostic.baseline=baseline
        with self.assertRaises(f.Refusal):diagnostic.run()
        self.assertEqual(9,len(runner.calls));self.assertEqual(2,len(calls))

    def test_toolchain_whole_private_pins_survive_all_owned_source_edits(self):
        diagnostic,runner,files,_=self.harness();before=f.canonical(diagnostic.manifest['tools']);commitment=diagnostic._tools.commitment
        result=diagnostic.run()
        self.assertEqual('PASSED_STAGE_ONLY',result['status']);self.assertEqual(commitment,result['toolInputSha256'])
        self.assertEqual(before,f.canonical(diagnostic.manifest['tools']));self.assertEqual(commitment,diagnostic._tools.require(files))
        self.assertEqual(9,len(runner.calls));self.assertEqual(6,len(files.tool_seeds))

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
                    return SimpleNamespace(si_pid=123,si_code=f.os.CLD_EXITED)
                def signal_group(pid,number):
                    if number and state['reaped']:raise AssertionError('destructive post-reap signal')
                    signals.append(number)
                    if number==0 and defect!='leftover':raise ProcessLookupError('absent')
                runner=f.Runner(ledger,files,Path('/repo/evidence'))
                with patch.object(f.signal,'getsignal',return_value=f.signal.SIG_DFL),patch.object(f.subprocess,'Popen',return_value=Child()) as launch,patch.object(f.selectors,'DefaultSelector',return_value=Selector()),patch.object(f.os,'set_blocking'),patch.object(runner,'group_members',return_value=()),patch.object(f.os,'read',return_value=b''),patch.object(f.os,'waitid',side_effect=observe),patch.object(f.os,'killpg',side_effect=signal_group):
                    if defect=='success':
                        result=runner(['NOT_EXECUTED'],Path('/repo/work'),{})
                        self.assertEqual({'code':0,'output':b'','intervened':False,'reaped':True},result)
                    else:
                        with self.assertRaises(f.Refusal):runner(['NOT_EXECUTED'],Path('/repo/work'),{})
                self.assertEqual(1,launch.call_count);self.assertTrue(state['closed']);self.assertEqual(defect!='success',runner.uncertain)
                self.assertEqual([f.signal.SIGTERM,0] if defect=='timeout' else ([0] if defect in ('leftover','success') else []),signals)
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

    def _inspect_metadata_jar(self, entries, *, refuse=False, raw_names=None):
        data=io.BytesIO()
        with f.zipfile.ZipFile(data,'w',compression=f.zipfile.ZIP_STORED) as archive:
            for name,mode,payload in entries:
                info=f.zipfile.ZipInfo('decompengine/web/ui/'+name)
                info.create_system=3;info.external_attr=mode<<16
                archive.writestr(info,payload)
        raw=data.getvalue()
        if raw_names is not None:
            before,after=raw_names
            self.assertEqual(len(before),len(after));self.assertEqual(2,raw.count(before))
            raw=raw.replace(before,after)
            with f.zipfile.ZipFile(io.BytesIO(raw)) as check:
                info=check.infolist()[0]
                self.assertEqual(after.decode('ascii'),info.orig_filename)
                self.assertEqual(after.decode('ascii').split(chr(0),1)[0],info.filename)
        class Stream(io.BytesIO):
            def fileno(self):return 42
        stream=Stream(raw)
        metadata=SimpleNamespace(st_dev=1,st_ino=2,st_mode=f.stat.S_IFREG|0o644,st_size=len(raw),st_mtime_ns=3,st_ctime_ns=4)
        files=f.Files.__new__(f.Files);files.ledger=f.Ledger(Clock());files.repository=Path('/repo')
        opened=[];original_open=f.zipfile.ZipFile.open
        def open_member(archive,info,*args,**kwargs):
            opened.append(info.filename)
            if info.is_dir():raise AssertionError('directory payload must not be opened')
            return original_open(archive,info,*args,**kwargs)
        result=None
        with patch.object(files,'path',return_value=Path('/repo/app.jar')),patch.object(f.os,'open',return_value=42),patch.object(f.os,'fstat',return_value=metadata),patch.object(f.os,'fdopen',return_value=stream),patch.object(Path,'stat',return_value=metadata),patch.object(f.zipfile.ZipFile,'open',new=open_member),patch.object(f.os,'close') as close:
            if refuse:
                with self.assertRaises(f.Refusal):files.jar_ui('/repo/app.jar')
                self.assertEqual([],opened)
            else:result=files.jar_ui('/repo/app.jar')
        self.assertTrue(stream.closed);close.assert_not_called()
        return result,opened

    def test_jar_ui_directory_paths_reject_before_payload(self):
        for name in ('../../outside/','assets/../outside/','/absolute/','assets//child/','assets/./child/','assets\\child/'):
            with self.subTest(name=name):
                self._inspect_metadata_jar([(name,f.stat.S_IFDIR|0o755,b'')],refuse=True)

    def test_jar_ui_directory_suffix_does_not_override_type_or_payload(self):
        for name,mode,payload in (
                ('link/',f.stat.S_IFLNK|0o777,b'target'),
                ('pipe/',f.stat.S_IFIFO|0o600,b''),
                ('regular/',f.stat.S_IFREG|0o644,b''),
                ('not-directory',f.stat.S_IFDIR|0o755,b''),
                ('assets/',f.stat.S_IFDIR|0o755,b'hidden'),
                ('',f.stat.S_IFREG|0o644,b'')):
            with self.subTest(name=name,mode=mode):
                self._inspect_metadata_jar([(name,mode,payload)],refuse=True)

    def test_jar_ui_rejects_raw_names_changed_by_zip_parser(self):
        for name,mode,payload in (
                ('assets/X../outside/',f.stat.S_IFDIR|0o755,b''),
                ('index.htmlX../outside',f.stat.S_IFREG|0o644,b'authored UI')):
            with self.subTest(name=name):
                before=('decompengine/web/ui/'+name).encode('ascii');after=before.replace(b'X',bytes((0,)))
                self._inspect_metadata_jar([(name,mode,payload)],refuse=True,raw_names=(before,after))

    def test_jar_ui_genuine_directories_preserve_exact_regular_payloads(self):
        entries=[('',f.stat.S_IFDIR|0o755,b''),('assets/',f.stat.S_IFDIR|0o755,b''),
                 ('assets/nested/',0,b''),('index.html',f.stat.S_IFREG|0o644,b'authored UI'),
                 ('asset-manifest.json',0,b'authored manifest')]
        rows,opened=self._inspect_metadata_jar(entries)
        self.assertEqual({'index.html':{'bytes':11,'sha256':f.sha(b'authored UI')},
                          'asset-manifest.json':{'bytes':17,'sha256':f.sha(b'authored manifest')}},rows)
        self.assertEqual(['decompengine/web/ui/index.html','decompengine/web/ui/asset-manifest.json'],opened)

    def test_cleanup_observation_expiry_never_signals_or_masks_primary(self):
        for late_observation in (1,3):
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
                with patch.object(f.signal,'getsignal',return_value=f.signal.SIG_DFL),patch.object(f.subprocess,'Popen',return_value=Child()),patch.object(f.selectors,'DefaultSelector',return_value=Selector()),patch.object(f.os,'set_blocking'),patch.object(runner,'group_members',return_value=()),patch.object(f.os,'waitid',side_effect=observe),patch.object(f.os,'killpg',side_effect=signal_group):
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


    def test_source_only_invalidation_precedes_sentinel_and_failed_task(self):
        diagnostic,producer,files,_=self.harness()
        result=diagnostic.run()
        self.assertEqual([('cold',False),('unchanged',False),('warm',False),('fresh',False),('stale',True),('drift',False)],producer.observations)
        self.assertEqual('PASSED_STAGE_ONLY',result['status'])
        self.assertEqual(files.read('/repo/work/evidence/fresh.json'),files.read('/repo/work/evidence/stale.json'))
        self.assertEqual('UP-TO-DATE',result['phases']['stale']['taskOutcomes'][':generateFrontendAssetManifest'])
        diagnostic,producer,files,_=self.harness('missing-source-input')
        with self.assertRaisesRegex(f.Refusal,'task outcomes'):diagnostic.run()
        self.assertEqual([('cold',False),('unchanged',False),('warm',False),('fresh',False)],producer.observations)
        self.assertFalse(any('freshness-obsolete.svg' in name for name in files.data))
        self.assertEqual('NOT_RUN',diagnostic.phases['stale']['status'])
        self.assertEqual('NOT_RUN',diagnostic.phases['drift']['status'])

    def test_stale_control_is_independent_closed_outcome_and_byte_check(self):
        for defect in ('stale','stale-manifest'):
            with self.subTest(defect=defect):
                diagnostic,producer,_,_=self.harness(defect)
                with self.assertRaises((f.Refusal,ValueError)) as caught:diagnostic.run()
                if defect=='stale':
                    self.assertIsInstance(caught.exception,f.Refusal);self.assertIn('private manifest/dist mismatch',str(caught.exception))
                else:self.assertIsInstance(caught.exception,f.json.JSONDecodeError)
                result=diagnostic.failure(caught.exception)
                self.assertEqual('PASSED',result['phases']['fresh']['status'])
                self.assertEqual('FAILED_OR_UNKNOWN',result['phases']['stale']['status'])
                self.assertEqual('NOT_RUN',result['phases']['drift']['status'])
                self.assertEqual(('stale',True),producer.observations[-1])
        good=build_output('stale')
        self.assertEqual('UP-TO-DATE',f.require_outcomes(good,'stale')[':generateFrontendAssetManifest'])
        executed={**good,'output':good['output'].replace(b':generateFrontendAssetManifest UP-TO-DATE',b':generateFrontendAssetManifest')}
        self.assertEqual('EXECUTED',f.require_outcomes(executed,'stale')[':generateFrontendAssetManifest'])
        for task in ('frontendBuild','stageFrontend','verifyFrontendAssets'):
            with self.subTest(task=task),self.assertRaises(f.Refusal):
                f.require_outcomes({**good,'output':good['output'].replace((':'+task+'\n').encode(),(':'+task+' UP-TO-DATE\n').encode())},'stale')

    def test_npm_requires_independently_pinned_fixed_launcher_and_entry(self):
        for missing in ('/repo/node/bin/npm','/repo/node/lib/node_modules/npm/bin/npm-cli.js'):
            diagnostic,producer,files,_=self.harness();del diagnostic.manifest['tools'][missing]
            with patch.object(files,'npm_launcher',wraps=files.npm_launcher) as link,patch.object(files,'read',wraps=files.read) as read:
                with self.assertRaisesRegex(f.Refusal,'lacks reviewed pin'):f.npm_inputs(diagnostic.manifest,files)
                link.assert_not_called();read.assert_not_called()
            with self.assertRaises(f.Refusal):diagnostic.run()
            self.assertEqual([],producer.calls)
        diagnostic,_,files,_=self.harness();rows=f.npm_inputs(diagnostic.manifest,files)
        self.assertEqual({'fixed-symlink-text','regular-entry-bytes'},{row['kind'] for row in rows.values()})
        for name in ('/repo/node/bin/npm','/repo/node/lib/node_modules/npm/bin/npm-cli.js'):
            original=files.data[name];files.data[name]=original+b'changed'
            with self.subTest(name=name),self.assertRaises(f.Refusal):f.npm_inputs(diagnostic.manifest,files)
            files.data[name]=original

    def test_actual_npm_leaf_exception_is_fixed_and_generic_paths_still_reject_links(self):
        files=f.Files.__new__(f.Files);files.repository=Path('/repo');files.ledger=f.Ledger(Clock())
        expected=f.NPM_LINK.encode('ascii')
        def metadata(mode=f.stat.S_IFLNK|0o777,size=len(expected),inode=2):
            return SimpleNamespace(st_dev=1,st_ino=inode,st_mode=mode,st_size=size,st_mtime_ns=3,st_ctime_ns=4)
        for defect in ('positive','regular','large','wrong','escape','chain','raced','late'):
            with self.subTest(defect=defect):
                clock=Clock();files.ledger=f.Ledger(clock)
                first=metadata(mode=f.stat.S_IFREG if defect=='regular' else f.stat.S_IFLNK|0o777,size=513 if defect=='large' else len(expected))
                def readlink(path):
                    if defect=='late':clock.now=406
                    return {'wrong':'/outside/npm-cli.js','escape':'../../outside/npm-cli.js','chain':'../lib/node_modules/npm/bin/other-link.js'}.get(defect,f.NPM_LINK)
                with patch.object(files,'path',return_value=Path('/repo/node/bin')) as parent,patch.object(Path,'lstat',side_effect=[first,metadata(inode=3 if defect=='raced' else 2)]),patch.object(f.os,'readlink',side_effect=readlink) as link:
                    if defect=='positive':self.assertEqual(expected,files.npm_launcher('/repo/node/bin/npm'))
                    else:
                        with self.assertRaises(f.Refusal):files.npm_launcher('/repo/node/bin/npm')
                    if defect in ('regular','large'):link.assert_not_called()
                    parent.assert_called_once_with(Path('/repo/node/bin'))
        with patch.object(Path,'is_symlink',return_value=True),patch.object(f.os,'open') as opened:
            with self.assertRaisesRegex(f.Refusal,'symbolic path'):files.read('/repo/node/bin/npm')
            opened.assert_not_called()

    def test_npm_mutation_before_after_command_and_before_final_credit_refuses(self):
        for when in ('before','after','final'):
            with self.subTest(when=when):
                diagnostic,producer,files,_=self.harness();entry='/repo/node/lib/node_modules/npm/bin/npm-cli.js'
                f.npm_inputs(diagnostic.manifest,files)  # independently admitted before injected mutation
                if when=='before':files.data[entry]+=b'changed'
                def invoke(argv,cwd,env):
                    result=producer(argv,cwd,env)
                    if when=='after':files.data[entry]+=b'changed'
                    return result
                diagnostic.runner=invoke
                if when=='final':
                    original_baseline=diagnostic.baseline;baseline_calls=[]
                    def final_baseline():
                        value=original_baseline();baseline_calls.append(1)
                        if len(baseline_calls)==2:files.data[entry]+=b'changed'
                        return value
                    diagnostic.baseline=final_baseline
                with self.assertRaisesRegex(f.Refusal,'npm reviewed input'):diagnostic.run()
                self.assertEqual(0 if when=='before' else (1 if when=='after' else 9),len(producer.calls))
                if when=='final':self.assertEqual('PASSED',diagnostic.phases['drift']['status'])

    def runner_vector(self, defect):
        clock=Clock();ledger=f.Ledger(clock);files=MemoryFiles(ledger);events=[]
        state={'waited':False,'registered':True,'closed':False,'term':False,'kill':False}
        class Stream:
            def fileno(self):return 42
            def close(self):state['closed']=True
        class Child:
            pid=123;stdout=Stream()
            def wait(self,timeout):
                state['waited']=True;events.append(('wait',timeout))
                if defect=='ambiguous-wait':raise OSError('authored ambiguous wait')
                return 0
        class Selector:
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def register(self,*args):pass
            def get_map(self):return {1:True} if state['registered'] else {}
            def select(self,timeout):return [(SimpleNamespace(fileobj=Child.stdout),None)]
            def unregister(self,*args):state['registered']=False
        def observe(kind,pid,flags):
            self.assertEqual((f.os.P_PID,123,f.os.WEXITED|f.os.WNOHANG|f.os.WNOWAIT),(kind,pid,flags))
            self.assertFalse(state['waited']);events.append(('observe',clock.now))
            if defect=='unknown-wait':raise ChildProcessError('authored ownership ambiguity')
            return SimpleNamespace(si_pid=124 if defect=='wrong-child' else 123,si_code=f.os.CLD_EXITED)
        def members(pid,cleanup=False):
            self.assertEqual(123,pid);self.assertFalse(state['waited']);events.append(('members',cleanup))
            if defect=='late-observation':clock.now=421
            if defect=='unknown-scan':raise PermissionError('authored metadata refusal')
            if defect=='survivor-kill' and not state['kill']:return (124,)
            if defect=='survivor-term' and not state['term']:return (124,)
            return ()
        def send(pid,number):
            self.assertEqual(123,pid);events.append(('signal',number))
            if number:
                self.assertFalse(state['waited'])
                if number==f.signal.SIGTERM:state['term']=True
                elif number==f.signal.SIGKILL:state['kill']=True
                else:raise AssertionError('unexpected signal')
            elif defect!='post-reap-leftover':raise ProcessLookupError('authored group absent')
        runner=f.Runner(ledger,files,Path('/repo/evidence'));result=error=None
        with ExitStack() as stack:
            for obj,name,kwargs in ((f.signal,'getsignal',{'return_value':f.signal.SIG_DFL}),(f.subprocess,'Popen',{'return_value':Child()}),(f.selectors,'DefaultSelector',{'return_value':Selector()}),(f.os,'set_blocking',{}),(f.os,'read',{'return_value':b''}),(f.os,'waitid',{'side_effect':observe}),(f.os,'killpg',{'side_effect':send}),(runner,'group_members',{'side_effect':members}),(f.time,'sleep',{'side_effect':lambda amount:setattr(clock,'now',clock.now+amount)})):
                stack.enter_context(patch.object(obj,name,**kwargs))
            try:result=runner(['NOT_EXECUTED'],Path('/repo/work'),{})
            except (f.Refusal,OSError) as caught:error=caught
        return result,error,state,events,files,runner

    def test_held_exited_leader_survivors_are_signaled_before_reap_and_never_success(self):
        for defect in ('survivor-term','survivor-kill','unknown-scan'):
            with self.subTest(defect=defect):
                result,error,state,events,files,runner=self.runner_vector(defect)
                self.assertIsNone(result);self.assertIsInstance(error,(f.Refusal,OSError));self.assertTrue(runner.uncertain)
                self.assertTrue(state['waited']);self.assertTrue(state['closed'])
                nonzero=[event[1] for event in events if event[0]=='signal' and event[1]]
                self.assertEqual([f.signal.SIGTERM]+([] if defect=='survivor-term' else [f.signal.SIGKILL]),nonzero)
                waiting=next(i for i,e in enumerate(events) if e[0]=='wait')
                self.assertTrue(all(i<waiting for i,e in enumerate(events) if e[0]=='signal' and e[1]))
                facts=f.closed_json(files.data['/repo/evidence/command-01.json'])
                self.assertTrue(facts['rootReaped']);self.assertTrue(facts['operationalGroupAbsent'])
                self.assertTrue(facts['intervened']);self.assertFalse(facts['descendantAbsenceProven'])

    def test_wait_ambiguity_late_observation_and_post_reap_group_never_grant_signal_authority(self):
        for defect in ('ambiguous-wait','unknown-wait','wrong-child','late-observation','post-reap-leftover'):
            with self.subTest(defect=defect):
                result,error,state,events,_,runner=self.runner_vector(defect)
                self.assertIsNone(result);self.assertIsNotNone(error);self.assertTrue(runner.uncertain);self.assertTrue(state['closed'])
                self.assertFalse(any(kind=='signal' and value for kind,value in events))
                if defect in ('ambiguous-wait','post-reap-leftover'):self.assertTrue(state['waited'])
        result,error,state,events,_,runner=self.runner_vector('positive')
        self.assertIsNone(error);self.assertEqual({'code':0,'output':b'','intervened':False,'reaped':True},result)
        self.assertFalse(runner.uncertain);self.assertTrue(state['closed'])
        self.assertEqual([0],[value for kind,value in events if kind=='signal'])

    def group_vector(self, names, defect=None, *, observation_error=None, observation_pid=800):
        clock=Clock();ledger=f.Ledger(clock);files=MemoryFiles(ledger)
        runner=f.Runner(ledger,files,Path('/repo/evidence'));opened=[];closed=[];reads=[];buffers={}
        class Entries:
            advances=0;closed=False
            def __init__(self):self.items=iter(names)
            def __enter__(self):return self
            def __exit__(self,*args):self.closed=True
            def __next__(self):self.advances+=1;return SimpleNamespace(name=next(self.items))
        entries=Entries()
        def metadata(fd):
            return SimpleNamespace(st_dev=1,st_ino=fd,st_mode=f.stat.S_IFIFO if defect=='special' else f.stat.S_IFREG,st_size=4097 if defect=='metadata-large' else 0)
        def opened_stat(path,flags):
            self.assertTrue(flags&f.os.O_NOFOLLOW);self.assertTrue(flags&f.os.O_NONBLOCK)
            if defect=='permission':raise PermissionError('authored denial')
            pid=int(path.split('/')[2])
            if defect=='open-error' and pid==observation_pid:raise observation_error
            fd=1000+pid;opened.append(fd)
            raw=(str(pid)+' (authored ) comm) Z 1 '+str(123 if pid in (123,124,125) else pid)+' '+str(123 if pid in (123,124,125) else pid)+' ').encode()+b'0 '*15+b'99\n'
            if defect=='session':raw=raw.replace(b' Z 1 123 123 ',b' Z 1 123 999 ')
            buffers[fd]=b'malformed' if defect=='malformed' else (b'x'*4096 if defect=='read-large' else raw)
            return fd
        def read(fd,size):
            reads.append((fd,size))
            if defect=='late':clock.now=406
            data=buffers[fd][:size];buffers[fd]=buffers[fd][size:];return data
        def named(path,**kwargs):
            if defect=='stat-error' and int(path.split('/')[2])==observation_pid:raise observation_error
            if defect=='disappeared':raise FileNotFoundError('authored disappearing row')
            fd=1000+int(path.split('/')[2]);row=metadata(fd)
            if defect=='identity':row.st_ino+=1
            return row
        result=error=None
        with patch.object(f.os,'scandir',return_value=entries) as scan,patch.object(f.os,'open',side_effect=opened_stat),patch.object(f.os,'fstat',side_effect=metadata),patch.object(f.os,'stat',side_effect=named),patch.object(f.os,'read',side_effect=read),patch.object(f.os,'close',side_effect=closed.append):
            try:result=runner.group_members(123)
            except (f.Refusal,OSError) as caught:error=caught
            scan.assert_called_once_with('/proc')
        return result,error,entries,opened,closed,reads

    def test_bounded_group_observer_parses_parenthesized_comm_and_closes_resources(self):
        result,error,entries,opened,closed,reads=self.group_vector(['self','123','124','800'])
        self.assertIsNone(error);self.assertEqual((124,),result)
        self.assertTrue(entries.closed);self.assertEqual(opened,closed);self.assertEqual(3,len(opened))
        self.assertTrue(all(0<size<=4096 for _,size in reads))
        result,error,_,opened,closed,_=self.group_vector(['123'])
        self.assertEqual((),result);self.assertIsNone(error);self.assertEqual(opened,closed)

    def test_group_observer_all_entry_and_stat_caps_and_unknowns_refuse_not_absence(self):
        result,error,entries,opened,closed,reads=self.group_vector(['nonnumeric-'+str(i) for i in range(257)])
        self.assertIsNone(result);self.assertIsInstance(error,f.Refusal)
        self.assertEqual(256,entries.advances);self.assertTrue(entries.closed)
        self.assertEqual([],opened);self.assertEqual([],reads)
        result,error,entries,opened,closed,_=self.group_vector(['123']+['nonpid-'+str(i) for i in range(254)])
        self.assertEqual((),result);self.assertIsNone(error);self.assertEqual(256,entries.advances);self.assertTrue(entries.closed);self.assertEqual(opened,closed)
        result,error,entries,opened,closed,_=self.group_vector(['self','800'])
        self.assertIsNone(result);self.assertIsInstance(error,f.Refusal);self.assertTrue(entries.closed);self.assertEqual(opened,closed)
        for defect in ('permission','special','metadata-large','read-large','late','malformed','session','disappeared','identity'):
            with self.subTest(defect=defect):
                result,error,entries,opened,closed,reads=self.group_vector(['123'],defect)
                self.assertIsNone(result);self.assertIsNotNone(error);self.assertTrue(entries.closed);self.assertEqual(opened,closed)
                if defect in ('special','metadata-large'):self.assertEqual([],reads)
                if defect=='read-large':self.assertEqual(4096,sum(size for _,size in reads))
        with patch.object(f,'GROUP_SCAN_BYTES',1):
            result,error,entries,opened,closed,_=self.group_vector(['123'])
            self.assertIsNone(result);self.assertIsInstance(error,f.Refusal);self.assertTrue(entries.closed);self.assertEqual(opened,closed)


    def test_group_observer_open_enoent_skips_vanished_row_and_keeps_survivors(self):
        names=['123','124','125','800']
        for vanished,expected in ((124,(125,)),(800,(124,125))):
            with self.subTest(vanished=vanished):
                missing=FileNotFoundError(f.errno.ENOENT,'authored vanished PID')
                result,error,entries,opened,closed,reads=self.group_vector(
                    names,'open-error',observation_error=missing,observation_pid=vanished)
                self.assertIsNone(error);self.assertEqual(expected,result)
                self.assertTrue(entries.closed);self.assertEqual(5,entries.advances)
                self.assertEqual([1000+int(name) for name in names if int(name)!=vanished],opened)
                self.assertEqual(opened,closed);self.assertNotIn(1000+vanished,[fd for fd,_ in reads])

    def test_group_observer_stat_enoent_closes_owned_fd_and_keeps_survivors(self):
        names=['123','124','125','800']
        for vanished,expected in ((124,(125,)),(800,(124,125))):
            with self.subTest(vanished=vanished):
                missing=FileNotFoundError(f.errno.ENOENT,'authored vanished PID')
                result,error,entries,opened,closed,reads=self.group_vector(
                    names,'stat-error',observation_error=missing,observation_pid=vanished)
                self.assertIsNone(error);self.assertEqual(expected,result)
                self.assertTrue(entries.closed);self.assertEqual(5,entries.advances)
                self.assertEqual([1000+int(name) for name in names],opened)
                self.assertEqual(opened,closed);self.assertIn(1000+vanished,[fd for fd,_ in reads])
                self.assertEqual(1,closed.count(1000+vanished))

    def test_group_observer_vanished_leader_remains_unknown_at_both_points(self):
        for defect in ('open-error','stat-error'):
            with self.subTest(defect=defect):
                missing=FileNotFoundError(f.errno.ENOENT,'authored vanished leader')
                result,error,entries,opened,closed,reads=self.group_vector(
                    ['123','124','125'],defect,observation_error=missing,observation_pid=123)
                self.assertIsNone(result);self.assertIsInstance(error,f.Refusal)
                self.assertRegex(str(error),'held leader absent from group observation')
                self.assertTrue(entries.closed);self.assertEqual(4,entries.advances)
                self.assertEqual(opened,closed)
                self.assertTrue({1124,1125}.issubset({fd for fd,_ in reads}))

    def test_group_observer_non_enoent_open_and_stat_errors_propagate(self):
        for defect in ('open-error','stat-error'):
            for code in (f.errno.EACCES,f.errno.ELOOP,f.errno.EIO,f.errno.ESRCH,f.errno.ENOTDIR):
                with self.subTest(defect=defect,code=code):
                    denied=OSError(code,'authored non-ENOENT refusal')
                    result,error,entries,opened,closed,_=self.group_vector(
                        ['123','124','125','800'],defect,observation_error=denied,observation_pid=124)
                    self.assertIsNone(result);self.assertIs(error,denied);self.assertEqual(code,error.errno)
                    self.assertTrue(entries.closed);self.assertEqual(opened,closed)
                    self.assertNotIn(1125,opened)

if __name__=='__main__':
    unittest.main()
