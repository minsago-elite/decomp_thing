"""Closed exchanges and migration refusal checks, entirely synthetic."""
from copy import deepcopy
import json
from pathlib import Path
import sys
import unittest
import tempfile
import shutil
import importlib.util
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import evaluate_candidate_v3 as e
import freeze_v3 as f
from test_process_results import receipt, observations
from static_test_support import historical_namespace, static_temp


def report_fixture():
    rows=[e.scenario_entry(o,receipt(),True,'a'*64) for o in observations()]
    summary=e.summarize(rows,True);status=summary.pop('behaviorStatus')
    phases={key:{'status':'passed','reason':'synthetic','evidenceSha256':None} for key in e.PHASES}
    phases['load']={'status':'unverified','value':None};phases['behavior']['status']=status
    return {'schemaVersion':3,'schema':'callable-library-candidate-evaluation-v3','candidateSha256':'a'*64,'profileSha256':e.digest(e.BASE/'contracts/candidate-build-profile.json'),'runtimeInputs':{'caller':{'path':'/synthetic/caller','sha256':'a'*64},'library':{'path':'/synthetic/libcandidate.so','sha256':'c'*64}},'phases':phases,'admitted':True,**summary,'scenarios':rows,'evidenceFiles':{'synthetic.json':'a'*64},'formalStructuralScore':None,'abiAccuracy':'unassessed','productionFactoryQualified':False,'productionProviderQualified':False,'productionFilesystemQualified':False}


def _freeze_dependency_fixture(root):
    """Owned synthetic root with exact reviewed public sources, never native outputs."""
    import hashlib
    original=Path(e.__file__).parent;paths={}
    names=[name+'.py' for name,_,_ in f._FREEZE_DEPENDENCY_SOURCES]
    names+=['worker_exec_proof.py']
    names+=['contracts/'+name for name in (
        'candidate-build-profile.json','execution-bindings-schema.json','helper-schema.json',
        'matrix-schema.json','preparation-schema.json','reference-observations-schema.json',
        'report-schema.json','toolchain-pin-schema.json','visible-manifest-schema.json')]
    for name in names:
        raw=(original/name).read_bytes();target=root/name;target.parent.mkdir(parents=True,exist_ok=True)
        target.write_bytes(raw);paths[str(target)]=hashlib.sha256(raw).hexdigest()
    return paths


def _freeze_process_root(value, root):
    """Rekey authored profile/parser coordinates, preserving the actual raw worker proof."""
    import hashlib
    result=deepcopy(value);pins=result['launchInputPins']
    for relative in ('contracts/candidate-build-profile.json','worker_exec_proof.py'):
        pins[str(root/relative)]=pins.pop(str(e.BASE/relative))
    result['workerProofBindings']['launchPinsSha256']=hashlib.sha256(
        json.dumps(pins,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()
    return result


def _freeze_report_root(value, root):
    result=deepcopy(value)
    for row in result['scenarios']:
        if row['process'] is not None:row['process']=_freeze_process_root(row['process'],root)
    return result


class SchemaMigration(unittest.TestCase):
    def test_preservation_supported_anchors_ignore_cwd_and_share_relative_absolute_lookup(self):
        import hashlib
        trusted=static_temp('static-process-correction-001')
        with tempfile.TemporaryDirectory(dir=trusted) as temporary:
            repository=Path(temporary)/'relocated checkout';repository.mkdir()
            retained=repository/'retained';retained.mkdir();file=retained/'historical.c';file.write_bytes(b'authored retained bytes')
            sha=hashlib.sha256(file.read_bytes()).hexdigest()
            for suffix in (('oracle','acp','callable-evaluator-v3','source'),
                           ('build','acp-decomp-effectiveness','callable-library-v3')):
                base=repository.joinpath(*suffix)
                for key in ('retained/historical.c',str(file)):
                    manifest={'schemaVersion':3,'files':{key:sha}}
                    with self.subTest(suffix=suffix,key=key),patch.object(f,'BASE',base), \
                            patch.object(Path,'cwd',side_effect=AssertionError('preservation must not use ambient cwd')):
                        self.assertEqual(repository,f._preservation_repository())
                        self.assertIsNone(f.verify_preservation(manifest))
            self.assertEqual(b'authored retained bytes',file.read_bytes())

    def test_preservation_refuses_alias_duplicates_escape_unknown_layout_and_hash_drift(self):
        import hashlib
        trusted=static_temp('static-process-correction-001')
        with tempfile.TemporaryDirectory(dir=trusted) as temporary:
            repository=Path(temporary)/'checkout';repository.mkdir();file=repository/'historical';file.write_bytes(b'authored')
            sha=hashlib.sha256(b'authored').hexdigest();base=repository/'oracle/acp/callable-evaluator-v3/source'
            for files,reason in (({'historical':sha,str(file):sha},'duplicate admitted file'),
                                 ({'../outside':sha},'parent traversal'),
                                 ({str(repository.parent/'outside'):sha},'outside admitted input scope'),
                                 ({'historical':'0'*64},'historical source changed')):
                with self.subTest(files=files),patch.object(f,'BASE',base):
                    with self.assertRaisesRegex(ValueError,reason):f.verify_preservation({'schemaVersion':3,'files':files})
            for unsupported in (repository/'source',base/'nested',Path('oracle/acp/callable-evaluator-v3/source')):
                with self.subTest(base=unsupported),patch.object(f,'BASE',unsupported), \
                        patch.object(f,'admit_files',side_effect=AssertionError('unknown layout before admission')):
                    with self.assertRaises(ValueError):f.verify_preservation({'schemaVersion':3,'files':{'historical':sha}})
            # An old absolute manifest is never rebased into this checkout by basename.
            with patch.object(f,'BASE',base),patch.object(f,'_open_regular',side_effect=AssertionError('old external root must refuse before open')):
                with self.assertRaisesRegex(ValueError,'outside admitted input scope'):
                    f.verify_preservation({'schemaVersion':3,'files':{'/unrelated-original-checkout/historical':sha}})

    def test_preservation_retains_nofollow_type_and_charged_population_controls(self):
        import hashlib
        trusted=static_temp('static-process-correction-001')
        with tempfile.TemporaryDirectory(dir=trusted) as temporary:
            repository=Path(temporary);retained=repository/'retained';retained.mkdir()
            file=retained/'original';file.write_bytes(b'authored');sha=hashlib.sha256(b'authored').hexdigest()
            (retained/'leaf-link').symlink_to(file);(repository/'parent-link').symlink_to(retained,target_is_directory=True)
            base=repository/'build/acp-decomp-effectiveness/callable-library-v3'
            for key in ('retained/leaf-link','parent-link/original'):
                with self.subTest(key=key),patch.object(f,'BASE',base):
                    with self.assertRaises(OSError):f.verify_preservation({'schemaVersion':3,'files':{key:sha}})
            with patch.object(f,'BASE',base):
                with self.assertRaisesRegex(ValueError,'regular file required'):
                    f.verify_preservation({'schemaVersion':3,'files':{'retained':sha}})
            actual=f.admit_files
            def charged(paths,budget=None,root=None):
                # Existing budget only: repository +retained +one file exactly3 nodes.
                return actual(paths,f.TreeBudget(nodes=3,directories=2,files=1,bytes=8,depth=2),root=root)
            with patch.object(f,'BASE',base),patch.object(f,'admit_files',side_effect=charged):
                self.assertIsNone(f.verify_preservation({'schemaVersion':3,'files':{'retained/original':sha}}))
                second=retained/'second';second.write_bytes(b'x')
                with self.assertRaisesRegex(ValueError,'node/depth budget'):
                    f.verify_preservation({'schemaVersion':3,'files':{'retained/original':sha,'retained/second':sha}})

    def test_admitted_json_uses_real_reader_strict_decoder_schema_and_ordinary_api(self):
        trusted=static_temp('static-process-correction-001')
        with tempfile.TemporaryDirectory(dir=trusted) as temporary:
            root=Path(temporary);path=root/'document.json'
            binding={'schemaVersion':3,'sourceCheckpointSha256':'a'*64,'initialSha256':{'synthetic':'b'*64},
                     'helperCopySha256':'c'*64,'helperSchemaSha256':'d'*64,'helperSchemaVersion':3}
            path.write_text(json.dumps(binding));record=f.admit_files([path],root=root)['files'][str(path)]
            real_read_regular=f.read_regular;schema_path=e.BASE/'contracts/execution-bindings-schema.json'
            def schema_only(candidate,maximum):
                self.assertEqual(schema_path,candidate,'admitted record must not independently re-admit pathname')
                self.assertEqual(1048576,maximum)
                return real_read_regular(candidate,maximum)
            with patch.object(f,'read_regular',side_effect=schema_only) as schema_read:
                self.assertEqual(binding,f._read_admitted_json(record,'execution-bindings'))
            schema_read.assert_called_once_with(schema_path,1048576)
            self.assertEqual(binding,f.read_json(path,'execution-bindings'))
            for raw in (b'{"schemaVersion":3,"schemaVersion":2}',b'{"x":NaN}',b'{',b'\xff'):
                path.write_bytes(raw);record=f.admit_files([path],root=root)['files'][str(path)]
                with self.subTest(raw=raw),self.assertRaises((ValueError,UnicodeError)):
                    f._read_admitted_json(record)
            path.write_bytes(b'{}');record=f.admit_files([path],root=root)['files'][str(path)]
            # Actual pinned schema validation, not a claimed qualified pin or schema stub.
            with self.assertRaises(Exception):f._read_admitted_json(record,'toolchain-pin')
            with self.assertRaises(Exception):f._read_admitted_json(record,'execution-bindings')

    def test_admitted_json_retains_original_bytes_or_refuses_changed_original_record(self):
        trusted=static_temp('static-process-correction-001')
        with tempfile.TemporaryDirectory(dir=trusted) as temporary:
            root=Path(temporary);path=root/'pin.json';raw=b'{"status":"static-recording-unqualified"}'
            path.write_bytes(raw);record=f.admit_files([path],root=root)['files'][str(path)]
            real_read=f.read_admitted;calls=[]
            def captured(item,maximum):
                calls.append((item,maximum));result=real_read(item,maximum)
                path.write_bytes(b'{"status":"invented-qualified","other":true}')
                return result
            with patch.object(f,'read_admitted',side_effect=captured), \
                    patch.object(f,'read_regular',side_effect=AssertionError('no independent pathname re-admission')):
                value=f._read_admitted_json(record,maximum=8388608)
            self.assertEqual({'status':'static-recording-unqualified'},value)
            self.assertEqual([(record,8388608)],calls)
            with self.assertRaisesRegex(ValueError,'static-only toolchain pin'):f.require_qualified_pin(value)
            with self.assertRaisesRegex(ValueError,'admitted file changed'):f._read_admitted_json(record)
            # Restore the original bytes, then re-admit deliberately as a NEW test input.
            path.write_bytes(raw);record=f.admit_files([path],root=root)['files'][str(path)]
            path.unlink();path.symlink_to(root/'absent')
            with self.assertRaises(OSError):f._read_admitted_json(record)

    def test_admitted_json_preservation_exact_cap_and_all_role_overcaps_precede_read(self):
        trusted=static_temp('static-process-correction-001')
        with tempfile.TemporaryDirectory(dir=trusted) as temporary:
            root=Path(temporary);path=root/'preservation.json'
            path.write_bytes(b' '*(1048576-2)+b'{}')
            record=f.admit_files([path],root=root)['files'][str(path)]
            self.assertEqual({},f._read_admitted_json(record,maximum=1048576))
            path.write_bytes(b' '*(1048576-1)+b'{}')
            record=f.admit_files([path],root=root)['files'][str(path)]
            with patch.object(f,'_open_regular',side_effect=AssertionError('cap+1 must refuse before payload open')):
                with self.assertRaisesRegex(ValueError,'admitted read bound'):f._read_admitted_json(record,maximum=1048576)
                for maximum in (1048576,8388608):
                    with self.subTest(maximum=maximum),self.assertRaisesRegex(ValueError,'admitted read bound'):
                        f._read_admitted_json({'size':maximum+1},maximum=maximum)

    def _admitted_checkpoint_fixture(self, root):
        import hashlib
        preflight=root/'preflight';preflight.mkdir();output=root/'not-created'
        files={'synthetic':'a'*64,**_freeze_dependency_fixture(root)};checkpoint=root/'source.json';checkpoint.write_text(json.dumps({'schemaVersion':3,'files':files}))
        matrix={'schemaVersion':3,'status':'preflight-only-independent-review-required','freezeCreated':False,
                'allControlsPassed':True,'executionDependenciesUnchanged':True,
                'rows':[{'name':'synthetic','expected':'matched','expectedStage':'behavior','passed':True,'receipt':'synthetic',
                         'receiptSha256':'a'*64,'runtimeRequestCount':24,'completedScenarioProcessCount':24,'unknownScenarioProcessCount':0}]}
        bindings={'schemaVersion':3,'sourceCheckpointSha256':hashlib.sha256(checkpoint.read_bytes()).hexdigest(),
                  'initialSha256':files,'helperCopySha256':'a'*64,'helperSchemaSha256':'a'*64,'helperSchemaVersion':3}
        (preflight/'matrix.json').write_text(json.dumps(matrix));(preflight/'execution-bindings.json').write_text(json.dumps(bindings))
        for name in ('toolchain.json','review.md','acceptance.md','qualification.md'):(root/name).write_text('{}')
        return (preflight,root/'review.md',output,root/'toolchain.json',root/'acceptance.md',checkpoint,root/'qualification.md')

    def test_freeze_checkpoint_composition_uses_original_extra_record_and_never_reopens_json(self):
        trusted=static_temp('static-process-correction-001')
        with tempfile.TemporaryDirectory(dir=trusted) as temporary:
            outer=Path(temporary)
            for mutation in (None,'after-capture','after-admission'):
                root=outer/(mutation or 'unchanged');root.mkdir();args=self._admitted_checkpoint_fixture(root);checkpoint=args[5]
                real_admit=f.admit_files;real_read=f.read_admitted;reads=[];boundary=ValueError('authored checkpoint boundary reached; never qualified')
                def admit(paths,*a,**kw):
                    records=real_admit(paths,*a,**kw)
                    if mutation=='after-admission' and str(checkpoint) in records['files']:
                        checkpoint.write_bytes(b'{"schemaVersion":2,"files":{}}')
                    return records
                def read(record,maximum):
                    raw=real_read(record,maximum)
                    if record['path']==checkpoint:
                        reads.append((record['sha256'],maximum))
                        if mutation=='after-capture':checkpoint.write_bytes(b'{"schemaVersion":2,"files":{}}')
                    return raw
                with self.subTest(mutation=mutation),patch.object(f,'BASE',root), \
                        patch.object(f,'admit_files',side_effect=admit),patch.object(f,'read_admitted',side_effect=read), \
                        patch.object(f,'read_json',side_effect=AssertionError('freeze must decode original admitted record')), \
                        patch.object(f,'execution_source_paths',side_effect=boundary) as population:
                    with self.assertRaises(ValueError) as caught:f.freeze(*args)
                if mutation=='after-admission':
                    self.assertIn('admitted file changed',str(caught.exception));population.assert_not_called();self.assertEqual([],reads)
                else:
                    self.assertIs(caught.exception,boundary);population.assert_called_once_with()
                    self.assertEqual(1,len(reads));self.assertEqual(8388608,reads[0][1])
                self.assertFalse(args[2].exists())

    def test_closed_report_validates(self):e.validate_exchange('report',report_fixture())
    def test_v2_and_legacy_counter_fields_refuse(self):
        for key,value in (('schemaVersion',2),('candidateCalled',True),('recordedCallCount',32),('behaviorRate',1)):
            report=report_fixture();report[key]=value
            with self.assertRaises(Exception):e.validate_exchange('report',report)
    def test_nested_unknown_fields_and_api_claims_refuse(self):
        for part,key,value in (('scenario','candidateCalled',True),('process','apiEntryCount',1),('phase','recordedCalls',1)):
            report=report_fixture()
            target=report['scenarios'][0] if part=='scenario' else report['scenarios'][0]['process'] if part=='process' else report['phases']['load']
            target[key]=value
            with self.assertRaises(Exception):e.validate_exchange('report',report)
        report=report_fixture();report['apiEntryCount']=1
        with self.assertRaises(Exception):e.validate_exchange('report',report)
    def test_all_changed_exchange_schemas_closed_version3(self):
        for name in ('report','reference-observations','matrix','preparation','execution-bindings','visible-manifest'):
            schema=json.loads((e.BASE/'contracts'/(name+'-schema.json')).read_bytes())
            self.assertFalse(schema['additionalProperties']);self.assertEqual(schema['properties']['schemaVersion']['const'],3)
    def test_reference_incomplete_and_old_shape_refuse(self):
        value={'schemaVersion':3,'sourceSha256':'a'*64,'callerSha256':'a'*64,'callerPath':'/synthetic/caller','libraryPath':'/synthetic/libcandidate.so','librarySha256':'c'*64,'profileSha256':e.digest(e.BASE/'contracts/candidate-build-profile.json'),'observations':[{**o,'evidenceSha256':'c'*64} for o in observations()]}
        e.validate_exchange('reference-observations',value)
        value['observations'][0]['process']['completed']=False
        with self.assertRaises(Exception):e.validate_exchange('reference-observations',value)
        value['observations'][0]['process']['completed']=True
        value['observations'][0]['exitCode']=0
        with self.assertRaises(Exception):e.validate_exchange('reference-observations',value)
    def test_completed_rows_require_protected_proof_and_bound_inputs(self):
        for field in ('workerExecVerified','workerTerminationVerified','workerProof','workerProofRawHex','workerProofBindings','launchInputPins','launcherExitCode','rootReaped','scopeAbsenceVerified'):
            report=report_fixture();del report['scenarios'][0]['process'][field]
            with self.assertRaises(Exception,msg=field):e.validate_exchange('report',report)
        for change in ('terminal','raw','caller','library','profile','launcher'):
            report=report_fixture();process=report['scenarios'][0]['process']
            if change=='terminal':process['termination']['value']=7
            elif change=='raw':process['workerProofRawHex']=''
            elif change=='caller':report['runtimeInputs']['caller']['sha256']='d'*64
            elif change=='library':report['runtimeInputs']['library']['sha256']='d'*64
            elif change=='profile':report['profileSha256']='d'*64
            else:process['launcherExitCode']=1
            with self.assertRaises(Exception,msg=change):e.validate_exchange('report',report)

    def test_freeze_public_source_cannot_seal(self):
        with self.assertRaisesRegex(ValueError,'trusted v3'):
            f.freeze(*([Path('/synthetic')]*7))
    def test_freeze_uses_full_toolchain_revalidation(self):
        class Fake:
            called=False
            def revalidate_pin(self,pin,root):self.called=True;raise ValueError('selection drift')
        fake=Fake()
        with patch.object(f.importlib.util,'spec_from_file_location'),patch.object(f.importlib.util,'module_from_spec',return_value=fake):
            with self.assertRaisesRegex(ValueError,'selection drift'):f.revalidate_toolchain({},Path('/synthetic'))
        self.assertTrue(fake.called)
    def test_all_exchange_instances_validate_and_v2_refuses(self):
        sha='a'*64
        values={
            'execution-bindings':{'schemaVersion':3,'sourceCheckpointSha256':sha,'initialSha256':{'synthetic':sha},'helperCopySha256':sha,'helperSchemaSha256':sha,'helperSchemaVersion':3},
            'matrix':{'schemaVersion':3,'status':'preflight-only-independent-review-required','freezeCreated':False,'allControlsPassed':False,'executionDependenciesUnchanged':True,'rows':[{'name':'synthetic','expected':'matched','expectedStage':'behavior','passed':False,'receipt':'synthetic','receiptSha256':sha,'runtimeRequestCount':24,'completedScenarioProcessCount':0,'unknownScenarioProcessCount':24}]},
            'visible-manifest':{'schemaVersion':3,'profile':e.load_profile(),'profileSha256':e.digest(e.BASE/'contracts/candidate-build-profile.json')},
            'preparation':{'schemaVersion':3,'status':'prepared-no-model-call','modelCallCount':0,'authenticationReleased':False,'trialAuthorized':False,'sourceCheckpointSha256':sha,'preflightMatrixSha256':sha,'reviewedPreflightInventorySha256':sha,'independentReviewSha256':sha,'independentAcceptanceSha256':sha,'toolchainEnvironmentPinSha256':sha,'artifacts':{'synthetic':sha},'historicalPreservationVerified':True,'preservationScope':'locked-template-inputs-only','externalDependenciesRequireReverification':True,'abiAccuracy':'unassessed','formalStructuralScore':None,'productionFactoryQualified':False,'productionProviderQualified':False,'productionFilesystemQualified':False}}
        for name,value in values.items():
            e.validate_exchange(name,value)
            for key,item in (('schemaVersion',2),('unexpected',True)):
                changed=deepcopy(value);changed[key]=item
                with self.assertRaises(Exception,msg=name):e.validate_exchange(name,changed)
    def test_reference_receipt_hash_and_parse_use_one_authenticated_snapshot(self):
        import bounded_runtime as runtime
        import hashlib
        trusted=static_temp('static-process')
        with tempfile.TemporaryDirectory(dir=trusted) as temporary:
            root=Path(temporary);(root/'private').mkdir()
            (root/'private/original.c').write_text('authored source only')
            shutil.copytree(e.BASE/'contracts',root/'contracts')
            prep=root/'preparation';prep.mkdir();(prep/'reference').mkdir()
            caller=prep/'caller';caller.write_bytes(b'authored inert caller')
            library=prep/'reference/libcandidate.so';library.write_bytes(b'authored inert library')
            pins=runtime._pin_files((caller,library));rows=[]
            for i,family in enumerate(e.SCENARIO_FAMILIES):
                execution=receipt(7,caller=str(caller),caller_sha=e.digest(caller),input_pins=pins)
                raw=json.dumps({'status':'failed','execution':e.public_result(execution)}).encode()
                (prep/('reference-process-'+str(i)+'.json')).write_bytes(raw)
                rows.append({'id':i,'family':family,'process':e.process_observation(execution),
                             'evidenceSha256':hashlib.sha256(raw).hexdigest()})
            observations=prep/'reference-observations.json'
            observations.write_text(json.dumps({'schemaVersion':3,'sourceSha256':e.digest(root/'private/original.c'),
                'callerSha256':e.digest(caller),'callerPath':str(caller),'libraryPath':str(library),
                'librarySha256':e.digest(library),'profileSha256':e.digest(root/'contracts/candidate-build-profile.json'),
                'observations':rows}))
            original_read=e._read_json;original_digest=e.digest;seen=[]
            def read_once(path,maximum):
                result=original_read(path,maximum)
                if path.name.startswith('reference-process-'):
                    self.assertEqual(1048576,maximum);seen.append(path.name)
                    # A later pathname version cannot redefine the returned parsed bytes/hash.
                    if path.name=='reference-process-0.json':path.write_bytes(b'{"execution":{}}')
                return result
            def no_receipt_digest(path,**kwargs):
                if path.name.startswith('reference-process-'):
                    raise AssertionError('receipt must not have a separate pathname digest')
                return original_digest(path,**kwargs)
            with patch.object(e,'BASE',root),patch.object(e,'_read_json',side_effect=read_once),patch.object(e,'digest',side_effect=no_receipt_digest):
                self.assertEqual(24,len(e.validated_observations(observations,caller,prep)))
            self.assertEqual(['reference-process-'+str(i)+'.json' for i in range(24)],seen)
            with patch.object(e,'BASE',root):
                with self.assertRaisesRegex(ValueError,'receipt drift'):
                    e.validated_observations(observations,caller,prep)

    def test_reference_original_source_uses_its_bounded_role_without_invented_phase_end(self):
        import bounded_runtime as runtime
        import build_contract as contract
        import stat
        import types
        trusted=static_temp('static-process')
        with tempfile.TemporaryDirectory(dir=trusted) as temporary:
            root=Path(temporary);(root/'private').mkdir();original=root/'private/original.c'
            original.write_bytes(b'authored original source')
            prep=root/'preparation';prep.mkdir();(prep/'reference').mkdir()
            caller=prep/'caller';caller.write_bytes(b'authored caller')
            library=prep/'reference/libcandidate.so';library.write_bytes(b'authored library')
            observations=prep/'reference-observations.json';observations.write_bytes(b'{}')
            header={'sourceSha256':e.digest(original),'callerSha256':e.digest(caller),'callerPath':str(caller),
                    'libraryPath':str(library),'librarySha256':e.digest(library),
                    'profileSha256':e.load_profile_with_digest()[1],'observations':[]}
            real_digest=e.digest;real_fstat=contract.os.fstat;original_inode=original.stat().st_ino
            calls=[]
            def hashing(path,**kwargs):
                calls.append((path,kwargs));return real_digest(path,**kwargs)
            with patch.object(e,'BASE',root),patch.object(e,'read_exchange',return_value=header), \
                    patch.object(e,'digest',side_effect=hashing):
                # Passing the real source admission reaches the unchanged24-row check.
                with self.assertRaisesRegex(ValueError,'scenario identity drift'):
                    e.validated_observations(observations,caller,prep)
            self.assertEqual([(original,{'maximum':16777216,'deadline':None})],calls)
            for mutation in ('fifo','oversize'):
                def fstat(fd):
                    value=real_fstat(fd)
                    if value.st_ino==original_inode:
                        fields={key:getattr(value,key) for key in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')}
                        if mutation=='fifo':fields['st_mode']=stat.S_IFIFO|0o600
                        else:fields['st_size']=16777217
                        return types.SimpleNamespace(**fields)
                    return value
                with self.subTest(mutation=mutation),patch.object(e,'BASE',root), \
                        patch.object(e,'read_exchange',return_value=header),patch.object(contract.os,'fstat',side_effect=fstat), \
                        patch.object(e,'_read_json',side_effect=AssertionError('source must refuse before receipts')):
                    with self.assertRaisesRegex(ValueError,'regular file byte bound'):
                        e.validated_observations(observations,caller,prep)
            original.unlink();original.symlink_to(caller)
            with patch.object(e,'BASE',root),patch.object(e,'read_exchange',return_value=header), \
                    patch.object(e,'_read_json',side_effect=AssertionError('source must refuse before receipts')):
                with self.assertRaises(OSError):e.validated_observations(observations,caller,prep)

    def test_nonzero_reference_binds_actual_selected_preparation_and_raw_receipts(self):
        import bounded_runtime as runtime
        trusted=static_temp('static-process')
        with tempfile.TemporaryDirectory(dir=trusted) as temporary:
            root=Path(temporary);(root/'private').mkdir();(root/'private/original.c').write_text('synthetic source only')
            prep=root/'preparation';prep.mkdir();(prep/'reference').mkdir()
            caller=prep/'caller';caller.write_bytes(b'authored inert caller')
            library=prep/'reference/libcandidate.so';library.write_bytes(b'authored inert shared-library file')
            shutil.copytree(e.BASE/'contracts',root/'contracts')
            # Actual bounded input reader supplies physical metadata. These wire
            # records remain authored parser fixtures, not native worker proof.
            pins=runtime._pin_files((caller,library))
            rows=[]
            for i,family in enumerate(e.SCENARIO_FAMILIES):
                raw=receipt(7,caller=str(caller),caller_sha=e.digest(caller),input_pins=pins)
                path=prep/('reference-process-'+str(i)+'.json')
                path.write_text(json.dumps({'status':'failed','execution':e.public_result(raw)}))
                rows.append({'id':i,'family':family,'process':e.process_observation(raw),'evidenceSha256':e.digest(path)})
            path=prep/'reference-observations.json'
            value={'schemaVersion':3,'sourceSha256':e.digest(root/'private/original.c'),'callerSha256':e.digest(caller),'callerPath':str(caller),'libraryPath':str(library),'librarySha256':e.digest(library),'profileSha256':e.digest(root/'contracts/candidate-build-profile.json'),'observations':rows}
            def write():path.write_text(json.dumps(value))
            write()
            with patch.object(e,'BASE',root):
                validated=e.validated_observations(path,caller,prep)
                self.assertEqual(len(validated),24)
                caller_pin=e._reference_caller_pin(validated,caller)
                self.assertEqual(caller_pin,pins[str(caller)])
                self.assertEqual(caller_pin['sha256'],value['callerSha256'])
                e._require_reference_caller(caller,caller_pin)
                # No later read can redefine the in-memory validated identity.
                altered=deepcopy(validated);altered[1]['process']['launchInputPins'][str(caller)]['sha256']='f'*64
                with self.assertRaisesRegex(ValueError,'across observations'):e._reference_caller_pin(altered,caller)
                with self.assertRaisesRegex(ValueError,'identity missing'):e._reference_caller_pin([],caller)
                rp=prep/'reference-process-0.json';retained=rp.read_bytes();rp.write_bytes(b'{}')
                with self.assertRaisesRegex(ValueError,'receipt drift'):e.validated_observations(path,caller,prep)
                rp.write_bytes(retained)
                caller_bytes=caller.read_bytes();caller.write_bytes(b'changed caller')
                with self.assertRaisesRegex(ValueError,'validated reference caller'):e._require_reference_caller(caller,caller_pin)
                self.assertEqual(caller_pin['sha256'],value['callerSha256'])
                self.assertNotEqual(caller_pin['sha256'],e.digest(caller))
                with self.assertRaisesRegex(ValueError,'fixture/caller'):e.validated_observations(path,caller,prep)
                caller.write_bytes(caller_bytes)
                e._require_reference_caller(caller,caller_pin)
                # Same bytes on a new inode must not borrow the reference identity.
                held_caller=prep/'held-reference-caller';caller.rename(held_caller);caller.write_bytes(caller_bytes)
                self.assertEqual(e.digest(caller),caller_pin['sha256'])
                with self.assertRaisesRegex(ValueError,'validated reference caller'):e._require_reference_caller(caller,caller_pin)
                caller.unlink();held_caller.rename(caller)
                e._require_reference_caller(caller,caller_pin)
                prior_mode=caller.stat().st_mode & 0o7777;caller.chmod(0o500)
                try:
                    with self.assertRaisesRegex(ValueError,'validated reference caller'):e._require_reference_caller(caller,caller_pin)
                finally:caller.chmod(prior_mode)
                e._require_reference_caller(caller,caller_pin)
                original=root/'private/original.c';original_bytes=original.read_bytes();original.write_bytes(b'changed source generation')
                with self.assertRaisesRegex(ValueError,'fixture/caller'):e.validated_observations(path,caller,prep)
                original.write_bytes(original_bytes)
                saved=library.read_bytes();library.rename(prep/'reference/retained-old-library.so')
                with self.assertRaises((OSError,ValueError)):e.validated_observations(path,caller,prep)
                library.write_bytes(saved) # same bytes, different physical identity
                with self.assertRaisesRegex(ValueError,'physical identity'):e.validated_observations(path,caller,prep)
                # Rebuild authored receipts from newly admitted actual metadata.
                for row in rows:
                    raw=receipt(7,caller=str(caller),caller_sha=e.digest(caller),input_pins=runtime._pin_files((caller,library)))
                    rp=prep/('reference-process-'+str(row['id'])+'.json');rp.write_text(json.dumps({'status':'failed','execution':e.public_result(raw)}))
                    row.update(process=e.process_observation(raw),evidenceSha256=e.digest(rp))
                write();self.assertEqual(len(e.validated_observations(path,caller,prep)),24)
                library.write_bytes(b'changed shared-library bytes')
                with self.assertRaisesRegex(ValueError,'fixture/caller'):e.validated_observations(path,caller,prep)
                library.write_bytes(saved)
                value['libraryPath']='/synthetic/nonexistent.so';write()
                with self.assertRaises(ValueError):e.validated_observations(path,caller,prep)
                value['libraryPath']=str(library);write()
                other=root/'other-preparation';other.mkdir()
                with self.assertRaisesRegex(ValueError,'independently selected'):e.validated_observations(path,caller,other)
                value['profileSha256']='f'*64;write()
                with self.assertRaises(ValueError):e.validated_observations(path,caller,prep)


    def test_accounting_and_unverified_activity_tamper_refuse(self):
        for key,value in (('matchedScenarioProcessCount',0),('processBehaviorRate',0),('admitted',False)):
            report=report_fixture();report[key]=value
            with self.assertRaises(ValueError):e.validate_exchange('report',report)
        report=report_fixture();report['scenarios'][0]['process']['scopeVerified']=False
        with self.assertRaises(Exception):e.validate_exchange('report',report)
        report=report_fixture();report['scenarios'][0]['apiEntryObservation']['status']='not-attempted'
        with self.assertRaises(ValueError):e.validate_exchange('report',report)
    def test_nonfinite_duplicate_and_bounded_exchange_read(self):
        trusted=static_temp('static-process')
        with tempfile.TemporaryDirectory(dir=trusted) as temporary:
            path=Path(temporary)/'input.json'
            for raw in ('{"schemaVersion":3,"schemaVersion":2}', '{"value":NaN}', 'xxxxxxxxx'):
                path.write_text(raw)
                with self.assertRaises(ValueError):e.read_exchange(path,'matrix',maximum=40)
            path.write_text('{"schemaVersion":3}')
            with self.assertRaises(ValueError):e.read_exchange(path,'matrix',maximum=4)
    def test_helper_raw_payload_closed_schema_with_pinned_engine(self):
        from test_identity_graph import graph
        value=graph();e.validate_exchange('helper',value)
        value['untrustedExtra']=True
        with self.assertRaises(Exception):e.validate_exchange('helper',value)
    def test_unknown_positive_control_is_not_accepted(self):
        report=report_fixture();report['matchedScenarioProcessCount']=0;report['unknownScenarioProcessCount']=24
        self.assertFalse(e.control_passed({'expected':'matched'},report))
        self.assertTrue(e.control_passed({'expected':'matched'},report_fixture()))
        report=report_fixture();report['mismatchedScenarioProcessCount']=1;report['phases']['behavior']['status']='failed'
        self.assertTrue(e.control_passed({'expected':'mismatched'},report))
        report=report_fixture();report['unknownScenarioProcessCount']=1
        self.assertTrue(e.control_passed({'expected':'unknown'},report))
        report=report_fixture();report.update(admitted=False,runtimeRequestCount=0,admissionRefusedCount=24)
        report['phases']['declarations']['status']='refused'
        self.assertTrue(e.control_passed({'expected':'refused','stage':'declarations'},report))
        report['runtimeRequestCount']=1
        self.assertFalse(e.control_passed({'expected':'refused','stage':'declarations'},report))
    def test_static_pin_cannot_be_upgraded_by_native_claim_text(self):
        native_claim='Native qualification: **QUALIFIED** '+('a'*64)+' '+('b'*64)
        pin={'schemaVersion':3,'status':'static-recording-unqualified','nativeQualificationClaim':native_claim}
        with self.assertRaisesRegex(ValueError,'static-only toolchain pin'):
            f.require_qualified_pin(pin)
        with self.assertRaisesRegex(ValueError,'typed qualified machine closure'):
            f.require_qualified_pin({'status':'invented-qualified','nativeQualificationClaim':native_claim})

    def test_source_checkpoint_precedes_preflight_and_output(self):
        trusted=static_temp('static-process-correction-001')
        with tempfile.TemporaryDirectory(dir=trusted) as temporary:
            root=Path(temporary);preflight=root/'preflight';preflight.mkdir();output=root/'no-seal-created'
            matrix={'schemaVersion':3,'status':'preflight-only-independent-review-required','freezeCreated':False,'allControlsPassed':True,'executionDependenciesUnchanged':True,'rows':[{'name':'synthetic','expected':'matched','expectedStage':'behavior','passed':True,'receipt':'synthetic','receiptSha256':'a'*64,'runtimeRequestCount':24,'completedScenarioProcessCount':24,'unknownScenarioProcessCount':0}]}
            bindings={'schemaVersion':3,'sourceCheckpointSha256':'a'*64,'initialSha256':{'synthetic':'a'*64},'helperCopySha256':'a'*64,'helperSchemaSha256':'a'*64,'helperSchemaVersion':3}
            (preflight/'matrix.json').write_text(json.dumps(matrix));(preflight/'execution-bindings.json').write_text(json.dumps(bindings))
            for name in ('source.json','toolchain.json','review.md','acceptance.md','qualification.md'):(root/name).write_text('{}')
            with patch.object(f,'BASE',root):
                with self.assertRaisesRegex(ValueError,'source checkpoint binding drift'):
                    f.freeze(preflight,root/'review.md',output,root/'toolchain.json',root/'acceptance.md',root/'source.json',root/'qualification.md')
            self.assertFalse(output.exists())

    def test_missing_raw_stream_report_remains_unknown_without_empty_fabrication(self):
        report=report_fixture();raw=receipt();del raw['stdout']
        rows=[e.scenario_entry(o,raw,True,'a'*64) for o in observations()]
        summary=e.summarize(rows,True);report.update({key:value for key,value in summary.items() if key!='behaviorStatus'})
        report['scenarios']=rows;report['phases']['behavior']['status']=summary['behaviorStatus']
        e.validate_exchange('report',report)
        self.assertEqual(report['unknownScenarioProcessCount'],24);self.assertEqual(report['completedScenarioProcessCount'],0)
        self.assertIsNone(rows[0]['process']['stdoutHex']);self.assertEqual(rows[0]['process']['stderrHex'],'')
        self.assertIsNone(report['processBehaviorRate'])

    def test_unprepared_launcher_unknown_proof_retains_diagnostics(self):
        raw=receipt();raw.update(exitCode=None,workerExecVerified=False,workerTerminationVerified=False,workerTermination=None,
             workerProofRaw=b'',workerProofBindings=None,launchInputPins=None,
             workerProof={'protocolVersion':1,'status':'unknown','proofSha256':None,'fileIdentityVerified':False,'pinsUnchanged':False,'reason':'launch-not-prepared'})
        report=report_fixture();rows=[e.scenario_entry(o,raw,True,'a'*64) for o in observations()]
        summary=e.summarize(rows,True);report.update({key:value for key,value in summary.items() if key!='behaviorStatus'})
        report['scenarios']=rows;report['phases']['behavior']['status']=summary['behaviorStatus']
        e.validate_exchange('report',report)
        self.assertEqual(report['unknownScenarioProcessCount'],24)
        self.assertIsNone(rows[0]['process']['termination'])
        self.assertEqual(rows[0]['process']['workerProof']['reason'],'launch-not-prepared')

    def test_historical_load_pass_acceptance_is_rejected_by_current_exchange(self):
        namespace=historical_namespace(summarize=e.summarize)
        report=report_fixture();report['phases']['load']={'status':'passed','reason':'unsupported claim','evidenceSha256':None}
        self.assertEqual(namespace['validate_exchange']('report',report),report)
        malformed=deepcopy(report);malformed['phases']['load']['status']='invented'
        with self.assertRaises(ValueError):namespace['validate_exchange']('report',malformed)
        with self.assertRaises(Exception):e.validate_exchange('report',report)

    def test_load_phase_and_api_claims_refuse_for_both_admission_states(self):
        for admitted in (True,False):
            report=report_fixture()
            if not admitted:
                rows=[e.scenario_entry(o) for o in observations()];summary=e.summarize(rows,False)
                report.update({key:value for key,value in summary.items() if key!='behaviorStatus'})
                report.update(admitted=False,scenarios=rows,runtimeInputs=None)
                for name in e.PHASES:report['phases'][name]={'status':'not-attempted','reason':'synthetic','evidenceSha256':None}
                report['phases']['load']={'status':'not-attempted','value':None}
            e.validate_exchange('report',report)
            for status in ('passed','failed','refused','unknown','unverified' if not admitted else 'not-attempted'):
                changed=deepcopy(report);changed['phases']['load']['status']=status
                with self.assertRaises(Exception):e.validate_exchange('report',changed)
            for field in ('apiEntryCount','apiCompletionCount','callbackCount','apiCoverage','apiBehaviorRate'):
                changed=deepcopy(report);changed[field]=0
                with self.assertRaises(Exception):e.validate_exchange('report',changed)



class BoundedTrees(unittest.TestCase):
    def setUp(self):
        self.trusted=static_temp('static-process-correction-001')
        self.temporary=tempfile.TemporaryDirectory(dir=self.trusted);self.addCleanup(self.temporary.cleanup)
        self.root=Path(self.temporary.name)

    def test_exact_and_one_over_node_file_byte_and_depth_caps(self):
        root=self.root/'input';root.mkdir();(root/'one').write_bytes(b'abc')
        limits=dict(nodes=2,directories=1,files=1,bytes=3,depth=1)
        snapshot=f.admit_tree(root,f.TreeBudget(**limits))
        self.assertEqual(snapshot['usage'],{'nodes':2,'directories':1,'files':1,'bytes':3})
        for key,value in (('nodes',1),('files',0),('bytes',2),('depth',0),('directories',0)):
            with patch.object(f.os,'read',side_effect=AssertionError('payload read before admission')):
                with self.assertRaises(ValueError,msg=key):f.admit_tree(root,f.TreeBudget(**{**limits,key:value}))

    def test_empty_directories_are_charged_and_copied(self):
        root=self.root/'input';root.mkdir();(root/'empty').mkdir()
        with self.assertRaises(ValueError):f.admit_tree(root,f.TreeBudget(directories=1))
        snapshot=f.admit_tree(root,f.TreeBudget(nodes=2,directories=2,files=0,bytes=0,depth=1))
        self.assertEqual(snapshot['usage']['nodes'],2)
        plan=f.CopyPlan();plan.add_tree('tree',snapshot);plan.execute(self.root/'copy')
        self.assertTrue((self.root/'copy/tree/empty').is_dir())

    def test_nested_depth_refuses_before_payload_read(self):
        root=self.root/'input';(root/'nested').mkdir(parents=True);(root/'nested/file').write_bytes(b'abc')
        with patch.object(f.os,'read',side_effect=AssertionError('over-depth payload read')):
            with self.assertRaises(ValueError):f.admit_tree(root,f.TreeBudget(depth=1))

    def test_streaming_iterator_stops_before_exhaustion_or_unbounded_sort(self):
        from types import SimpleNamespace
        counts={'yielded':0,'stat':0}
        class Entry:
            def __init__(self,n):self.name=str(n)
            def stat(self,follow_symlinks):
                counts['stat']+=1;return SimpleNamespace(st_mode=f.stat.S_IFREG,st_size=1)
        class Entries:
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def __iter__(self):
                for n in range(50):counts['yielded']+=1;yield Entry(n)
        root=self.root/'input';root.mkdir()
        with patch.object(f.os,'scandir',return_value=Entries()),patch.object(f.os,'read',side_effect=AssertionError('unadmitted read')):
            with self.assertRaises(ValueError):f.admit_tree(root,f.TreeBudget(nodes=4))
        self.assertEqual(counts,{'yielded':4,'stat':3})

    def test_symlink_special_and_parent_symlink_refuse_without_payload(self):
        import os
        target=self.root/'target';target.write_bytes(b'authored harmless bytes')
        for kind in ('symlink','fifo'):
            root=self.root/kind;root.mkdir()
            if kind=='symlink':(root/'entry').symlink_to(target)
            else:os.mkfifo(root/'entry')
            with patch.object(f.os,'read',side_effect=AssertionError('unsupported payload read')):
                with self.assertRaises(ValueError):f.admit_tree(root)
        (self.root/'alias').symlink_to(self.root/'symlink',target_is_directory=True)
        with self.assertRaises(OSError):f.admit_tree(self.root/'alias')

    def test_complete_copy_reservation_counts_duplicate_payloads_before_output(self):
        source=self.root/'source';source.write_bytes(b'ab')
        item=next(iter(f.admit_files([source])['files'].values()))
        plan=f.CopyPlan(f.TreeBudget(nodes=4,files=3,bytes=3))
        plan.add('first',record=item)
        with self.assertRaisesRegex(ValueError,'payload budget'):plan.add('second',record=item)
        self.assertEqual(plan.budget.used['bytes'],2);self.assertFalse((self.root/'output').exists())
        with self.assertRaises(ValueError):f.CopyPlan(f.TreeBudget(files=10001))

    def test_json_population_reserved_before_bounded_stream_materialization(self):
        counts={'chunks':0}
        class Encoder:
            def __init__(self,**kwargs):pass
            def iterencode(self,value):
                for n in range(50):counts['chunks']+=1;yield 'x'
        plan=f.CopyPlan(f.TreeBudget(nodes=2,directories=1,files=1,bytes=3))
        with patch.object(f.json,'JSONEncoder',Encoder):
            with self.assertRaisesRegex(ValueError,'JSON copy payload budget'):plan.add_json('report.json',{})
        self.assertEqual(counts['chunks'],4);self.assertEqual(plan.budget.used['files'],1)
        with self.assertRaisesRegex(ValueError,'pending JSON'):plan.execute(self.root/'output')
        self.assertFalse((self.root/'output').exists())

    def test_copy_source_replacement_rejects_before_any_read(self):
        source=self.root/'source';source.write_bytes(b'ab');target=self.root/'other';target.write_bytes(b'cd')
        item=next(iter(f.admit_files([source])['files'].values()))
        plan=f.CopyPlan();plan.add('file',record=item)
        source.unlink();source.symlink_to(target)
        with patch.object(f.os,'read',side_effect=AssertionError('replaced source payload read')):
            with self.assertRaises((OSError,ValueError)):plan.execute(self.root/'output')
        if (self.root/'output/file').exists():self.assertEqual((self.root/'output/file').stat().st_size,0)

    def test_directory_replacement_is_rejected_before_opening_source_file(self):
        root=self.root/'input';root.mkdir();source=root/'file';source.write_bytes(b'ab')
        item=next(iter(f.admit_files([source],root=self.root)['files'].values()))
        root.rename(self.root/'previous');root.mkdir();source.write_bytes(b'ab')
        actual=f.os.open;opened=[]
        def open_file(path,*args,**kwargs):opened.append(str(path));return actual(path,*args,**kwargs)
        plan=f.CopyPlan();plan.add('file',record=item)
        with patch.object(f.os,'open',side_effect=open_file),patch.object(f.os,'read',side_effect=AssertionError('replaced parent payload')):
            with self.assertRaisesRegex(ValueError,'directory changed'):plan.execute(self.root/'output')
        # Source-parent proof fails before opening the source or target file.
        self.assertEqual(opened.count('file'),0)

    def test_exact_final_copy_caps_and_duplicate_payload_coverage(self):
        source=self.root/'source';source.write_bytes(b'ab')
        item=next(iter(f.admit_files([source])['files'].values()))
        limits=f.TreeBudget(nodes=3,directories=1,files=2,bytes=4,depth=1)
        plan=f.CopyPlan(limits);plan.add('one',record=item);plan.add('two',record=item)
        plan.execute(self.root/'output')
        self.assertEqual(plan.budget.used,{'nodes':3,'directories':1,'files':2,'bytes':4})
        self.assertEqual((self.root/'output/one').read_bytes(),(self.root/'output/two').read_bytes())

    def test_chunked_exact_fd_copy_and_bound_before_oversize_read(self):
        source=self.root/'source';source.write_bytes(b'abcdefg')
        item=next(iter(f.admit_files([source])['files'].values()))
        with patch.object(f.os,'read',side_effect=AssertionError('oversize read')):
            with self.assertRaises(ValueError):f.read_admitted(item,maximum=6)
        calls=[];actual=f.os.read
        def read(fd,n):calls.append(n);return actual(fd,n)
        with patch.object(f,'CHUNK_BYTES',2),patch.object(f.os,'read',side_effect=read):
            plan=f.CopyPlan();plan.add('file',record=item);plan.execute(self.root/'output')
        self.assertEqual((self.root/'output/file').read_bytes(),b'abcdefg');self.assertTrue(all(n<=2 for n in calls))

    def test_historical_inventory_counterexample_is_preserved_and_current_stops_early(self):
        from types import SimpleNamespace
        counts={'yielded':0,'checked':0}
        class Entry:
            def __init__(self,n):self.name=str(n)
            def __lt__(self,other):return self.name<other.name
            def is_file(self):counts['checked']+=1;return True
            def stat(self):return SimpleNamespace(st_size=1)
            def relative_to(self,root):return self.name
        class Root:
            def rglob(self,pattern):
                for n in range(50):counts['yielded']+=1;yield Entry(n)
        namespace=historical_namespace(digest=lambda _: 'a'*64)
        with self.assertRaises(ValueError):namespace['inventory'](Root())
        self.assertEqual(counts['yielded'],50);self.assertGreater(counts['yielded'],4)


class RegularOpenOwnership(unittest.TestCase):
    """Actual helper over symbolic FDs; no filesystem, payload or process operations."""
    def vector(self, failure=None, close_failures=(), *, regular=True, malformed_notes=False):
        path=Path('/authored/record.json');parents=(('/authored',(1,2,3)),)
        handles=set();acquired=[];closed=[];attempted=[];events=[]
        open_error=OSError('authored leaf-open refusal')
        stat_error=OSError('authored admission-fstat refusal')
        if malformed_notes:stat_error.__notes__=None
        parent_error=OSError('authored parent-close refusal')
        leaf_error=OSError('authored leaf-close refusal')
        nonregular_error=ValueError('regular file required')
        def parent_open(directory,expected):
            self.assertEqual((path.parent,parents),(directory,expected))
            handles.add(41);acquired.append(41);events.append(('parent',41))
            return 41
        def leaf_open(name,flags,*,dir_fd):
            self.assertEqual(('record.json',41),(name,dir_fd))
            self.assertEqual(f.os.O_RDONLY|f.os.O_NOFOLLOW|f.os.O_NONBLOCK|f.os.O_CLOEXEC,flags)
            self.assertIn(41,handles);events.append(('open',42))
            if failure=='open':raise open_error
            handles.add(42);acquired.append(42)
            return 42
        def admission(number):
            self.assertEqual(42,number);self.assertIn(number,handles)
            events.append(('fstat',42))
            if failure=='fstat':raise stat_error
            return type('AuthoredMetadata',(),{'st_mode':f.stat.S_IFREG if regular else f.stat.S_IFIFO})()
        def closing(number):
            attempted.append(number)  # Count even a retry whose assertion is caught by cleanup.
            self.assertIn(number,handles,'each acquired descriptor gets one close attempt')
            # Remove symbolic ownership even on failure: no assumption permits a retry.
            handles.remove(number);closed.append(number);events.append(('close',number))
            if number in close_failures:raise parent_error if number==41 else leaf_error
        answer=error=None
        with patch.object(f,'_open_directory',side_effect=parent_open), \
                patch.object(f.os,'open',side_effect=leaf_open), \
                patch.object(f.os,'fstat',side_effect=admission) as observed, \
                patch.object(f.os,'close',side_effect=closing), \
                patch.object(f.os,'read',side_effect=AssertionError('regular-open must not read payload')) as reading, \
                patch.object(f.os,'pread',side_effect=AssertionError('regular-open must not pread payload')) as preading, \
                patch.object(f,'ValueError',return_value=nonregular_error,create=True) as nonregular:
            try:answer=f._open_regular(path,parents)
            except BaseException as caught:error=caught
        self.assertEqual([],reading.call_args_list);self.assertEqual([],preading.call_args_list)
        self.assertEqual(closed,attempted);self.assertEqual(len(attempted),len(set(attempted)))
        return {'answer':answer,'error':error,'handles':handles,'acquired':acquired,'closed':closed,'attempted':attempted,'events':events,
                'open_error':open_error,'stat_error':stat_error,'parent_error':parent_error,'leaf_error':leaf_error,
                'nonregular_error':nonregular_error,'fstat_calls':observed.call_count,'nonregular_calls':nonregular.call_args_list}

    def assert_failed_closed(self,value,primary,closed):
        self.assertIsNone(value['answer']);self.assertIs(value['error'],value[primary])
        self.assertEqual(set(),value['handles']);self.assertEqual(closed,value['closed'])
        self.assertEqual(sorted(value['acquired']),sorted(value['closed']))

    def test_regular_open_success_preserves_order_and_transfers_only_leaf(self):
        value=self.vector()
        self.assertIsNone(value['error']);self.assertEqual(42,value['answer'])
        self.assertEqual({42},value['handles']);self.assertEqual([41],value['closed'])
        self.assertEqual([('parent',41),('open',42),('close',41),('fstat',42)],value['events'])
        self.assertEqual(1,value['fstat_calls']);self.assertEqual([],value['nonregular_calls'])

    def test_regular_open_leaf_open_and_late_fstat_failures_close_once(self):
        for failure,primary,closed in (('open','open_error',[41]),('fstat','stat_error',[41,42])):
            with self.subTest(failure=failure):
                value=self.vector(failure)
                self.assert_failed_closed(value,primary,closed)
                self.assertEqual(0 if failure=='open' else 1,value['fstat_calls'])
                if failure=='fstat':
                    self.assertEqual([('parent',41),('open',42),('close',41),('fstat',42),('close',42)],value['events'])

    def test_regular_open_parent_close_failure_still_closes_leaf_without_admission(self):
        for faults in ((41,),(41,42)):
            with self.subTest(close_failures=faults):
                value=self.vector(close_failures=faults)
                self.assert_failed_closed(value,'parent_error',[41,42])
                self.assertEqual(0,value['fstat_calls']);self.assertEqual([],value['nonregular_calls'])
                self.assertEqual([('parent',41),('open',42),('close',41),('close',42)],value['events'])
                if 42 in faults:
                    self.assertEqual(['regular file descriptor cleanup failures: 1'],value['error'].__notes__)

    def test_regular_open_metadata_nonregular_and_open_primaries_survive_cleanup_faults(self):
        for failure,faults,regular,primary,closed in (
                ('open',(41,),True,'open_error',[41]),
                ('fstat',(42,),True,'stat_error',[41,42]),
                (None,(),False,'nonregular_error',[41,42]),
                (None,(42,),False,'nonregular_error',[41,42])):
            with self.subTest(failure=failure,close_failures=faults,regular=regular):
                value=self.vector(failure,faults,regular=regular)
                self.assert_failed_closed(value,primary,closed)
                if faults:
                    self.assertEqual(['regular file descriptor cleanup failures: 1'],value['error'].__notes__)
                if not regular:
                    self.assertEqual(1,len(value['nonregular_calls']))
                    self.assertEqual(('regular file required',),value['nonregular_calls'][0].args)
                else:self.assertEqual([],value['nonregular_calls'])
        # Malformed existing notes make add_note raise; that secondary diagnostic
        # must not mask this exact admission error after the leaf-close fault.
        value=self.vector('fstat',(42,),malformed_notes=True)
        self.assert_failed_closed(value,'stat_error',[41,42])
        self.assertIsNone(value['error'].__notes__)
        self.assertEqual([41,42],value['attempted']);self.assertEqual(1,value['fstat_calls'])


# Exact reviewed coordinator SOURCE TEXT only. Never execute these module bodies.
# No private originals/cases/candidates or host build path is a runtime fixture input.
_PREDICATE_PREPARE_SOURCE = b'"""Trusted-only preflight template. Execution requires later native authorization."""\nimport argparse\nimport json\nfrom pathlib import Path\nfrom bounded_runtime import write_json, contained_command\nfrom build_contract import write_visible, profile\nfrom evaluate_candidate_v3 import (BASE,evaluate,run,phase_command,runtime_command,process_observation,validate_exchange,SCENARIO_FAMILIES,control_passed,new_worker_leaf,copy_input,compile_sequence,environment)\nfrom generate_controls_v3 import generate\nfrom freeze_v3 import execution_source_paths, admit_files, read_json, CopyPlan\n\nTEMPLATE_BASE=Path(__file__).resolve().parent\n\n\ndef preflight(output, helper, source_checkpoint):\n    if \'build/acp-decomp-effectiveness/callable-library-v3\' not in str(BASE):raise ValueError(\'trusted source copy required\')\n    if TEMPLATE_BASE != BASE:raise ValueError(\'compose current templates and held support in one new trusted generation before preflight\')\n    checkpoint=read_json(source_checkpoint)\n    if set(checkpoint)!={\'schemaVersion\',\'files\'} or checkpoint[\'schemaVersion\']!=3:raise ValueError(\'prior immutable v3 source checkpoint required\')\n    initial=checkpoint[\'files\']\n    # Complete exact execution-source set; no runtime results or historical observations are inputs.\n    required=execution_source_paths()\n    if set(initial)!=required:raise ValueError(\'source checkpoint must cover complete exact execution inputs\')\n    sources=admit_files(initial,root=BASE)[\'files\']\n    if any(sources[path][\'sha256\']!=sha for path,sha in initial.items()):raise ValueError(\'source changed before preflight\')\n    helper_record=next(iter(admit_files([helper],root=BASE)[\'files\'].values()))\n    plan=CopyPlan()\n    for path,item in sources.items():plan.add(Path(\'execution-snapshot\')/Path(path).relative_to(BASE),record=item)\n    plan.add(\'record_identity_probe\',record=helper_record)\n    plan.execute(output)  # entire source/helper copy population reserved first\n    write_visible(output)\n    helper_copy=output/\'record_identity_probe\'\n    bindings={\'schemaVersion\':3,\'sourceCheckpointSha256\':next(iter(admit_files([source_checkpoint],root=BASE)[\'files\'].values()))[\'sha256\'],\'initialSha256\':initial,\'helperCopySha256\':helper_record[\'sha256\'],\'helperSchemaSha256\':sources[str(BASE/\'contracts/helper-schema.json\')][\'sha256\'],\'helperSchemaVersion\':3}\n    validate_exchange(\'execution-bindings\',bindings);write_json(output/\'execution-bindings.json\',bindings)\n    def snapshot_sha(path):return next(iter(admit_files([path],root=BASE)[\'files\'].values()))[\'sha256\']\n    controls=generate(output/\'controls\');caller=output/\'caller\'\n    caller_work=new_worker_leaf(\'caller-build\')\n    caller_source=copy_input(BASE/\'private/caller.c\',caller_work/\'caller.c\')\n    caller_binary=caller_work/\'caller\'\n    caller_argv=[\'/usr/bin/gcc\',\'-std=c11\',\'-O2\',\'-Wall\',\'-Wextra\',\'-Werror\',str(caller_source),\'-ldl\',\'-o\',str(caller_binary)]\n    build,_=run(contained_command(caller_argv,caller_work,(caller_source,),environment=environment(caller_work)),caller_work,timeout=profile()[\'bounds\'][\'callerBuildSeconds\'],phase=\'caller-build\')\n    write_json(output/\'caller-build.json\',build)\n    if build[\'status\']!=\'passed\':raise RuntimeError(\'caller build incomplete\')\n    copy_input(caller_binary,caller,executable=True)\n    def retain_reference(phase,status):write_json(output/(\'reference-\'+phase+\'.json\'),status)\n    reference_status,reference_artifacts=compile_sequence(BASE/\'private/original.c\',headers=(BASE/\'private/original.h\',),retain=retain_reference)\n    if any(reference_status.get(phase,{}).get(\'status\')!=\'passed\' for phase in (\'preprocess\',\'compile\',\'link\')):\n        raise RuntimeError(\'reference build incomplete\')\n    reference=output/\'reference\';reference.mkdir(mode=0o700)\n    copy_input(reference_artifacts[\'link\'],reference/\'libcandidate.so\')\n    case_definitions=read_json(BASE/\'private/cases.json\',maximum=1048576)\n    cases=case_definitions[\'scenarios\']\n    if [c[\'id\'] for c in cases]!=list(range(24)) or [c[\'family\'] for c in cases]!=SCENARIO_FAMILIES:raise ValueError(\'scenario source identity drift\')\n    reference_library=(reference/\'libcandidate.so\').resolve(strict=True)\n    reference_input={\'path\':str(reference_library),\'sha256\':snapshot_sha(reference_library)}\n    observations=[]\n    for case in cases:\n        runtime_work=new_worker_leaf(\'runtime\')\n        status,result=run(runtime_command(caller,reference_library,case[\'id\']),runtime_work,timeout=profile()[\'bounds\'][\'runtimeSeconds\'],phase=\'runtime\',runtime_library=reference_input)\n        process=process_observation(result)\n        # Nonzero completed reference termination is valid; incomplete capture never becomes an oracle.\n        if not process[\'completed\']:raise RuntimeError(\'reference process incomplete\')\n        receipt=output/(\'reference-process-\'+str(case[\'id\'])+\'.json\');write_json(receipt,status)\n        observations.append({\'id\':case[\'id\'],\'family\':case[\'family\'],\'process\':process,\'evidenceSha256\':snapshot_sha(receipt)})\n    if snapshot_sha(reference_library)!=reference_input[\'sha256\']:raise ValueError(\'admitted reference library changed during scenarios\')\n    observations_path=output/\'reference-observations.json\'\n    value={\'schemaVersion\':3,\'sourceSha256\':sources[str(BASE/\'private/original.c\')][\'sha256\'],\'callerSha256\':snapshot_sha(caller),\'callerPath\':str(caller.resolve(strict=True)),\'libraryPath\':reference_input[\'path\'],\'librarySha256\':reference_input[\'sha256\'],\'profileSha256\':snapshot_sha(BASE/\'contracts/candidate-build-profile.json\'),\'observations\':observations}\n    validate_exchange(\'reference-observations\',value);write_json(observations_path,value)\n    rows=[]\n    for c in controls:\n        receipt=output/(\'control-\'+c[\'name\'])/\'receipt.json\'\n        report=evaluate(Path(c[\'path\']),receipt.parent,helper_copy,caller,output,observations_path)\n        rows.append({\'name\':c[\'name\'],\'expected\':c[\'expected\'],\'expectedStage\':c[\'stage\'],\'passed\':control_passed(c,report),\'receipt\':str(receipt),\'receiptSha256\':snapshot_sha(receipt),\'runtimeRequestCount\':report[\'runtimeRequestCount\'],\'completedScenarioProcessCount\':report[\'completedScenarioProcessCount\'],\'unknownScenarioProcessCount\':report[\'unknownScenarioProcessCount\']})\n    summary={\'schemaVersion\':3,\'status\':\'preflight-only-independent-review-required\',\'freezeCreated\':False,\'allControlsPassed\':all(r[\'passed\'] for r in rows),\'executionDependenciesUnchanged\':all(item[\'sha256\']==initial[path] for path,item in admit_files(initial,root=BASE)[\'files\'].items()) and next(iter(admit_files([helper],root=BASE)[\'files\'].values()))[\'sha256\']==helper_record[\'sha256\'],\'rows\':rows}\n    validate_exchange(\'matrix\',summary);write_json(output/\'matrix.json\',summary);return summary\n\n\nif __name__==\'__main__\':\n    parser=argparse.ArgumentParser(description=__doc__)\n    for name in (\'output\',\'helper\',\'source-checkpoint\'):parser.add_argument(\'--\'+name,type=Path,required=True)\n    args=parser.parse_args();print(json.dumps(preflight(args.output.resolve(),args.helper.resolve(),args.source_checkpoint.resolve()),indent=2))\n'
_PREDICATE_GENERATOR_SOURCE = b'"""Fresh private source controls; never reads a historical candidate."""\nfrom pathlib import Path\nimport hashlib\nimport json\nfrom build_contract import load_profile\nfrom freeze_v3 import read_regular, CopyPlan\nBASE=Path(__file__).resolve().parent\n\ndef generate(destination):\n    maximum=load_profile()[\'bounds\'][\'sourceBytes\']\n    header=read_regular(BASE/\'private/original.h\',maximum).decode(\'utf8\')\n    source=read_regular(BASE/\'private/original.c\',maximum).decode(\'utf8\').replace(\'#include "original.h"\', header).replace(\'#define ACP_PUBLIC __attribute__((visibility("default")))\',\'#define ACP_PUBLIC\')\n    controls=[];plan=CopyPlan()\n    def add(name,text,kind=\'refused\',stage=\'declarations\'):\n        raw=text.encode(\'utf8\')\n        if len(raw)>maximum:raise ValueError(\'control source bound\')\n        path=destination/(name+\'.c\');plan.add(name+\'.c\',raw=raw)\n        controls.append({\'name\':name,\'path\':str(path),\'sha256\':hashlib.sha256(raw).hexdigest(),\'expected\':kind,\'stage\':stage})\n    add(\'baseline\',source,\'matched\',\'behavior\')\n    add(\'renamed\',source.replace(\'struct acp_pair\',\'struct alternate_pair\').replace(\'struct acp_record\',\'struct alternate_record\'),\'matched\',\'behavior\')\n    anonymous=source.replace(\'struct acp_pair {\',\'struct {\').replace(\'struct acp_record {\',\'struct {\')\n    add(\'anonymous\',anonymous,\'matched\',\'behavior\')\n    aliases=source.replace(\'} acp_pair;\',\'} pair_origin;\\ntypedef pair_origin pair_mid;\\ntypedef pair_mid acp_pair;\').replace(\'} acp_record;\',\'} record_origin;\\ntypedef record_origin record_mid;\\ntypedef record_mid acp_record;\')\n    add(\'two-hop-alias\',aliases,\'matched\',\'behavior\')\n    mixed=aliases.replace(\'typedef int32_t (*acp_callback)\', \'typedef int32_t callback_scalar;\\ntypedef double weight_scalar;\\ntypedef int32_t (*acp_callback)\').replace(\'(*acp_callback)(int32_t value\',\'(*acp_callback)(callback_scalar value\').replace(\'double weight;\',\'double weight;\')\n    # Alias defined before records, then used in fields, parameters and callback.\n    mixed=mixed.replace(\'typedef enum acp_mode\',\'typedef double field_scalar;\\ntypedef enum acp_mode\').replace(\'    double weight;\',\'    field_scalar weight;\').replace(\'acp_pair pair, double scale\',\'acp_pair pair, weight_scalar scale\')\n    add(\'alias-parameter-callback-fields\',mixed,\'matched\',\'behavior\')\n    add(\'missing-fold\',source.replace(\'acp_fold\',\'removed_fold\'),\'refused\',\'exports\')\n    add(\'reordered-fields\',source.replace(\'    double weight;\\n    uint64_t bits;\',\'    uint64_t bits;\\n    double weight;\'))\n    add(\'equal-size-field\',source.replace(\'    uint64_t bits;\',\'    double bits;\').replace(\'pair.bits & UINT64_C(7)\',\'(uint64_t)pair.bits & UINT64_C(7)\'))\n    add(\'scale-parameter\',source.replace(\'acp_pair pair, double scale\',\'acp_pair pair, uint64_t scale\'))\n    add(\'signedness\',source.replace(\'acp_mix(int32_t delta\',\'acp_mix(uint32_t delta\'))\n    add(\'width\',source.replace(\'acp_mix(int32_t delta\',\'acp_mix(int64_t delta\'))\n    add(\'callback\',source.replace(\'(*acp_callback)(int32_t value\',\'(*acp_callback)(int64_t value\'))\n    start=source.index(\'ACP_PUBLIC double acp_fold(unsigned count, ...)\\n{\')\n    fixed=source[:start]+\'ACP_PUBLIC double acp_fold(unsigned count) { return (double)count * 0.5; }\\n\'\n    fixed=fixed.replace(\'double acp_fold(unsigned count, ...);\',\'double acp_fold(unsigned count);\')\n    add(\'varargs\',fixed)\n    add(\'state-layout\',source.replace(\'    uint32_t calls;\',\'    uint64_t calls;\'))\n    add(\'hidden-symbol\',source.replace(\'ACP_PUBLIC uint64_t acp_mix(\', \'__attribute__((visibility("hidden"))) uint64_t acp_mix(\'),\'refused\',\'exports\')\n    static=source.replace(\'uint64_t acp_mix(\', \'static uint64_t acp_mix(\').replace(\'ACP_PUBLIC static uint64_t\',\'__attribute__((used)) static uint64_t\')\n    add(\'static-symbol\',static,\'refused\',\'exports\')\n    add(\'ms-abi\',source.replace(\'uint64_t acp_mix(\', \'uint64_t __attribute__((ms_abi)) acp_mix(\'))\n    add(\'packed\',source.replace(\'struct acp_pair {\',\'struct __attribute__((packed)) acp_pair {\'))\n    add(\'anonymous-attribute\',anonymous.replace(\'typedef struct {\',\'typedef struct __attribute__((packed)) {\',1))\n    add(\'alias-attribute\',source.replace(\'} acp_pair;\',\'} acp_pair __attribute__((aligned(32)));\'))\n    add(\'asm-label\',source.replace(\'uint8_t rotate);\',\'uint8_t rotate) __asm__("other_mix");\',1),\'refused\',\'exports\')\n    add(\'behavior-mutant\',source.replace(\'0x9e3779b97f4a7c15\',\'0x9e3779b97f4a7c16\'),\'mismatched\',\'behavior\')\n    add(\'overinvoke\',source.replace(\'    result = callback(value, context);\',\'    callback(value, context);\\n    callback(value, context);\\n    callback(value, context);\\n    result = callback(value, context);\'),\'mismatched\',\'behavior\')\n    add(\'abnormal-runtime\',source.replace(\'    uint64_t combined = value ^ signed_token(delta);\',\'    __builtin_trap();\\n    uint64_t combined = value ^ signed_token(delta);\'),\'mismatched\',\'behavior\')\n    add(\'timeout\',source.replace(\'    uint64_t combined = value ^ signed_token(delta);\',\'    for (;;) { __asm__ volatile(""); }\\n    uint64_t combined = value ^ signed_token(delta);\'),\'unknown\',\'behavior\')\n    overflow=source.replace(\'    uint64_t combined = value ^ signed_token(delta);\',\'    extern long write(int, const void *, unsigned long);\\n    static const char output[8192] = {0};\\n    for (;;) { (void)write(1, output, sizeof(output)); }\\n    uint64_t combined = value ^ signed_token(delta);\')\n    add(\'output-overflow\',overflow,\'unknown\',\'behavior\')\n    add(\'constructor-load-failure\',source+\'\\n__attribute__((constructor)) static void load_failure(void) { __builtin_trap(); }\\n\',\'mismatched\',\'behavior\')\n    add(\'constructor-marker-exit\',source+\'\\n#include <unistd.h>\\n__attribute__((constructor)) static void early(void) { const char m[]="ACP_V2_LOAD_OK\\\\nACP_V2_CALL\\\\n"; write(2,m,sizeof(m)-1); _exit(7); }\\n\',\'mismatched\',\'behavior\')\n    add(\'constructor-crash\',source+\'\\n__attribute__((constructor)) static void crash(void) { __builtin_trap(); }\\n\',\'mismatched\',\'behavior\')\n    sentinel=destination/\'host-only-sentinel.h\'\n    plan.add(\'host-only-sentinel.h\',raw=b\'#define ACP_HOST_ONLY_SENTINEL_1507 1\\n\')\n    add(\'macro-host-include\',\'#define ACP_HASH #\\nACP_HASH include "\'+str(sentinel.absolute())+\'"\\n\'+source,\'refused\',\'declarations\')\n    add(\'private-source-include\',\'#include "/work/expected.c"\\n\',\'build-failed\',\'preprocess\')\n    add(\'private-header-include\',\'#include "/work/original.h"\\n\',\'build-failed\',\'preprocess\')\n    manifest={\'schemaVersion\':3,\'controls\':controls}\n    plan.add_json(\'manifest.json\',manifest)\n    # Every control, sentinel, directory and manifest is reserved before output.\n    plan.execute(destination)\n    return controls\n\n\ndef control_policy():\n    """Reviewed finite control coverage, independent of a produced manifest."""\n    return {\'baseline\': {\'expected\': \'matched\', \'stage\': \'behavior\'}, \'renamed\': {\'expected\': \'matched\', \'stage\': \'behavior\'}, \'anonymous\': {\'expected\': \'matched\', \'stage\': \'behavior\'}, \'two-hop-alias\': {\'expected\': \'matched\', \'stage\': \'behavior\'}, \'alias-parameter-callback-fields\': {\'expected\': \'matched\', \'stage\': \'behavior\'}, \'missing-fold\': {\'expected\': \'refused\', \'stage\': \'exports\'}, \'reordered-fields\': {\'expected\': \'refused\', \'stage\': \'declarations\'}, \'equal-size-field\': {\'expected\': \'refused\', \'stage\': \'declarations\'}, \'scale-parameter\': {\'expected\': \'refused\', \'stage\': \'declarations\'}, \'signedness\': {\'expected\': \'refused\', \'stage\': \'declarations\'}, \'width\': {\'expected\': \'refused\', \'stage\': \'declarations\'}, \'callback\': {\'expected\': \'refused\', \'stage\': \'declarations\'}, \'varargs\': {\'expected\': \'refused\', \'stage\': \'declarations\'}, \'state-layout\': {\'expected\': \'refused\', \'stage\': \'declarations\'}, \'hidden-symbol\': {\'expected\': \'refused\', \'stage\': \'exports\'}, \'static-symbol\': {\'expected\': \'refused\', \'stage\': \'exports\'}, \'ms-abi\': {\'expected\': \'refused\', \'stage\': \'declarations\'}, \'packed\': {\'expected\': \'refused\', \'stage\': \'declarations\'}, \'anonymous-attribute\': {\'expected\': \'refused\', \'stage\': \'declarations\'}, \'alias-attribute\': {\'expected\': \'refused\', \'stage\': \'declarations\'}, \'asm-label\': {\'expected\': \'refused\', \'stage\': \'exports\'}, \'behavior-mutant\': {\'expected\': \'mismatched\', \'stage\': \'behavior\'}, \'overinvoke\': {\'expected\': \'mismatched\', \'stage\': \'behavior\'}, \'abnormal-runtime\': {\'expected\': \'mismatched\', \'stage\': \'behavior\'}, \'timeout\': {\'expected\': \'unknown\', \'stage\': \'behavior\'}, \'output-overflow\': {\'expected\': \'unknown\', \'stage\': \'behavior\'}, \'constructor-load-failure\': {\'expected\': \'mismatched\', \'stage\': \'behavior\'}, \'constructor-marker-exit\': {\'expected\': \'mismatched\', \'stage\': \'behavior\'}, \'constructor-crash\': {\'expected\': \'mismatched\', \'stage\': \'behavior\'}, \'macro-host-include\': {\'expected\': \'refused\', \'stage\': \'declarations\'}, \'private-source-include\': {\'expected\': \'build-failed\', \'stage\': \'preprocess\'}, \'private-header-include\': {\'expected\': \'build-failed\', \'stage\': \'preprocess\'}}\n'


class AdmittedPredicateSources(unittest.TestCase):
    def sources(self, root):
        import hashlib
        payloads={'prepare_v3.py':_PREDICATE_PREPARE_SOURCE,
                  'generate_controls_v3.py':_PREDICATE_GENERATOR_SOURCE,
                  'evaluate_candidate_v3.py':Path(e.__file__).read_bytes()}
        for name,maximum,sha in f._PREDICATE_MODULES:
            self.assertEqual(maximum,len(payloads[name]))
            self.assertEqual(sha,hashlib.sha256(payloads[name]).hexdigest())
        for name,raw in payloads.items():(root/name).write_bytes(raw)
        return {str(root/name):hashlib.sha256(raw).hexdigest() for name,raw in payloads.items()},payloads

    def captured(self, root, paths):
        with patch.object(f,'BASE',root):
            sources,captured=f._admit_execution_predicates(paths)
            policy,passed=f._bind_admitted_predicates(sources,captured,paths)
        return sources,captured,policy,passed

    def report(self, expected, stage='declarations'):
        value=report_fixture()
        admitted=expected in ('matched','mismatched','unknown')
        if expected=='mismatched':
            rows=[e.scenario_entry(o,receipt(stdout=b'authored different bytes'),True,'a'*64) for o in observations()]
        elif expected=='unknown':
            incomplete=receipt();incomplete['timedOut']=True
            rows=[e.scenario_entry(o,incomplete,True,'a'*64) for o in observations()]
        elif not admitted:
            rows=[e.scenario_entry(o) for o in observations()]
        else:rows=value['scenarios']
        value['admitted']=admitted;value['scenarios']=rows
        if not admitted:
            value['runtimeInputs']=None
            for name in e.PHASES:
                value['phases'][name]={'status':'not-attempted','reason':'authored static refusal','evidenceSha256':None}
            value['phases'][stage]['status']='failed' if expected=='build-failed' else 'refused'
        summary=e.summarize(rows,admitted);behavior=summary.pop('behaviorStatus')
        value.update(summary);value['phases']['behavior']['status']=behavior
        value['phases']['load']={'status':'unverified' if admitted else 'not-attempted','value':None}
        e.validate_exchange('report',value)
        return value

    def freeze_fixture(self, root, *, failing_baseline=False):
        import hashlib
        from test_link_inputs import LinkInputTests, pin
        paths,payloads=self.sources(root)
        paths.update(_freeze_dependency_fixture(root))
        for name in ('helper-schema.json','candidate-build-profile.json'):
            path=root/'contracts'/name;path.parent.mkdir(exist_ok=True)
            path.write_bytes((e.BASE/'contracts'/name).read_bytes())
            paths[str(path)]=hashlib.sha256(path.read_bytes()).hexdigest()
        _,_,policy,_=self.captured(root,paths)
        preflight=root/'preflight';preflight.mkdir();(preflight/'controls').mkdir()
        helper=preflight/'record_identity_probe';helper.write_bytes(b'authored inert helper')
        controls=[];rows=[]
        for name,entry in policy().items():
            source=preflight/'controls'/(name+'.c');source.write_bytes(('authored '+name).encode())
            source_sha=hashlib.sha256(source.read_bytes()).hexdigest()
            controls.append({'name':name,'path':str(source),'sha256':source_sha,**entry})
            directory=preflight/'receipts'/name;directory.mkdir(parents=True)
            evidence=directory/'synthetic.json';evidence.write_bytes(('authored evidence '+name).encode())
            evidence_sha=hashlib.sha256(evidence.read_bytes()).hexdigest()
            expected='mismatched' if failing_baseline and name=='baseline' else entry['expected']
            report=self.report(expected,entry['stage']);report['candidateSha256']=source_sha
            report['evidenceFiles']={'synthetic.json':evidence_sha}
            for row in report['scenarios']:
                if row['evidenceSha256'] is not None:row['evidenceSha256']=evidence_sha
            e.validate_exchange('report',report)
            report=_freeze_report_root(report,root)
            target=directory/'receipt.json';target.write_text(json.dumps(report))
            rows.append({'name':name,'expected':entry['expected'],'expectedStage':entry['stage'],'passed':True,
                         'receipt':str(target),'receiptSha256':hashlib.sha256(target.read_bytes()).hexdigest(),
                         'runtimeRequestCount':report['runtimeRequestCount'],
                         'completedScenarioProcessCount':report['completedScenarioProcessCount'],
                         'unknownScenarioProcessCount':report['unknownScenarioProcessCount']})
        (preflight/'controls/manifest.json').write_text(json.dumps({'schemaVersion':3,'controls':controls}))
        matrix={'schemaVersion':3,'status':'preflight-only-independent-review-required','freezeCreated':False,
                'allControlsPassed':True,'executionDependenciesUnchanged':True,'rows':rows}
        e.validate_exchange('matrix',matrix);(preflight/'matrix.json').write_text(json.dumps(matrix))
        checkpoint=root/'source.json';checkpoint.write_text(json.dumps({'schemaVersion':3,'files':paths}))
        bindings={'schemaVersion':3,'sourceCheckpointSha256':hashlib.sha256(checkpoint.read_bytes()).hexdigest(),
                  'initialSha256':paths,'helperCopySha256':hashlib.sha256(helper.read_bytes()).hexdigest(),
                  'helperSchemaSha256':paths[str(root/'contracts/helper-schema.json')],'helperSchemaVersion':3}
        e.validate_exchange('execution-bindings',bindings)
        (preflight/'execution-bindings.json').write_text(json.dumps(bindings))
        # Reuse the existing inert producer fixture, not a schema/qualification stub.
        fixture=LinkInputTests();self.addCleanup(fixture.doCleanups);fixture.setUp()
        toolchain=pin.collect_pin(fixture.manifest,fixture.root)
        e.validate_exchange('toolchain-pin',toolchain)
        (root/'toolchain.json').write_text(json.dumps(toolchain))
        for name in ('review.md','acceptance.md','qualification.md'):(root/name).write_text('UNQUALIFIED fixture')
        return (preflight,root/'review.md',root/'not-created',root/'toolchain.json',root/'acceptance.md',
                checkpoint,root/'qualification.md'),paths,payloads

    def test_actual_predicate_generation_keeps_record_shape_and_all_five_pure_outcomes(self):
        with tempfile.TemporaryDirectory(dir=static_temp('static-process-correction-001')) as temporary:
            root=Path(temporary);paths,_=self.sources(root);other=root/'other.py';other.write_bytes(b'never retained')
            paths[str(other)]=f.hashlib.sha256(b'never retained').hexdigest()
            sources,captured,policy,passed=self.captured(root,paths)
            self.assertEqual({str(root/name) for name,_,_ in f._PREDICATE_MODULES},set(captured))
            self.assertEqual({'path','relative','identity','sha256','size','parents'},set(sources[str(other)]))
            for name,(record,raw) in captured.items():
                self.assertIs(record,sources[name]);self.assertEqual(record['size'],len(raw))
            table=policy();self.assertEqual(32,len(table))
            for kind,stage in (('matched','behavior'),('mismatched','behavior'),('unknown','behavior'),
                               ('refused','declarations'),('build-failed','preprocess')):
                report=self.report(kind,stage)
                self.assertTrue(passed({'expected':kind,'stage':stage},report))
                self.assertFalse(passed({'expected':'matched','stage':stage},self.report('refused',stage)))
            self.assertEqual({},policy.__globals__['__builtins__']);self.assertEqual({},passed.__globals__['__builtins__'])
            self.assertEqual('control_policy',policy.__code__.co_qualname)
            self.assertEqual('control_passed',passed.__code__.co_qualname)

    def test_real_freeze_uses_captured_A_with_pathname_B_and_poisoned_imports_then_refuses_qualification(self):
        from types import SimpleNamespace
        for bad_report in (False,True):
            with tempfile.TemporaryDirectory(dir=static_temp('static-process-correction-001')) as temporary:
                root=Path(temporary)/'build/acp-decomp-effectiveness/callable-library-v3';root.mkdir(parents=True)
                args,paths,payloads=self.freeze_fixture(root,failing_baseline=bad_report)
                real_admit=f._admit_execution_predicates;real_bind=f._bind_admitted_predicates;seen=[]
                def admit(checkpoint):
                    result=real_admit(checkpoint)
                    for name,raw in payloads.items():(root/name).write_bytes(raw.replace(b'control_passed',b'control_forged')+b'\n# pathname B\n')
                    return result
                def bind(*values):
                    handles=real_bind(*values);seen.append(handles)
                    self.assertFalse(handles[1]({'expected':'matched'},self.report('refused')))
                    for name,raw in payloads.items():(root/name).write_bytes(raw)
                    return handles
                _,_,actual_policy,_=self.captured(root,paths)
                expected_policy=actual_policy()
                poison=SimpleNamespace(control_policy=lambda:expected_policy,control_passed=lambda *unused:True)
                with patch.object(f,'BASE',root),patch.object(f,'execution_source_paths',return_value=set(paths)), \
                        patch.object(f,'_admit_execution_predicates',side_effect=admit), \
                        patch.object(f,'_bind_admitted_predicates',side_effect=bind), \
                        patch.dict(sys.modules,{name:poison for name in ('prepare_v3','generate_controls_v3','evaluate_candidate_v3')}), \
                        patch.object(f,'require_qualified_pin',wraps=f.require_qualified_pin) as qualification:
                    message='control expectation/result drift' if bad_report else 'static-only toolchain pin'
                    with self.assertRaisesRegex(ValueError,message):f.freeze(*args)
                self.assertEqual(1,len(seen));self.assertFalse(args[2].exists())
                if bad_report:qualification.assert_not_called()
                else:qualification.assert_called_once()
                self.assertTrue(all((root/name).read_bytes()==raw for name,raw in payloads.items()))
                # Restored matching bytes do not attest an undetectable OS metadata ABA.
                restored=f.admit_files(paths,root=root)['files']
                self.assertEqual(paths,{name:row['sha256'] for name,row in restored.items()})

    def test_predicate_missing_generation_and_original_record_checkpoint_joins_precede_compile(self):
        import hashlib
        with tempfile.TemporaryDirectory(dir=static_temp('static-process-correction-001')) as temporary:
            root=Path(temporary);paths,payloads=self.sources(root)
            for missing in tuple(paths):
                with self.subTest(missing=missing),patch.object(f,'BASE',root), \
                        patch.object(f,'compile',create=True,side_effect=AssertionError('no compile')) as compiler:
                    with self.assertRaisesRegex(ValueError,'missing predicate'):f._admit_execution_predicates({k:v for k,v in paths.items() if k!=missing})
                    compiler.assert_not_called()
            with patch.object(f,'BASE',root):sources,captured=f._admit_execution_predicates(paths)
            for fault in ('checkpoint','record','raw','missing-capture'):
                current=dict(paths);owned=dict(sources);retained=dict(captured)
                selected=str(root/'evaluate_candidate_v3.py');record,raw=retained[selected]
                if fault=='checkpoint':current[selected]='0'*64
                elif fault=='record':owned[selected]=dict(record)
                elif fault=='raw':retained[selected]=(record,b'X'+raw[1:])
                else:del retained[selected]
                with self.subTest(fault=fault),patch.object(f,'BASE',root), \
                        patch.object(f,'compile',create=True,side_effect=AssertionError('all joins precede compile')) as compiler:
                    with self.assertRaisesRegex(ValueError,'predicate'):f._bind_admitted_predicates(owned,retained,current)
                    compiler.assert_not_called()
            for name,raw in payloads.items():
                changed=raw.replace(b'control_passed',b'control_forged') if b'control_passed' in raw else b'X'+raw[1:]
                self.assertEqual(len(raw),len(changed));(root/name).write_bytes(changed)
                forged=dict(paths);forged[str(root/name)]=hashlib.sha256(changed).hexdigest()
                with self.subTest(generation=name),patch.object(f,'BASE',root), \
                        patch.object(f,'compile',create=True,side_effect=AssertionError('unsupported generation before compile')) as compiler:
                    with self.assertRaisesRegex(ValueError,'unsupported predicate source generation'):f._admit_execution_predicates(forged)
                    compiler.assert_not_called()
                (root/name).write_bytes(raw)

    def test_predicate_prebody_caps_nonregular_and_total_budget_refuse_without_retention(self):
        with tempfile.TemporaryDirectory(dir=static_temp('static-process-correction-001')) as temporary:
            root=Path(temporary);paths,payloads=self.sources(root);target=root/'prepare_v3.py'
            for size in (0,7055,7057):
                target.write_bytes(b'x'*size)
                with self.subTest(size=size),patch.object(f,'BASE',root), \
                        patch.object(f,'_consume',side_effect=AssertionError('no body retention')) as consume:
                    with self.assertRaisesRegex(ValueError,'predicate source exact byte bound'):f._admit_execution_predicates(paths)
                    consume.assert_not_called()
            target.unlink();target.mkdir()
            with patch.object(f,'BASE',root),patch.object(f,'_consume',side_effect=AssertionError('no special payload')) as consume:
                with self.assertRaisesRegex(ValueError,'regular file required'):f._admit_execution_predicates(paths)
                consume.assert_not_called()
            target.rmdir();target.write_bytes(payloads['prepare_v3.py'])
            budget=f.TreeBudget
            with patch.object(f,'BASE',root),patch.object(f,'TreeBudget',side_effect=lambda:budget(bytes=7055)), \
                    patch.object(f,'_consume',side_effect=AssertionError('reservation before retained bytes')) as consume:
                with self.assertRaisesRegex(ValueError,'payload budget'):f._admit_execution_predicates(paths)
                consume.assert_not_called()

    def test_predicate_compile_and_direct_shape_refuse_without_executing_modules_or_partial_pair(self):
        with tempfile.TemporaryDirectory(dir=static_temp('static-process-correction-001')) as temporary:
            root=Path(temporary);paths,_=self.sources(root)
            with patch.object(f,'BASE',root):sources,captured=f._admit_execution_predicates(paths)
            failure=SyntaxError('authored compiler refusal')
            with patch.object(f,'BASE',root),patch.object(f,'compile',create=True,side_effect=failure), \
                    patch.object(f,'FunctionType',side_effect=AssertionError('no partial pair')) as functions:
                with self.assertRaises(SyntaxError) as caught:f._bind_admitted_predicates(sources,captured,paths)
                self.assertIs(failure,caught.exception);functions.assert_not_called()
            real_compile=compile
            def no_module_body(raw,filename,*args,**kwargs):
                return real_compile(raw+b'\nraise AssertionError("module body was executed")\n',filename,*args,**kwargs)
            with patch.object(f,'BASE',root),patch.object(f,'compile',create=True,side_effect=no_module_body):
                policy,passed=f._bind_admitted_predicates(sources,captured,paths)
                self.assertEqual(32,len(policy()))
                self.assertFalse(passed({'expected':'matched'},self.report('refused')))
            allocation=MemoryError('authored second function allocation');real_function=f.FunctionType;created=[]
            def functions(*args,**kwargs):
                if created:raise allocation
                result=real_function(*args,**kwargs);created.append(result);return result
            with patch.object(f,'BASE',root),patch.object(f,'FunctionType',side_effect=functions) as constructing:
                with self.assertRaises(MemoryError) as caught:f._bind_admitted_predicates(sources,captured,paths)
                self.assertIs(allocation,caught.exception);self.assertEqual(2,constructing.call_count)
            self.assertEqual(1,len(created),'test spy is the only holder of the unpublished first function')
            shapes=(
                ('evaluate_candidate_v3.py', 'def control_passed(control): return True\n'),
                ('evaluate_candidate_v3.py', 'def control_passed(control,report): return global_claim\n'),
                ('evaluate_candidate_v3.py', 'def control_passed(control,report): return report.get("accepted")\n'),
                ('evaluate_candidate_v3.py', 'def control_passed(control,report,*args): return True\n'),
                ('evaluate_candidate_v3.py', 'def control_passed(control,report): yield True\n'),
                ('evaluate_candidate_v3.py', 'def control_passed(control,report):\n def retain(): return control\n return retain\n'),
                ('evaluate_candidate_v3.py', 'async def control_passed(control,report): return True\n'),
                ('evaluate_candidate_v3.py', 'def holder():\n def control_passed(control,report): return True\n return control_passed\n'),
                ('evaluate_candidate_v3.py', 'def control_passed(control,report): return True\ndef control_passed(control,report): return False\n'),
                ('prepare_v3.py', 'def control_passed(control,report): return True\n'),
            )
            for module,source in shapes:
                def compiler(raw,filename,*args,**kwargs):
                    return real_compile(source if Path(filename).name==module else raw,filename,*args,**kwargs)
                with self.subTest(module=module,shape=source),patch.object(f,'BASE',root), \
                        patch.object(f,'compile',create=True,side_effect=compiler), \
                        patch.object(f,'FunctionType',side_effect=AssertionError('shape fails before functions')) as functions:
                    with self.assertRaisesRegex(ValueError,'predicate'):f._bind_admitted_predicates(sources,captured,paths)
                    functions.assert_not_called()

    def test_predicate_acquisition_close_failure_keeps_exact_error_and_no_usable_capture(self):
        with tempfile.TemporaryDirectory(dir=static_temp('static-process-correction-001')) as temporary:
            root=Path(temporary);paths,_=self.sources(root);real_record=f._record;real_close=f.os.close
            target=[];closed=[];failure=OSError('authored source descriptor close')
            def record(path,relative,metadata,descriptor,*args,**kwargs):
                result=real_record(path,relative,metadata,descriptor,*args,**kwargs)
                if path==root/'prepare_v3.py':target.append(descriptor)
                return result
            def close(descriptor):
                real_close(descriptor)
                if target and descriptor==target[0]:
                    closed.append(descriptor);raise failure
            with patch.object(f,'BASE',root),patch.object(f,'_record',side_effect=record), \
                    patch.object(f.os,'close',side_effect=close), \
                    patch.object(f,'compile',create=True,side_effect=AssertionError('no usable pair after close')) as compiler:
                with self.assertRaises(OSError) as caught:f._admit_execution_predicates(paths)
                self.assertIs(failure,caught.exception);compiler.assert_not_called()
            self.assertEqual(target,closed)


class FreezeDependencyCapture(unittest.TestCase):
    def fixture(self):
        directory=tempfile.TemporaryDirectory(dir=static_temp('static-process-correction-001'))
        self.addCleanup(directory.cleanup);root=Path(directory.name)
        paths=_freeze_dependency_fixture(root)
        return root,paths

    def test_freezer_import_is_project_inert_and_untyped_json_keeps_duplicate_refusal(self):
        import builtins
        from types import ModuleType
        source=Path(f.__file__);real_import=builtins.__import__;observed=[]
        def imports(name,*args,**kwargs):
            if name in ('bounded_runtime','build_contract','interface_gate_v3','evaluate_candidate_v3'):
                observed.append(name);raise AssertionError('ordinary project import before admission')
            return real_import(name,*args,**kwargs)
        namespace={'__name__':'inert_freezer','__file__':str(source)}
        code=compile(source.read_bytes(),str(source),'exec')
        with patch.object(builtins,'__import__',side_effect=imports):exec(code,namespace)
        self.assertEqual([],observed)
        self.assertEqual(f.BASE,namespace['BASE'])
        self.assertEqual({'ok':1},namespace['_decode_json'](b'{"ok":1}'))
        with self.assertRaisesRegex(ValueError,'duplicate contract key'):
            namespace['_decode_json'](b'{"x":1,"x":2}')
        self.assertIsNone(namespace['_FREEZE_DEPENDENCY_SCOPE'].get())

    def test_all_four_original_captures_precede_all_compile_and_first_body(self):
        import hashlib
        root,_=self.fixture();events=[];actual_record=f._record;actual_compile=compile;actual_exec=exec
        def record(*args,**kwargs):
            value=actual_record(*args,**kwargs);events.append(('capture',value['path'].name));return value
        def compiled(raw,*args,**kwargs):
            events.append(('compile',hashlib.sha256(raw).hexdigest()));return actual_compile(raw,*args,**kwargs)
        def executed(code,globals):events.append(('body',Path(globals['__file__']).name));return actual_exec(code,globals)
        with patch.object(f,'BASE',root),patch.object(f,'_record',side_effect=record), \
                patch.object(f,'compile',create=True,side_effect=compiled),patch.object(f,'exec',create=True,side_effect=executed):
            with f._freeze_dependency_scope() as owner:
                validator=owner.validator();self.assertIs(validator,owner.validator())
                self.assertEqual('READY',owner.state)
                records=f.admit_files(owner.records,root=root)['files']
                owner.require_sources(records,{name:row['sha256']for name,row in records.items()})
        self.assertEqual(['capture']*4+['compile']*4+['body']*4+['capture']*4,[kind for kind,_ in events])
        self.assertEqual([sha for _,_,sha in f._FREEZE_DEPENDENCY_SOURCES],[value for kind,value in events if kind=='compile'])
        self.assertEqual('CLOSED',owner.state)
        self.assertTrue(all(alias not in sys.modules for alias in owner.aliases))

    def test_captured_A_survives_path_B_and_public_cache_poison_without_reimport(self):
        from types import ModuleType
        root,_=self.fixture();originals={name:(root/(name+'.py')).read_bytes()for name,_,_ in f._FREEZE_DEPENDENCY_SOURCES}
        poison=ModuleType('poison');real_compile=compile;changed=[]
        def compiling(raw,*args,**kwargs):
            if not changed:
                for name in originals:(root/(name+'.py')).write_bytes(b'raise AssertionError("B must not execute")')
                changed.append(True)
            return real_compile(raw,*args,**kwargs)
        with patch.object(f,'BASE',root),patch.object(f,'compile',create=True,side_effect=compiling), \
                patch.dict(sys.modules,{name:poison for name in (*originals,'freeze_v3')}):
            with f._freeze_dependency_scope() as owner:
                validator=owner.validator();module=owner.modules['evaluate_candidate_v3']
                self.assertIs(validator.__globals__,module.__dict__)
                self.assertIsNot(module,poison)
                self.assertIs(module.summarize.__globals__,module.__dict__)
                self.assertIs(module.worker_execution_complete,owner.modules['bounded_runtime'].worker_execution_complete)
                for name,raw in originals.items():(root/(name+'.py')).write_bytes(raw)
                with patch.object(f.importlib.util,'spec_from_file_location',side_effect=AssertionError('no pathname loader')):
                    self.assertIs(validator,owner.validator())
                self.assertEqual({'x':1},owner.modules['build_contract']._pairs([('x',1)]))
                with self.assertRaisesRegex(ValueError,'duplicate contract key'):
                    owner.modules['build_contract']._pairs([('x',1),('x',2)])
        self.assertTrue(changed)
        self.assertTrue(all((root/(name+'.py')).read_bytes()==raw for name,raw in originals.items()))

        # Real captured bodies must not derive a different BASE through a post-capture symlink.
        root,_=self.fixture();other=root/'other';other.mkdir();real_exec=exec;fired=[]
        def execute_with_alias(code,globals):
            if not fired:
                path=root/'build_contract.py';path.rename(other/'build_contract.py');path.symlink_to(other/'build_contract.py')
                fired.append(True)
            return real_exec(code,globals)
        with patch.object(f,'BASE',root),patch.object(f,'exec',create=True,side_effect=execute_with_alias):
            with self.assertRaisesRegex(ValueError,'defining source root'):
                with f._freeze_dependency_scope() as owner:owner.validator()
            self.assertEqual([True],fired);self.assertEqual(set(),owner.ready)

    def test_each_bad_source_and_capture_close_failure_refuse_before_any_compile(self):
        for name,_,_ in f._FREEZE_DEPENDENCY_SOURCES:
            for mutation in ('missing','size','short','same-size','symlink'):
                root,_=self.fixture();path=root/(name+'.py');raw=path.read_bytes()
                if mutation=='missing':path.unlink()
                elif mutation=='size':path.write_bytes(raw+b'x')
                elif mutation=='short':path.write_bytes(raw[:-1])
                elif mutation=='same-size':path.write_bytes(b'#'+raw[1:])
                else:
                    retained=root/(name+'.retained');path.rename(retained);path.symlink_to(retained)
                with self.subTest(name=name,mutation=mutation),patch.object(f,'BASE',root), \
                        patch.object(f,'compile',create=True,side_effect=AssertionError('no unauthenticated compile')) as compiler:
                    with self.assertRaises((OSError,ValueError)):
                        with f._freeze_dependency_scope() as owner:owner.validator()
                    compiler.assert_not_called();self.assertEqual('CLOSED',owner.state)
                    self.assertFalse(owner.aliases)
        # A scripted special-file metadata result is refused by the real open helper;
        # no FIFO or host attacker is created and the payload reader is never reached.
        import os,stat
        from types import SimpleNamespace
        root,_=self.fixture();actual_open=f.os.open;actual_stat=f.os.fstat;special_fd=[]
        def opened_special(name,flags,*args,**kwargs):
            fd=actual_open(name,flags,*args,**kwargs)
            if name=='build_contract.py':
                self.assertTrue(flags&os.O_NONBLOCK);special_fd.append(fd)
            return fd
        def special_metadata(fd):
            value=actual_stat(fd)
            if special_fd and fd==special_fd[0]:
                return SimpleNamespace(st_mode=stat.S_IFIFO|0o600)
            return value
        with patch.object(f,'BASE',root),patch.object(f.os,'open',side_effect=opened_special), \
                patch.object(f.os,'fstat',side_effect=special_metadata),patch.object(f.os,'read',side_effect=AssertionError('no special payload')) as payload:
            with self.assertRaisesRegex(ValueError,'regular file required'):
                with f._freeze_dependency_scope() as owner:owner.validator()
            payload.assert_not_called()
        root,_=self.fixture();real_close=f.os.close;real_open=f._open_regular;held=[];primary=OSError('authored capture close')
        def opened(*args,**kwargs):fd=real_open(*args,**kwargs);held.append(fd);return fd
        def close(fd):
            real_close(fd)
            if held and fd==held[0]:held.pop(0);raise primary
        with patch.object(f,'BASE',root),patch.object(f,'_open_regular',side_effect=opened), \
                patch.object(f.os,'close',side_effect=close),patch.object(f,'compile',create=True) as compiler:
            with self.assertRaises(OSError) as caught:
                with f._freeze_dependency_scope() as owner:owner.validator()
            self.assertIs(primary,caught.exception);compiler.assert_not_called()

    def test_real_dataclasses_private_contract_and_exact_three_export_self_facade(self):
        root,_=self.fixture();read=f.read_regular;reads=[]
        def reading(path,maximum):reads.append((path,maximum));return read(path,maximum)
        with patch.object(f,'BASE',root),patch.object(f,'read_regular',side_effect=reading):
            with f._freeze_dependency_scope() as owner:
                validator=owner.validator();module=owner.modules['evaluate_candidate_v3'];contract=owner.modules['build_contract']
                self.assertEqual(module.CapturedArtifact.__module__,module.__name__)
                self.assertIs(sys.modules[module.__name__],module)
                self.assertIs(owner.facade.read_regular,f.read_regular)
                self.assertIs(owner.facade.admit_files,f.admit_files);self.assertIs(owner.facade.TreeBudget,f.TreeBudget)
                snapshot=contract._ProfileSnapshot((root/'contracts/candidate-build-profile.json').read_bytes())
                with contract.profile_scope(snapshot):
                    artifact=module.CapturedArtifact(b'authored inert bytes')
                    self.assertEqual(artifact.sha256,module.hashlib.sha256(artifact.data).hexdigest())
                import build_contract as ambient
                with self.assertRaisesRegex(ValueError,'owned profile snapshot'):
                    with contract.profile_scope(ambient._ProfileSnapshot(snapshot.raw)):self.fail('foreign snapshot admitted')
                copied=module.CopiedInput(Path('/authored/input'),(3,4,0o400),'a'*64)
                self.assertEqual({'device':3,'inode':4,'mode':0o400,'sha256':'a'*64},copied.pin())
                binding={'schemaVersion':3,'sourceCheckpointSha256':'a'*64,'initialSha256':{'synthetic':'d'*64},
                         'helperCopySha256':'b'*64,'helperSchemaSha256':'c'*64,'helperSchemaVersion':3}
                self.assertEqual(binding,validator('execution-bindings',binding))
                self.assertEqual([(root/'contracts/execution-bindings-schema.json',1048576)],reads)
                router=owner.importer('evaluate_candidate_v3')
                self.assertIs(owner.facade,router('freeze_v3',fromlist=('read_regular',)))
                for name,fromlist,level in [('bounded_runtime.extra',('x',),0),('bounded_runtime',('*',),0),
                        ('bounded_runtime',('unreviewed',),0),('build_contract',('profile',),1)]:
                    with self.assertRaises(ValueError):router(name,fromlist=fromlist,level=level)

    def test_compile_body_alias_and_cleanup_faults_keep_primary_and_never_publish_partial_graph(self):
        from types import ModuleType
        for stage in ('compile','body','collision','changed-cleanup'):
            root,_=self.fixture();primary=MemoryError('authored '+stage);real_exec=exec;foreign=ModuleType('foreign');aliases=[]
            def execute(code,globals):
                if stage=='body':raise primary
                return real_exec(code,globals)
            with self.subTest(stage=stage),patch.object(f,'BASE',root):
                if stage=='compile':
                    with patch.object(f,'compile',create=True,side_effect=primary),patch.object(f,'exec',create=True) as bodies:
                        with self.assertRaises(MemoryError) as caught:
                            with f._freeze_dependency_scope() as owner:owner.validator()
                        self.assertIs(primary,caught.exception);bodies.assert_not_called()
                elif stage=='body':
                    with patch.object(f,'exec',create=True,side_effect=execute):
                        with self.assertRaises(MemoryError) as caught:
                            with f._freeze_dependency_scope() as owner:owner.validator()
                        self.assertIs(primary,caught.exception);self.assertIsNone(owner.selected)
                elif stage=='collision':
                    with self.assertRaisesRegex(ValueError,'alias collision'):
                        with f._freeze_dependency_scope() as owner:
                            alias='_v3_freeze_'+format(id(owner),'x')+'_build_contract';sys.modules[alias]=foreign;aliases.append(alias)
                            owner.validator()
                    self.assertIs(sys.modules[alias],foreign)
                else:
                    with self.assertRaisesRegex(ValueError,'cleanup identity unknown'):
                        with f._freeze_dependency_scope() as owner:
                            owner.validator();alias=next(iter(owner.aliases));sys.modules[alias]=foreign;aliases.append(alias)
                    self.assertIs(sys.modules[alias],foreign)
                self.assertIsNone(f._FREEZE_DEPENDENCY_SCOPE.get());self.assertEqual('CLOSED',owner.state)
                self.assertFalse(any(sys.modules.get(alias)is module for alias,module in owner.aliases.items()))
                for alias in aliases:
                    if sys.modules.get(alias)is foreign:del sys.modules[alias]

        for compile_fails in (False,True):
            root,_=self.fixture();primary=MemoryError('authored compile primary');cleanup=OSError('authored lock release')
            with patch.object(f,'BASE',root):
                with self.assertRaises((MemoryError,OSError)) as caught:
                    with f._freeze_dependency_scope() as owner:
                        real_lock=owner.lock
                        class ReleaseFailure:
                            def acquire(self,blocking):return real_lock.acquire(blocking)
                            def release(self):real_lock.release();raise cleanup
                        owner.lock=ReleaseFailure()
                        if compile_fails:
                            with patch.object(f,'compile',create=True,side_effect=primary):owner.validator()
                        else:owner.validator()
                self.assertIs(primary if compile_fails else cleanup,caught.exception)
                self.assertEqual('CLOSED',owner.state);self.assertIsNone(f._FREEZE_DEPENDENCY_SCOPE.get())
                self.assertFalse(any(sys.modules.get(key)is module for key,module in owner.aliases.items()))
        # Alias and token cleanup failures remain secondary to the original body.
        root,_=self.fixture();context=f._FREEZE_DEPENDENCY_SCOPE;primary=MemoryError('authored body primary')
        cleanup=OSError('authored reset refusal');foreign=ModuleType('retained foreign');aliases=[]
        class ResetFailure:
            def get(self):return context.get()
            def set(self,value):return context.set(value)
            def reset(self,token):context.reset(token);raise cleanup
        with patch.object(f,'BASE',root),patch.object(f,'_FREEZE_DEPENDENCY_SCOPE',ResetFailure()):
            with self.assertRaises(MemoryError) as caught:
                with f._freeze_dependency_scope() as owner:
                    owner.validator();alias=next(iter(owner.aliases));aliases.append(alias);sys.modules[alias]=foreign
                    raise primary
            self.assertIs(primary,caught.exception);self.assertIsNone(context.get())
            self.assertIs(sys.modules[alias],foreign)
            self.assertFalse(any(sys.modules.get(key)is module for key,module in owner.aliases.items()))
        for alias in aliases:
            if sys.modules.get(alias)is foreign:del sys.modules[alias]

    def test_real_report_reference_and_completion_semantics_survive_the_private_graph(self):
        root,_=self.fixture()
        with patch.object(f,'BASE',root),f._freeze_dependency_scope() as owner:
            validator=owner.validator();module=owner.modules['evaluate_candidate_v3'];runtime=owner.modules['bounded_runtime']
            report=_freeze_report_root(report_fixture(),root);self.assertEqual(report,validator('report',report))
            for mutation in ('order','count','completion','profile','parser','target','library','evidence'):
                changed=deepcopy(report);process=changed['scenarios'][0]['process']
                if mutation=='order':changed['scenarios'][0],changed['scenarios'][1]=changed['scenarios'][1],changed['scenarios'][0]
                elif mutation=='count':changed['matchedScenarioProcessCount']=0
                elif mutation=='completion':process['workerTerminationVerified']=False
                elif mutation=='profile':process['launchInputPins'][str(root/'contracts/candidate-build-profile.json')]['sha256']='f'*64
                elif mutation=='parser':process['workerProofRawHex']='00'
                elif mutation=='target':process['workerProofBindings']['targetSha256']='f'*64
                elif mutation=='library':process['workerProofBindings']['expected']['library']['sha256']='f'*64
                else:changed['scenarios'][0]['evidenceSha256']='f'*64
                with self.subTest(mutation=mutation),self.assertRaises(Exception):validator('report',changed)
            # Actual reference admission, including the distinct order check outside validate_exchange.
            (root/'private').mkdir();(root/'private/original.c').write_bytes(b'authored original source')
            prep=root/'preparation';(prep/'reference').mkdir(parents=True)
            caller=prep/'caller';caller.write_bytes(b'authored inert caller')
            library=prep/'reference/libcandidate.so';library.write_bytes(b'authored inert library')
            pins=runtime._pin_files((caller,library));rows=[]
            for index,family in enumerate(module.SCENARIO_FAMILIES):
                raw=_freeze_process_root(receipt(7,caller=str(caller),caller_sha=module.digest(caller),input_pins=pins),root)
                path=prep/('reference-process-'+str(index)+'.json')
                path.write_text(json.dumps({'status':'failed','execution':module.public_result(raw)}))
                rows.append({'id':index,'family':family,'process':module.process_observation(raw),'evidenceSha256':module.digest(path)})
            value={'schemaVersion':3,'sourceSha256':module.digest(root/'private/original.c'),
                   'callerSha256':module.digest(caller),'callerPath':str(caller),'libraryPath':str(library),
                   'librarySha256':module.digest(library),'profileSha256':module.digest(root/'contracts/candidate-build-profile.json'),
                   'observations':rows}
            path=prep/'reference-observations.json';path.write_text(json.dumps(value))
            self.assertEqual(value,validator('reference-observations',value))
            self.assertEqual(24,len(module.validated_observations(path,caller,prep)))
            changed=deepcopy(value);changed['observations'][0],changed['observations'][1]=changed['observations'][1],changed['observations'][0]
            self.assertEqual(changed,validator('reference-observations',changed))
            path.write_text(json.dumps(changed))
            with self.assertRaisesRegex(ValueError,'scenario identity drift'):module.validated_observations(path,caller,prep)

    def test_invocation_context_closed_failed_wrong_root_busy_and_cross_owner_are_not_reused(self):
        from contextvars import copy_context
        root,_=self.fixture();previous=f._FREEZE_DEPENDENCY_SCOPE.get()
        with patch.object(f,'BASE',root):
            with f._freeze_dependency_scope() as owner:
                inherited=copy_context()
                with self.assertRaisesRegex(ValueError,'nested'): 
                    with f._freeze_dependency_scope():self.fail('nested owner admitted')
                owner.lock.acquire()
                try:
                    with self.assertRaisesRegex(ValueError,'busy'):owner.validator()
                    self.assertEqual('NEW',owner.state)
                finally:owner.lock.release()
                owner.validator();self.assertEqual('READY',owner.state)
                with patch.object(f,'get_ident',return_value=owner.thread+1):
                    with self.assertRaises(ValueError):owner.validator()
                with patch.object(f,'BASE',root/'other'):
                    with self.assertRaises(ValueError):owner.validator()
            self.assertIs(previous,f._FREEZE_DEPENDENCY_SCOPE.get())
            with self.assertRaises(ValueError):inherited.run(f.validate_exchange,'execution-bindings',{})
            with f._freeze_dependency_scope() as other:
                other.validator();self.assertIsNot(owner,other)
                self.assertTrue(set(owner.aliases).isdisjoint(other.aliases))
            with f._freeze_dependency_scope() as failed:
                error=ValueError('authored compile refusal')
                with patch.object(f,'compile',create=True,side_effect=error) as compiler:
                    with self.assertRaises(ValueError) as caught:failed.validator()
                    self.assertIs(error,caught.exception)
                    with self.assertRaises(ValueError):failed.validator()
                    self.assertEqual(1,compiler.call_count)

    def test_real_freeze_dependency_join_and_qualification_refusal_never_create_output(self):
        root,_=self.fixture()
        # Reuse the existing genuine predicate/report fixture, with private-root completion pins.
        case=AdmittedPredicateSources(methodName='runTest')
        composed=root/'build/acp-decomp-effectiveness/callable-library-v3';composed.mkdir(parents=True)
        args,paths,_=case.freeze_fixture(composed)
        with patch.object(f,'BASE',composed),patch.object(f,'execution_source_paths',return_value=set(paths)), \
                patch.object(f,'require_qualified_pin',wraps=f.require_qualified_pin) as qualification:
            with self.assertRaisesRegex(ValueError,'static-only toolchain pin'):f.freeze(*args)
            qualification.assert_called_once();self.assertFalse(args[2].exists())
        case.doCleanups()
        with patch.object(f,'BASE',root),f._freeze_dependency_scope() as owner:
            owner.validator();sources=f.admit_files(owner.records,root=root)['files'];checkpoint={k:v['sha256']for k,v in sources.items()}
            for name,_,_ in f._FREEZE_DEPENDENCY_SOURCES:
                changed=deepcopy(sources);changed[str(root/(name+'.py'))]['identity']=(0,)*6
                with self.subTest(name=name),self.assertRaisesRegex(ValueError,'original checkpoint join'):
                    owner.require_sources(changed,checkpoint)


if __name__=='__main__':unittest.main()
