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


class SchemaMigration(unittest.TestCase):
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


if __name__=='__main__':unittest.main()
