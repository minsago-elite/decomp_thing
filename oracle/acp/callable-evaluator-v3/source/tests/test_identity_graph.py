"""Pure public descriptor fixtures. Never compiles or invokes native code."""
import copy
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import interface_gate_v3 as gate


def integer(kind='int', qualifiers=0):
    bits = 8 if 'char' in kind else 16 if 'short' in kind else 64 if 'long' in kind else 32
    return {'kind':'integer','builtinKind':kind,'bits':bits,'signed':not kind.startswith('unsigned-'),'qualifiers':qualifiers}


def reference(identity, kind='record', qualifiers=0):
    return {'kind':kind,'identity':identity,'qualifiers':qualifiers}


def function(result=None, parameters=None):
    return {'kind':'function','return':result or integer(),'parameters':parameters or [],'variadic':False,'callingConvention':'C'}


def record(identity, field_type=None):
    return {'kind':'record','identity':identity,'sizeBits':64,'alignBits':64,'fields':[{'name':'value','type':field_type or integer('long'),'offsetBits':0}]}


def receipt(nodes=None, roots=None):
    nodes = nodes or []
    return {'schemaVersion':3,'status':'supported','target':'x86_64-test','dataLayout':'e-test',
            'diagnostics':[],'interfaces':roots or {name:integer() for name in gate.REQUIRED},
            'declarationNodes':nodes,'provenance':[],
            'gccTypeBindings':[{'identity':node['identity'],'expression':('struct ' if node['kind']=='record' else 'enum ')+'type_'+str(node['identity'])} for node in nodes]}


def graph():
    roots = {name:function() for name in gate.REQUIRED}
    roots['acp_state'] = reference(1)
    roots['acp_mix'] = function(reference(2), [reference(1),reference(2)])
    return receipt([record(1),record(2)], roots)


def remap(value, mapping):
    value = copy.deepcopy(value)
    def walk(item):
        if isinstance(item, dict):
            if 'identity' in item:
                item['identity'] = mapping.get(item['identity'], item['identity'])
            for child in item.values(): walk(child)
        elif isinstance(item, list):
            for child in item: walk(child)
    walk(value)
    return value


def completed_result(stdout=b'', stderr=b'', exit_code=0):
    import hashlib
    pins={'/authored/worker':{'device':7,'inode':8,'mode':493,'sha256':'0'*64},
          '/authored/bwrap':{'device':3,'inode':4,'mode':493,'sha256':'0'*64}}
    bindings={'protocolVersion':1,'expected':{'attempt':'a'*32,'phase':'runtime','reportDevice':1,
        'reportInode':2,'reaperDevice':3,'reaperInode':4,'outerPidNsDevice':5,'outerPidNsInode':6,'targetDevice':7,'targetInode':8},
        **{key:'0'*64 for key in ('launchConfigSha256','environmentPinSha256','monitorBinarySha256','monitorSourceSha256','protocolSha256','parserSha256','manifestSha256','targetSha256')},
        'launchPinsSha256':hashlib.sha256(json.dumps(pins,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()}
    execution={'v':1,'t':'exec','s':1,'a':'a'*32,'p':'runtime','c':3,'ed':7,'ei':8,'od':7,'oi':8,
               'w':(4<<16)|(5<<8)|127,'cf':1,'dp':0,'rd':3,'ri':4,'b':[1,100,5,9,1,3]}
    termination={'v':1,'t':'term','s':2,'a':'a'*32,'p':'runtime','c':3,
                 'r':exit_code<<8 if exit_code>=0 else -exit_code,'k':'exit' if exit_code>=0 else 'signal','n':abs(exit_code)}
    raw=b''.join((json.dumps(row,separators=(',',':'))+'\n').encode() for row in (execution,termination))
    return {'workerProofRaw':raw,'bounds':{'phase':'runtime','profileSha256':'0'*64},'launchInputPins':pins,'workerProofBindings':bindings,'exitCode':exit_code,'stdout':stdout,'stderr':stderr,
            'launcherExitCode':0,'provisioningOnly':False,
            'workerTermination':{'kind':'exit' if exit_code>=0 else 'signal',
                                 'value':abs(exit_code),'rawWaitStatus':exit_code<<8 if exit_code>=0 else -exit_code},
            'workerProof':{'protocolVersion':1,'status':'verified','proofSha256':hashlib.sha256(raw).hexdigest(),
                           'fileIdentityVerified':True,'pinsUnchanged':True},
            **{key:True for key in ('launcherCreated','launcherPidIdentityVerified','scopeVerified','scopeAdmitted','captureComplete','waitComplete','cleanupVerified','rootReaped','finalAbsenceVerified','workerExecVerified','workerTerminationVerified')},
            **{key:False for key in ('timedOut','outputExceeded','infrastructureFailure')},
            'kernelScope':{'finalAbsenceVerified':True}}


class IdentityGraph(unittest.TestCase):
    def assert_unknown(self, value):
        result = gate.compare_descriptors(value, value)
        self.assertEqual(result['status'], 'unknown')
        self.assertFalse(result['accepted'])

    def test_local_ids_order_and_alias_presentations_do_not_determine_equality(self):
        expected = graph()
        actual = remap(expected, {1:91,2:7})
        actual['declarationNodes'].reverse()
        actual['gccTypeBindings'] = [{'identity':91,'expression':'anonymous_alias'}, {'identity':7,'expression':'struct renamed'}, {'identity':91,'expression':'second_alias'}]
        actual['provenance'] = [{'kind':'alias','identity':92,'name':'renamed_alias','targetIdentity':91,'underlyingDiagnosticSpelling':'public_alias'}]
        self.assertTrue(gate.compare_descriptors(expected, actual)['accepted'])

    def test_distinct_equal_layout_records_cannot_collapse(self):
        expected = graph()
        actual = remap(expected, {2:1})
        actual['declarationNodes'] = actual['declarationNodes'][:1]
        actual['gccTypeBindings'] = actual['gccTypeBindings'][:1]
        self.assertEqual(gate.compare_descriptors(expected, actual)['status'], 'refused')

    def test_repeated_identity_cannot_split(self):
        expected = graph()
        actual = copy.deepcopy(expected)
        actual['declarationNodes'].append(record(3))
        actual['gccTypeBindings'].append({'identity':3,'expression':'struct separate'})
        actual['interfaces']['acp_mix']['parameters'][0] = reference(3)
        self.assertEqual(gate.compare_descriptors(expected, actual)['status'], 'refused')

    def test_nested_repeated_dag_and_callback_root(self):
        expected = graph()
        expected['declarationNodes'][1]['fields'][0]['type'] = reference(1)
        expected['interfaces']['acp_apply'] = function(parameters=[{'kind':'pointer','bits':64,'qualifiers':0,'pointee':function(reference(2), [reference(1),reference(2)])}])
        self.assertTrue(gate.compare_descriptors(expected, remap(expected,{1:9,2:10}))['accepted'])

    def test_alias_bindings_resolve_exact_identity_not_equal_shape(self):
        value = graph()
        value['gccTypeBindings'] += [{'identity':1,'expression':'alias_chain_one'}, {'identity':1,'expression':'alias_chain_two'}]
        source = gate.layout_assertions(Path('/work/public.c'), value)
        self.assertIn('acp_expected_acp_mix(alias_chain_one, struct type_2)', source)
        self.assertIn('alias_chain_two, alias_chain_one', source)
        self.assertEqual(gate.resolve_declaration(value, reference(2))['identity'],2)

    def test_enum_identity_and_underlying_type(self):
        roots = {name:function() for name in gate.REQUIRED}
        roots['acp_state'] = reference(1,'enum')
        roots['acp_mix'] = function(reference(2,'enum'), [reference(1,'enum')])
        nodes = [{'kind':'enum','identity':i,'integerType':integer('unsigned-int'),'values':[{'name':'MODE','value':'0'}]} for i in (1,2)]
        expected = receipt(nodes,roots)
        self.assertTrue(gate.compare_descriptors(expected,remap(expected,{1:8,2:9}))['accepted'])
        actual = remap(expected,{2:1})
        actual['declarationNodes']=actual['declarationNodes'][:1];actual['gccTypeBindings']=actual['gccTypeBindings'][:1]
        self.assertEqual(gate.compare_descriptors(expected,actual)['status'],'refused')
        self.assertIn('typedef enum type_2 acp_expected_acp_mix(enum type_1)',gate.layout_assertions(Path('/work/public.c'),expected))

    def test_unresolved_duplicate_conflicting_and_unreachable_nodes(self):
        value=graph();value['interfaces']['acp_state']=reference(99);self.assert_unknown(value)
        value=graph();value['declarationNodes'].append(record(1));self.assert_unknown(value)
        value=graph();value['gccTypeBindings'][1]['expression']=value['gccTypeBindings'][0]['expression'];self.assert_unknown(value)
        value=graph();value['declarationNodes'].append(record(3));self.assert_unknown(value)
        value=graph();value['gccTypeBindings'].pop();self.assert_unknown(value)
        value=graph();value['interfaces']['acp_mix']['return']['kind']='enum';self.assert_unknown(value)

    def test_active_cycle_refuses_but_repeated_node_does_not(self):
        value=graph();value['declarationNodes'][0]['fields'][0]['type']=reference(2)
        value['declarationNodes'][1]['fields'][0]['type']=reference(1)
        self.assert_unknown(value)
        self.assertTrue(gate.compare_descriptors(graph(),graph())['accepted'])

    def test_target_and_layout_field_qualifiers_are_compared(self):
        for mutate in (lambda v:v.update(target='other'), lambda v:v.update(dataLayout='other'),
                       lambda v:v['declarationNodes'][0].update(alignBits=32),
                       lambda v:v['declarationNodes'][0]['fields'][0].update(name='other'),
                       lambda v:v['interfaces']['acp_state'].update(qualifiers=1)):
            actual=graph();mutate(actual)
            self.assertEqual(gate.compare_descriptors(graph(),actual)['status'],'refused')

    def test_unsupported_old_schema_and_bad_c_expression_are_unknown(self):
        value=graph();value['schemaVersion']=2;self.assert_unknown(value)
        value=graph();value['status']='refused';self.assert_unknown(value)
        value=graph();value['gccTypeBindings'][0]['expression']='alias; bad';self.assert_unknown(value)
        value=graph();value['declarationNodes'][0]['fields'][0]['name']='bad\nname';self.assert_unknown(value)
        with self.assertRaises(ValueError):gate.layout_assertions(Path('/work/bad".c'),graph())

    def test_bounds_are_enforced(self):
        value=graph()
        with patch.object(gate,'MAX_GRAPH_NODES',1): self.assert_unknown(value)
        with patch.object(gate,'MAX_GRAPH_DEPTH',0): self.assert_unknown(value)

    def test_closed_helper_schema_records_refs_and_exact_kinds(self):
        schema=json.loads((Path(gate.__file__).parent/'contracts/helper-schema.json').read_text())
        self.assertEqual(schema['oneOf'][0]['properties']['schemaVersion'],{'const':3})
        self.assertFalse(schema['definitions']['recordRef']['additionalProperties'])
        self.assertEqual(set(schema['definitions']['recordRef']['required']),{'kind','identity','qualifiers'})
        self.assertEqual(set(schema['definitions']['binding']['required']),{'identity','expression'})
        self.assertEqual(set(schema['definitions']['integer']['properties']['builtinKind']['enum']),set(gate.INTEGER_SPELLINGS))

    def test_probe_rejects_v2_and_validates_supported_graph_without_native_run(self):
        import tempfile
        with tempfile.TemporaryDirectory(dir=Path(gate.__file__).parent) as directory:
            work=Path(directory);source=work/'public.c';source.write_text('int public_test;')
            helper=work/'not-executed';helper.write_text('inert')
            result=completed_result(json.dumps(graph()).encode())
            with patch.object(gate,'bounded_run',return_value=result), patch.object(gate,'probe_command',return_value=['NOT-EXECUTED']):
                self.assertEqual(gate.probe(source,helper,work,{})['schemaVersion'],3)
                old=graph();old['schemaVersion']=2;result['stdout']=json.dumps(old).encode()
                with self.assertRaises(ValueError):gate.probe(source,helper,work,{})

    def test_helper_support_imports_are_inert_and_build_receipt_binds_v3(self):
        import runpy
        import tempfile
        root=Path(gate.__file__).parent
        with patch('subprocess.Popen',side_effect=AssertionError('native execution forbidden')), patch('subprocess.check_output',side_effect=AssertionError('native execution forbidden')):
            builder=runpy.run_path(str(root/'toolchain-001/build_helper.py'),run_name='inert_import')
            pinner=runpy.run_path(str(root/'toolchain-001/pin_helper.py'),run_name='inert_import')
        self.assertTrue(callable(builder['build']))
        self.assertTrue(callable(pinner['pin']))
        with tempfile.TemporaryDirectory(dir=root) as directory:
            work=Path(directory);(work/'toolchain-001').mkdir();(work/'contracts').mkdir()
            (work/'record_identity_probe.cpp').write_text('// inert public fixture')
            (work/'contracts/helper-schema.json').write_text('{"schemaVersion":3}')
            (work/'toolchain-001/record_identity_probe').write_bytes(b'NOT EXECUTABLE')
            build=builder['build']
            from unittest.mock import Mock
            runner=Mock(return_value=completed_result())
            with patch.dict(build.__globals__,ROOT=work,load_profile=lambda:{'bounds':{'helperBuildSeconds':60,'helperOutputBytesPerStream':1048576,'fileSizeBytes':16777216}},bounded_run=runner,read_output=lambda path,limit,elf=False:b'NOT EXECUTABLE'):
                result=build('receipt.json')
            self.assertEqual(runner.call_args.kwargs['phase'],'helper-build')
            self.assertEqual(result['schemaVersion'],3)
            self.assertEqual(result['binarySha256'],gate.digest(work/'toolchain-001/record_identity_probe'))
            self.assertEqual(result['helperSchemaSha256'],gate.digest(work/'contracts/helper-schema.json'))
            self.assertEqual(result['sourceSha256'],gate.digest(work/'record_identity_probe.cpp'))
            incomplete=completed_result();incomplete['cleanupVerified']=False
            with patch.dict(build.__globals__,ROOT=work,load_profile=lambda:{'bounds':{'helperBuildSeconds':60,'helperOutputBytesPerStream':1048576,'fileSizeBytes':16777216}},bounded_run=lambda *args,**kwargs:incomplete):
                with self.assertRaisesRegex(ValueError,'incomplete helper build') as failure:build('not-created.json')
                self.assertIs(failure.exception.bounded_result,incomplete)
                self.assertFalse((work/'toolchain-001/not-created.json').exists())

    def test_enum_per_list_and_unified_work_boundaries(self):
        def enum_receipt(count):
            value=receipt()
            value['interfaces']['acp_state']=reference(1,'enum')
            value['declarationNodes']=[{'kind':'enum','identity':1,'integerType':integer(),'values':[{'name':'E'+str(i),'value':str(i)} for i in range(count)]}]
            value['gccTypeBindings']=[{'identity':1,'expression':'enum public_mode'}]
            return value
        # Six roots plus one enum-underlying descriptor consume seven visits.
        exact=enum_receipt(4096-7)
        self.assertTrue(gate.compare_descriptors(exact,copy.deepcopy(exact))['accepted'])
        with self.assertRaisesRegex(ValueError,'graph-bound'):
            gate._validated_graph(enum_receipt(4096-6))
        per_list_exact=enum_receipt(4096)
        gate._validate_raw_helper(per_list_exact)  # Schema ceiling only.
        with self.assertRaisesRegex(ValueError,'graph-bound'):
            gate._validated_graph(per_list_exact)  # Global overhead still counts.
        with self.assertRaisesRegex(ValueError,'invalid raw helper schema'):
            gate._validate_raw_helper(enum_receipt(4097))
        source=(Path(gate.__file__).parent/'record_identity_probe.cpp').read_text()
        enumeration=source[source.index('Array values;unsigned members=0;'):source.index('provenance.push_back(Object{{"kind","enum"}')]
        self.assertLess(enumeration.index('members++>=4096'),enumeration.index('attrs(v)'))
        self.assertLess(enumeration.index('++nodes>4096'),enumeration.index('attrs(v)'))
        self.assertLess(enumeration.index('++nodes>4096'),enumeration.index('values.push_back'))

    def test_schema_closes_raw_roots_required_fields_and_recursive_leaves(self):
        mutations=[lambda v:v.update(unexpectedRoot=True),lambda v:v.pop('diagnostics'),lambda v:v.pop('provenance'),
                   lambda v:v['interfaces']['acp_mix'].update(unexpectedNested=True),
                   lambda v:v['declarationNodes'][0]['fields'][0]['type'].update(unexpectedNested=True),
                   lambda v:v['gccTypeBindings'][0].update(unexpectedBinding=True),
                   lambda v:v.update(provenance=[{'kind':'alias','identity':8,'name':'alias','underlyingDiagnosticSpelling':'int','unexpected':True}]),
                   lambda v:v.update(diagnostics=[1]),lambda v:v.update(schemaVersion=2),
                   lambda v:v.update(diagnostics=['overflow']*4097)]
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                value=graph();mutate(value)
                with self.assertRaisesRegex(ValueError,'invalid raw helper schema'):
                    gate._validate_raw_helper(value)
                self.assert_unknown(value)

    def test_raw_refusal_and_fixture_shapes_are_closed_and_never_admitted(self):
        refusal={'schemaVersion':3,'status':'refused','diagnostics':['unsupported-integer-builtin-kind']}
        gate._validate_raw_helper(refusal);self.assert_unknown(refusal)
        partial=copy.deepcopy(refusal)
        partial['interfaces']={'acp_state':{'kind':'unsupported','reason':'unsupported-integer-builtin-kind'}}
        gate._validate_raw_helper(partial)
        partial['interfaces']['acp_state']['unexpected']=True
        with self.assertRaises(ValueError):gate._validate_raw_helper(partial)
        fixture={'schemaVersion':3,'fixtureOnly':True,'status':'supported','diagnostic':'','visited':1}
        gate._validate_raw_helper(fixture);self.assert_unknown(fixture)
        for value in (dict(refusal,unexpectedRoot=True),dict(fixture,unexpectedRoot=True),{'schemaVersion':3,'status':'refused'}):
            with self.assertRaises(ValueError):gate._validate_raw_helper(value)

    def test_probe_validates_actual_raw_schema_before_receipt_enrichment(self):
        import tempfile
        root=Path(gate.__file__).parent
        mutations=[lambda v:v.update(unexpectedRoot=True),lambda v:v.pop('diagnostics'),lambda v:v.pop('provenance'),
                   lambda v:v['interfaces']['acp_mix'].update(unexpectedNested=True),lambda v:v.update(schemaVersion=2),
                   lambda v:v.update(execution={},inputBindings={})]
        with tempfile.TemporaryDirectory(dir=root) as directory:
            work=Path(directory);source=work/'public.c';source.write_text('int public_test;')
            helper=work/'inert-helper';helper.write_text('NOT EXECUTED')
            for mutate in mutations:
                value=graph();mutate(value)
                result=completed_result(json.dumps(value).encode())
                with patch.object(gate,'bounded_run',return_value=result) as runner, patch.object(gate,'probe_command',return_value=['NOT-EXECUTED']):
                    with self.assertRaises(ValueError) as failure:gate.probe(source,helper,work,{})
                    self.assertIs(failure.exception.bounded_result,result)
                    self.assertEqual(runner.call_args.kwargs['phase'],'probe')
            refusal={'schemaVersion':3,'status':'refused','diagnostics':['unsupported-integer-builtin-kind']}
            result=completed_result(json.dumps(refusal).encode(),exit_code=2)
            with patch.object(gate,'bounded_run',return_value=result), patch.object(gate,'probe_command',return_value=['NOT-EXECUTED']):
                refused=gate.probe(source,helper,work,{})
                self.assertEqual(refused['status'],'refused');self.assert_unknown(refused)
            fixture={'schemaVersion':3,'fixtureOnly':True,'status':'supported','diagnostic':'','visited':1}
            result=completed_result(json.dumps(fixture).encode())
            with patch.object(gate,'bounded_run',return_value=result), patch.object(gate,'probe_command',return_value=['NOT-EXECUTED']):
                with self.assertRaisesRegex(ValueError,'fixture-only'):gate.probe(source,helper,work,{})

    def test_trusted_enrichment_is_explicit_and_cannot_enter_through_raw_gate(self):
        value=graph()
        bindings={'sourceSha256':'a'*64,'helperSha256':'b'*64,'inputsUnchanged':True}
        execution=gate.public_result(completed_result())
        execution['inputBindings']=bindings
        value.update(execution=execution,inputBindings=bindings)
        with self.assertRaises(ValueError):gate._validate_raw_helper(value)
        self.assertTrue(gate.compare_descriptors(value,copy.deepcopy(value))['accepted'])
        value['unexpectedRoot']=True;self.assert_unknown(value);value.pop('unexpectedRoot')
        value.pop('execution');self.assert_unknown(value)

    def test_probe_and_exports_need_complete_process_observations(self):
        import tempfile
        root=Path(gate.__file__).parent
        fields=('launcherCreated','launcherPidIdentityVerified','scopeVerified','scopeAdmitted','captureComplete','waitComplete','cleanupVerified','rootReaped','finalAbsenceVerified')
        with tempfile.TemporaryDirectory(dir=root) as directory:
            work=Path(directory);source=work/'public.c';source.write_text('int public_test;')
            helper=work/'inert-helper';helper.write_text('NOT EXECUTED')
            for field in fields:
                result=completed_result(json.dumps(graph()).encode());result[field]=False
                with patch.object(gate,'bounded_run',return_value=result),patch.object(gate,'probe_command',return_value=['NOT-EXECUTED']):
                    with self.assertRaisesRegex(ValueError,'incomplete helper'):gate.probe(source,helper,work,{})
            for field in ('timedOut','outputExceeded','infrastructureFailure'):
                result=completed_result();result[field]=True
                self.assertFalse(gate._complete_execution(result))
            (work/'inert.so').write_bytes(b'NOT EXECUTABLE')
            result=completed_result();result['captureComplete']=False
            with patch.object(gate,'bounded_run',return_value=result) as runner:
                exported=gate.export_inventory(work/'inert.so',8,work,{'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C'})
                self.assertEqual(exported['status'],'unknown');self.assertFalse(exported['accepted'])
                self.assertEqual(runner.call_count,1)
                self.assertEqual(runner.call_args.kwargs['phase'],'elf-inspection')
            with patch.object(gate,'bounded_run',side_effect=[completed_result(),result]) as runner:
                exported=gate.export_inventory(work/'inert.so',8,work,{'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C'})
                self.assertEqual(exported['status'],'unknown');self.assertFalse(exported['accepted'])
                self.assertEqual(runner.call_count,2)

if __name__ == '__main__': unittest.main()
