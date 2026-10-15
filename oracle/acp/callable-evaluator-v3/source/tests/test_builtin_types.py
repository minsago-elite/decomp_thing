"""Pure builtin-kind and generated assertion tests; no compiler execution."""
import copy
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import interface_gate_v3 as gate
from test_identity_graph import integer, reference, function, record, receipt

class BuiltinTypes(unittest.TestCase):
    def test_exact_supported_spelling_in_fields_arguments_returns_callbacks(self):
        for kind, spelling in gate.INTEGER_SPELLINGS.items():
            with self.subTest(kind=kind):
                roots={name:function(integer(kind),[integer(kind)]) for name in gate.REQUIRED}
                roots['acp_state']=reference(1)
                roots['acp_apply']=function(integer(kind),[{'kind':'pointer','bits':64,'qualifiers':0,'pointee':function(integer(kind),[integer(kind)])}])
                value=receipt([record(1,integer(kind))],roots)
                self.assertTrue(gate.compare_descriptors(value,copy.deepcopy(value))['accepted'])
                source=gate.layout_assertions(Path('/work/public.c'),value)
                self.assertIn('), '+spelling+'), "field type"',source)
                self.assertIn('typedef '+spelling+' acp_expected_acp_mix('+spelling+')',source)
                self.assertIn('typedef '+spelling+' (*acp_assert_fn_0)('+spelling+')',source)

    def test_same_width_distinct_integer_kinds_refused(self):
        for left,right in (('long','long-long'),('unsigned-long','unsigned-long-long'),('char','signed-char'),('char','unsigned-char')):
            expected=receipt();actual=copy.deepcopy(expected)
            expected['interfaces']['acp_state']=integer(left)
            actual['interfaces']['acp_state']=integer(right)
            self.assertEqual(gate.compare_descriptors(expected,actual)['status'],'refused')

    def test_typedef_provenance_does_not_change_builtin_and_qualifiers_preserved(self):
        expected=receipt();actual=copy.deepcopy(expected)
        expected['interfaces']['acp_state']=integer('long-long',5)
        actual['interfaces']['acp_state']=integer('long-long',5)
        actual['provenance']=[{'kind':'alias','identity':1,'name':'alias_one','underlyingDiagnosticSpelling':'long long'},{'kind':'alias','identity':2,'name':'alias_two','targetIdentity':1,'underlyingDiagnosticSpelling':'alias_one'}]
        self.assertTrue(gate.compare_descriptors(expected,actual)['accepted'])
        self.assertIn('const volatile long long',gate.layout_assertions(Path('/work/public.c'),actual))
        actual['interfaces']['acp_state']['qualifiers']=0
        self.assertEqual(gate.compare_descriptors(expected,actual)['status'],'refused')

    def test_pointer_and_pointee_qualifiers_keep_their_positions(self):
        value=receipt();value['interfaces']['acp_state']={'kind':'pointer','bits':64,'qualifiers':1,'pointee':{'kind':'void','qualifiers':4}}
        self.assertIn('volatile void * const',gate.layout_assertions(Path('/work/public.c'),value))

    def test_unsupported_bool_extended_integer_and_inconsistent_signedness(self):
        for kind in ('bool','_Bool','int128','unsigned-int128','wchar'):
            value=receipt();value['interfaces']['acp_state']['builtinKind']=kind
            self.assertEqual(gate.compare_descriptors(value,value)['status'],'unknown')
            with self.assertRaises(ValueError):gate.layout_assertions(Path('/work/public.c'),value)
        value=receipt();value['interfaces']['acp_state']['signed']=False
        self.assertEqual(gate.compare_descriptors(value,value)['status'],'unknown')

    def test_helper_source_uses_closed_kind_mapping_not_width_guess(self):
        source=(Path(gate.__file__).parent/'record_identity_probe.cpp').read_text()
        for kind in gate.INTEGER_SPELLINGS:
            self.assertIn('kind="'+kind+'"',source)
        self.assertIn('unsupported-integer-builtin-kind',source)
        self.assertIn('getCanonicalDecl()',source)
        self.assertIn('"declarationNodes"',source)
        self.assertNotIn('"descriptor",desc',source)

if __name__ == '__main__': unittest.main()
