"""Independent export and structural declaration admission; never loads a library."""
import json
import os
import shutil
import tempfile
import re
from importlib.metadata import version
import fastjsonschema
from pathlib import Path
from bounded_runtime import bounded_run, public_result, digest, contained_command, worker_execution_complete
from build_contract import profile, load_profile
REQUIRED = {'acp_mix','acp_pair_scale','acp_update','acp_apply','acp_fold','acp_state'}
# Stable Clang builtin kinds; width alone never identifies a C integer type.
INTEGER_SPELLINGS = {
    'char':'char', 'signed-char':'signed char', 'unsigned-char':'unsigned char',
    'short':'short', 'unsigned-short':'unsigned short', 'int':'int',
    'unsigned-int':'unsigned int', 'long':'long', 'unsigned-long':'unsigned long',
    'long-long':'long long', 'unsigned-long-long':'unsigned long long',
}
MAX_GRAPH_NODES = 4096
MAX_GRAPH_DEPTH = 64
_IDENTIFIER = re.compile(r'[A-Za-z_][A-Za-z_0-9]*\Z', re.ASCII)
_EXPRESSION = re.compile(r'(?:(?:struct|enum) )?[A-Za-z_][A-Za-z_0-9]*\Z', re.ASCII)


def _integer(value, minimum=0):
    return type(value) is int and value >= minimum


def _keys(value, keys):
    if not isinstance(value, dict) or set(value) != set(keys):
        raise ValueError('invalid declaration descriptor fields')


_COMPILED_HELPER_SCHEMA = None


def _validate_raw_helper(value):
    """Apply the actual closed exchange schema before any trusted enrichment."""
    global _COMPILED_HELPER_SCHEMA
    schema_path = Path(__file__).resolve().parent / 'contracts/helper-schema.json'
    schema_sha = digest(schema_path)
    if _COMPILED_HELPER_SCHEMA is None or _COMPILED_HELPER_SCHEMA[0] != schema_sha:
        if version('fastjsonschema') != '2.22.2':
            raise ValueError('unqualified helper schema validator version')
        schema = json.loads(schema_path.read_bytes())
        if schema.get('$schema') != 'http://json-schema.org/draft-07/schema#':
            raise ValueError('unqualified helper schema dialect')
        _COMPILED_HELPER_SCHEMA = (schema_sha, fastjsonschema.compile(schema, use_default=False))
    try:
        _COMPILED_HELPER_SCHEMA[1](value)
    except fastjsonschema.JsonSchemaException as error:
        raise ValueError('invalid raw helper schema: ' + str(error)[:300]) from error
    return value


def _complete_execution(result):
    """Require authenticated worker exec/termination and complete containment receipts."""
    return worker_execution_complete(result)



class owned_worker_leaf:
    """Explicit attempt lifetime; unknown worker absence retains the owned leaf."""
    def __init__(self, root, prefix):
        workspace = root/'worker-work'
        workspace.mkdir(mode=0o700,exist_ok=True)
        if workspace.is_symlink() or workspace.resolve() != workspace:
            raise ValueError('worker workspace is not canonical')
        self.path = Path(tempfile.mkdtemp(prefix=prefix,dir=workspace))
        metadata = self.path.lstat()
        self.identity = {'path':str(self.path),'device':metadata.st_dev,'inode':metadata.st_ino,
                         'uid':metadata.st_uid,'mode':metadata.st_mode}
        self.launched = False
        self.result = None

    def __enter__(self):
        return self

    def run(self, runner, *args, **kwargs):
        self.launched = True
        try:
            self.result = runner(*args, **kwargs)
            return self.result
        except BaseException as error:
            self.result = getattr(error,'bounded_result',None)
            raise

    def __exit__(self, kind, error, traceback):
        result = self.result
        absence = (isinstance(result,dict) and
                   all(result.get(key) is True for key in ('cleanupVerified','rootReaped','finalAbsenceVerified')) and
                   isinstance(result.get('kernelScope'),dict) and
                   result['kernelScope'].get('finalAbsenceVerified') is True)
        facts = {'identity':self.identity,'retained':True,'deletionAttempted':False,
                 'absenceVerified':absence,'prelaunch':not self.launched}
        try:
            current = self.path.lstat()
            if (current.st_dev,current.st_ino,current.st_uid,current.st_mode) != tuple(self.identity[k] for k in ('device','inode','uid','mode')):
                facts['reason']='leaf identity changed; no deletion'
            elif not self.launched or absence:
                facts['deletionAttempted']=True
                shutil.rmtree(self.path)
                facts['retained']=False
            else:
                facts['reason']='worker absence unverified; leaf retained'
        except Exception as cleanup_error:
            facts['reason']='leaf deletion/identity error'
            facts['secondaryError']=type(cleanup_error).__name__+': '+str(cleanup_error)[:300]
        if isinstance(result,dict):
            result['leafCleanup']=facts
        if error is not None:
            error.leafCleanup=facts
        elif facts.get('secondaryError') or facts.get('reason'):
            failure=ValueError('worker leaf cleanup incomplete')
            failure.bounded_result=result
            failure.leafCleanup=facts
            raise failure
        return False


def _require_helper_target(execution, helper_sha):
    """Join the controller claim to the executable independently proven by monitor."""
    binding = execution.get('workerProofBindings') or {}
    expected = binding.get('expected') or {}
    pins = execution.get('launchInputPins') or {}
    if (binding.get('targetSha256') != helper_sha or not any(
            row.get('sha256') == helper_sha and
            (row.get('device'),row.get('inode')) == (expected.get('targetDevice'),expected.get('targetInode'))
            for row in pins.values())):
        raise ValueError('helper claim differs from monitor-proven executable')


def _raw_from_receipt(receipt):
    """Raw helper roots are closed; only this reader may add these two fields."""
    if not isinstance(receipt, dict):
        raise ValueError('invalid helper receipt')
    trusted_keys = {'execution','inputBindings'}
    present = set(receipt) & trusted_keys
    if not present:
        return _validate_raw_helper(receipt)
    if present != trusted_keys:
        raise ValueError('incomplete trusted helper enrichment')
    bindings, execution = receipt['inputBindings'], receipt['execution']
    _keys(bindings, ('sourceSha256','helperSha256','inputsUnchanged'))
    if bindings['inputsUnchanged'] is not True or any(not isinstance(bindings[key], str) or not re.fullmatch('[0-9a-f]{64}', bindings[key]) for key in ('sourceSha256','helperSha256')):
        raise ValueError('invalid trusted helper input bindings')
    if not _complete_execution(execution) or execution.get('inputBindings') != bindings:
        raise ValueError('incomplete trusted helper execution')
    _require_helper_target(execution, bindings['helperSha256'])
    return _validate_raw_helper({key:value for key,value in receipt.items() if key not in trusted_keys})


def _validated_graph(receipt):
    """Validate the bounded rooted graph before comparing or emitting C source.

    Only active nodes indicate cycles; an already completed DAG node is valid.
    GCC bindings identify declarations, never a matching structural shape.
    """
    receipt = _raw_from_receipt(receipt)
    if receipt.get('schemaVersion') != 3 or receipt.get('status') != 'supported' or receipt.get('fixtureOnly'):
        raise ValueError('unsupported helper schema or declaration')
    if not isinstance(receipt.get('target'), str) or not receipt['target'] or not isinstance(receipt.get('dataLayout'), str) or not receipt['dataLayout']:
        raise ValueError('missing target identity')
    interfaces = receipt.get('interfaces')
    if not isinstance(interfaces, dict) or set(interfaces) != REQUIRED:
        raise ValueError('missing-interface-identity')
    raw_nodes = receipt.get('declarationNodes')
    if not isinstance(raw_nodes, list) or len(raw_nodes) > MAX_GRAPH_NODES:
        raise ValueError('invalid declaration node table')
    nodes = {}
    for node in raw_nodes:
        if not isinstance(node, dict) or not _integer(node.get('identity'), 1) or node['identity'] in nodes:
            raise ValueError('duplicate or invalid declaration identity')
        nodes[node['identity']] = node
    active, complete = set(), set()
    budget = 0

    def descriptor(d, depth):
        nonlocal budget
        budget += 1
        if budget > MAX_GRAPH_NODES or depth > MAX_GRAPH_DEPTH:
            raise ValueError('graph-bound')
        if not isinstance(d, dict):
            raise ValueError('invalid type descriptor')
        kind = d.get('kind')
        if kind != 'function' and (not _integer(d.get('qualifiers')) or d['qualifiers'] > 7):
            raise ValueError('unsupported qualifiers')
        if kind in ('record', 'enum'):
            _keys(d, ('kind','identity','qualifiers'))
            identity = d['identity']
            if not _integer(identity, 1) or identity not in nodes or nodes[identity].get('kind') != kind:
                raise ValueError('unresolved declaration identity')
            if identity in active:
                raise ValueError('type-resolution-cycle')
            if identity in complete:
                return
            active.add(identity)
            node = nodes[identity]
            if kind == 'record':
                _keys(node, ('kind','identity','sizeBits','alignBits','fields'))
                if not _integer(node['sizeBits']) or not _integer(node['alignBits'], 1) or not isinstance(node['fields'], list):
                    raise ValueError('invalid record layout')
                names = set()
                for field in node['fields']:
                    _keys(field, ('name','type','offsetBits'))
                    name = field['name']
                    if not isinstance(name, str) or not _IDENTIFIER.fullmatch(name) or name in names or not _integer(field['offsetBits']) or field['offsetBits'] > node['sizeBits']:
                        raise ValueError('invalid field identity or offset')
                    names.add(name)
                    descriptor(field['type'], depth + 1)
            else:
                _keys(node, ('kind','identity','integerType','values'))
                descriptor(node['integerType'], depth + 1)
                if node['integerType'].get('kind') != 'integer' or not isinstance(node['values'], list):
                    raise ValueError('invalid enum underlying type')
                if len(node['values']) > MAX_GRAPH_NODES:
                    raise ValueError('enum-member-bound')
                # Charge all member visits before walking them. This is the same
                # unified budget as type visits, not an additional allowance.
                budget += len(node['values'])
                if budget > MAX_GRAPH_NODES:
                    raise ValueError('graph-bound: enum members')
                names = set()
                for item in node['values']:
                    _keys(item, ('name','value'))
                    if not isinstance(item['name'], str) or not _IDENTIFIER.fullmatch(item['name']) or item['name'] in names or not isinstance(item['value'], str) or not re.fullmatch(r'-?(?:0|[1-9][0-9]*)', item['value'], re.ASCII):
                        raise ValueError('invalid enumerator')
                    names.add(item['name'])
            active.remove(identity)
            complete.add(identity)
        elif kind == 'integer':
            _keys(d, ('kind','builtinKind','bits','signed','qualifiers'))
            if not isinstance(d['builtinKind'], str) or d['builtinKind'] not in INTEGER_SPELLINGS or not _integer(d['bits'], 1) or type(d['signed']) is not bool:
                raise ValueError('unsupported integer builtin kind')
            if d['builtinKind'] != 'char' and d['signed'] != (not d['builtinKind'].startswith('unsigned-')):
                raise ValueError('inconsistent integer signedness')
        elif kind == 'float':
            _keys(d, ('kind','name','bits','qualifiers'))
            if d['name'] not in ('float','double','long double') or not _integer(d['bits'], 1):
                raise ValueError('unsupported floating type')
        elif kind == 'void':
            _keys(d, ('kind','qualifiers'))
        elif kind == 'pointer':
            _keys(d, ('kind','bits','qualifiers','pointee'))
            if not _integer(d['bits'], 1) or not isinstance(d['pointee'], dict) or d['pointee'].get('kind') not in ('void','function'):
                raise ValueError('unsupported pointer contract')
            descriptor(d['pointee'], depth + 1)
        elif kind == 'function':
            _keys(d, ('kind','return','parameters','variadic','callingConvention'))
            if not isinstance(d['parameters'], list) or type(d['variadic']) is not bool or d['callingConvention'] != 'C' or (d['variadic'] and not d['parameters']):
                raise ValueError('unsupported function contract')
            descriptor(d['return'], depth + 1)
            for parameter in d['parameters']:
                descriptor(parameter, depth + 1)
        else:
            raise ValueError('unsupported type kind')

    for name in sorted(REQUIRED):
        descriptor(interfaces[name], 0)
    if complete != set(nodes):
        raise ValueError('unreachable declaration node')
    bindings = receipt.get('gccTypeBindings')
    if not isinstance(bindings, list) or len(bindings) > MAX_GRAPH_NODES:
        raise ValueError('invalid GCC binding table')
    expressions = {}
    bound = set()
    for binding in bindings:
        _keys(binding, ('identity','expression'))
        identity, expression = binding['identity'], binding['expression']
        if not _integer(identity, 1) or identity not in nodes or not isinstance(expression, str) or not _EXPRESSION.fullmatch(expression):
            raise ValueError('invalid GCC declaration binding')
        if expression in expressions and expressions[expression] != identity:
            raise ValueError('conflicting GCC declaration binding')
        expressions[expression] = identity
        bound.add(identity)
    if bound != set(nodes):
        raise ValueError('helper omitted reachable GCC declaration binding')
    return nodes


def resolve_declaration(receipt, descriptor):
    """Resolve a canonical record/enum reference (e.g. exported state layout)."""
    nodes = _validated_graph(receipt)
    if not isinstance(descriptor, dict) or descriptor.get('kind') not in ('record','enum') or descriptor.get('identity') not in nodes or nodes[descriptor['identity']]['kind'] != descriptor['kind']:
        raise ValueError('unresolved declaration identity')
    return nodes[descriptor['identity']]


def compare_descriptors(expected, actual):
    try:
        expected_nodes, actual_nodes = _validated_graph(expected), _validated_graph(actual)
    except (KeyError, TypeError, ValueError, RecursionError) as error:
        return {'accepted':False, 'status':'unknown', 'reason':str(error)[:300]}
    forward, reverse = {}, {}
    compared = set()

    def equal(left, right):
        if type(left) is not type(right):
            return False
        if isinstance(left, dict):
            if set(left) != set(right):
                return False
            if left.get('kind') in ('record','enum') and 'qualifiers' in left:
                if left['kind'] != right['kind'] or left['qualifiers'] != right['qualifiers']:
                    return False
                e, a = left['identity'], right['identity']
                if (e in forward and forward[e] != a) or (a in reverse and reverse[a] != e):
                    return False
                forward[e], reverse[a] = a, e
                if (e, a) in compared:
                    return True
                compared.add((e, a))
                return equal({k:v for k,v in expected_nodes[e].items() if k != 'identity'}, {k:v for k,v in actual_nodes[a].items() if k != 'identity'})
            return all(equal(left[k], right[k]) for k in left)
        if isinstance(left, list):
            return len(left) == len(right) and all(equal(e,a) for e,a in zip(left,right))
        return left == right

    differences = [name for name in sorted(REQUIRED) if not equal(expected['interfaces'][name], actual['interfaces'][name])]
    target_equal = expected['target'] == actual['target'] and expected['dataLayout'] == actual['dataLayout']
    accepted = not differences and target_equal
    return {'accepted':accepted, 'status':'passed' if accepted else 'refused', 'differences':differences, 'targetEqual':target_equal}

def probe_command(helper, work, arguments):
    work=work.resolve(strict=True);helper=helper.resolve(strict=True)
    command=['/usr/bin/bwrap','--unshare-all','--unshare-user','--die-with-parent','--new-session','--disable-userns','--cap-drop','ALL','--clearenv']
    for directory in ('/usr','/lib','/lib64'):
        if Path(directory).exists():command+=['--ro-bind',directory,directory]
    return command+['--proc','/proc','--dev','/dev','--remount-ro','/dev','--size','16777216','--tmpfs','/tmp','--ro-bind',str(work),'/work','--ro-bind',str(helper),'/probe','--chdir','/work',*sum((['--setenv',k,v] for k,v in profile()['analysisIsolation']['environment'].items()),[]),'/probe',*arguments]

def probe(source, helper, work, environment):
    source=source.resolve(strict=True);work=work.resolve(strict=True)
    if not source.is_relative_to(work):
        raise ValueError('probe input outside isolated work root')
    helper=helper.resolve(strict=True)
    bindings={'sourceSha256':digest(source),'helperSha256':digest(helper)}
    argument='/work/'+str(source.relative_to(work))
    bounds=load_profile()['bounds']
    result = bounded_run(probe_command(helper,work,[argument]),work,environment,
                         timeout=bounds['probeSeconds'],output_limit=bounds['helperOutputBytesPerStream'],
                         managed_scope=True,phase='probe')
    receipt = public_result(result)
    bindings['inputsUnchanged']=bindings['sourceSha256']==digest(source) and bindings['helperSha256']==digest(helper)
    receipt['inputBindings']=bindings
    try:
        if not bindings['inputsUnchanged']:
            raise ValueError('probe inputs changed during execution')
        if not _complete_execution(result):
            raise ValueError('incomplete helper execution')
        _require_helper_target(result, bindings['helperSha256'])
        if result['exitCode'] not in (0,1,2):
            raise ValueError('unexpected helper termination')
        value = _validate_raw_helper(json.loads(result['stdout']))
        if value.get('fixtureOnly'):
            raise ValueError('fixture-only helper output is not declaration evidence')
        if (value['status']=='supported' and result['exitCode']!=0) or (value['status']=='refused' and result['exitCode']==0):
            raise ValueError('helper status and termination disagree')
        if value['status']=='supported':
            _validated_graph(value)
    except Exception as error:
        # Retain full tool diagnostics for the controller's unknown receipt.
        error.bounded_result=result
        raise
    value['inputBindings']=bindings
    value['execution'] = receipt
    return value

def export_inventory(library, expected_state_bytes, work, environment):
    bounds=load_profile()['bounds']
    r = bounded_run(contained_command(['/usr/bin/readelf','--dyn-syms','--wide',str(library)],work,read_only_files=(library,),environment=environment),work,environment,timeout=bounds['elfInspectionSeconds'],output_limit=bounds['outputBytesPerStream'],managed_scope=True,phase='elf-inspection')
    if not _complete_execution(r):
        return {'status':'unknown','accepted':False,'reason':'incomplete export inspection','execution':public_result(r)}
    symbols = []
    for line in r['stdout'].decode('utf8',errors='strict').splitlines():
        parts = line.split()
        if len(parts) == 8 and parts[0].rstrip(':').isdigit():
            symbols.append(dict(zip(('number','value','size','type','binding','visibility','index','name'),parts)))
    sections_result=bounded_run(contained_command(['/usr/bin/readelf','--section-headers','--wide',str(library)],work,read_only_files=(library,),environment=environment),work,environment,timeout=bounds['elfInspectionSeconds'],output_limit=bounds['outputBytesPerStream'],managed_scope=True,phase='elf-inspection')
    if not _complete_execution(sections_result):
        return {'status':'unknown','accepted':False,'reason':'incomplete section inspection','execution':public_result(r),'sectionsExecution':public_result(sections_result)}
    section_flags={}
    for line in sections_result['stdout'].decode('utf8',errors='strict').splitlines():
        match=re.match(r'\s*\[\s*(\d+)\]\s+(.+)',line)
        if match:
            columns=match.group(2).split()
            if len(columns)==10: section_flags[match.group(1)]=columns[6]
    reasons = []
    for name in sorted(REQUIRED):
        matches = [s for s in symbols if s['name'] == name]
        expected_type = 'OBJECT' if name == 'acp_state' else 'FUNC'
        if len(matches) != 1 or any(s['binding'] != 'GLOBAL' or s['visibility'] != 'DEFAULT' or s['index'] == 'UND' or s['type'] != expected_type for s in matches):
            reasons.append(name+':missing-or-unsupported-export')
        elif name == 'acp_state' and int(matches[0]['size']) != expected_state_bytes:
            reasons.append(name+':object-size')
        elif name == 'acp_state' and 'W' not in section_flags.get(matches[0]['index'],''):
            reasons.append(name+':object-not-writable')
    return {'status':'passed' if not reasons and r['exitCode']==0 and sections_result['exitCode']==0 else 'refused','accepted':not reasons and r['exitCode']==0 and sections_result['exitCode']==0,'reasons':reasons,'symbols':symbols,'sectionFlags':section_flags,'sectionsExecution':public_result(sections_result),'execution':public_result(r)}

def layout_assertions(source, receipt):
    """Emit GCC assertions using exact builtin kinds and canonical bindings."""
    nodes = _validated_graph(receipt)
    # Deterministic alias selection; every expression is checked below.
    bindings = sorted({(b['identity'], b['expression']) for b in receipt['gccTypeBindings']})
    expressions = {}
    for identity, expression in bindings:
        expressions.setdefault(identity, expression)
    source = str(source)
    if any(character in source for character in ('"', '\n', '\r', '\\')):
        raise ValueError('invalid assertion include path')
    lines = ['#include "' + source + '"']
    next_function = 0

    def qualify(name, qualifiers, pointer=False):
        qualifiers = ' '.join(q for mask,q in ((1,'const'),(2,'restrict'),(4,'volatile')) if qualifiers & mask)
        if not qualifiers:
            return name
        return name + ' ' + qualifiers if pointer else qualifiers + ' ' + name

    def type_name(d):
        nonlocal next_function
        kind = d['kind']
        if kind == 'integer':
            name = INTEGER_SPELLINGS[d['builtinKind']]
        elif kind == 'float':
            name = d['name']
        elif kind == 'void':
            name = 'void'
        elif kind in ('record','enum'):
            name = expressions[d['identity']]
        elif kind == 'pointer':
            if d['pointee']['kind'] == 'function':
                function = d['pointee']
                name = 'acp_assert_fn_' + str(next_function)
                next_function += 1
                result = type_name(function['return'])
                args = [type_name(p) for p in function['parameters']]
                if function['variadic']:
                    args.append('...')
                lines.append('typedef ' + result + ' (*' + name + ')(' + (', '.join(args) or 'void') + ');')
                return qualify(name, d['qualifiers'])
            return qualify(type_name(d['pointee']) + ' *', d['qualifiers'], pointer=True)
        else:
            raise ValueError('unsupported GCC assertion type')
        return qualify(name, d['qualifiers'])

    for identity, expression in bindings:
        node = nodes[identity]
        if node['kind'] == 'record':
            lines.extend([
                f'_Static_assert(sizeof({expression}) * 8 == {node["sizeBits"]}, "size");',
                f'_Static_assert(_Alignof({expression}) * 8 == {node["alignBits"]}, "align");',
            ])
            for field in node['fields']:
                lines.append(f'_Static_assert(__builtin_offsetof({expression}, {field["name"]}) * 8 == {field["offsetBits"]}, "offset");')
                name = type_name(field['type'])
                lines.append(f'_Static_assert(__builtin_types_compatible_p(__typeof__((({expression} *)0)->{field["name"]}), {name}), "field type");')
        else:
            name = type_name(node['integerType'])
            lines.append(f'_Static_assert(__builtin_types_compatible_p({expression}, {name}), "enum type");')
            for item in node['values']:
                lines.append(f'_Static_assert({item["name"]} == {item["value"]}, "enumerator");')
        # Ensure aliases claimed for a canonical identity agree within this TU.
        lines.append(f'_Static_assert(__builtin_types_compatible_p({expression}, {expressions[identity]}), "declaration identity");')
    for name in sorted(REQUIRED):
        descriptor = receipt['interfaces'][name]
        if descriptor['kind'] == 'function':
            result = type_name(descriptor['return'])
            args = [type_name(p) for p in descriptor['parameters']]
            if descriptor['variadic']:
                args.append('...')
            expected_name = 'acp_expected_' + name
            lines.append('typedef ' + result + ' ' + expected_name + '(' + (', '.join(args) or 'void') + ');')
            lines.append(f'_Static_assert(__builtin_types_compatible_p(__typeof__({name}), {expected_name}), "function type");')
        else:
            expected_name = type_name(descriptor)
            lines.append(f'_Static_assert(__builtin_types_compatible_p(__typeof__({name}), {expected_name}), "state type");')
    return '\n'.join(lines) + '\n'
