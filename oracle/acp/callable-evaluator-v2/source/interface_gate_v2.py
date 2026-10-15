"""Independent export and structural declaration admission; never loads a library."""
import json
import re
from pathlib import Path
from bounded_runtime import bounded_run, public_result, digest
from build_contract import profile
REQUIRED = {'acp_mix','acp_pair_scale','acp_update','acp_apply','acp_fold','acp_state'}
def compare_descriptors(expected, actual):
    if expected.get('status') != 'supported' or actual.get('status') != 'supported':
        return {'accepted':False,'status':'unknown','reason':'unsupported-or-unresolved-declaration'}
    if set(expected.get('interfaces',{})) != REQUIRED or set(actual.get('interfaces',{})) != REQUIRED:
        return {'accepted':False,'status':'unknown','reason':'missing-interface-identity'}
    differences = [n for n in sorted(REQUIRED) if expected['interfaces'][n] != actual['interfaces'][n]]
    target_equal = expected.get('target') == actual.get('target') and expected.get('dataLayout') == actual.get('dataLayout')
    return {'accepted':not differences and target_equal,'status':'passed' if not differences and target_equal else 'refused','differences':differences,'targetEqual':target_equal}
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
    result = bounded_run(probe_command(helper,work,[argument]),work,environment,timeout=profile()['bounds']['compilerSeconds'],output_limit=profile()['bounds']['helperOutputBytesPerStream'],managed_scope=True)
    receipt = public_result(result)
    bindings['inputsUnchanged']=bindings['sourceSha256']==digest(source) and bindings['helperSha256']==digest(helper)
    receipt['inputBindings']=bindings
    if not bindings['inputsUnchanged']:raise ValueError('probe inputs changed during execution')
    if result['exitCode'] not in (0,2):
        return {'status':'refused','diagnostics':['syntax-or-probe-failure'],'execution':receipt,'inputBindings':bindings}
    value = json.loads(result['stdout'])
    if value.get('schemaVersion') != 2:
        raise ValueError('unexpected helper schema')
    value['inputBindings']=bindings
    value['execution'] = receipt
    return value

def export_inventory(library, expected_state_bytes, work, environment):
    r = bounded_run(['/usr/bin/readelf','--dyn-syms','--wide',str(library)],work,environment,timeout=10,managed_scope=True)
    symbols = []
    for line in r['stdout'].decode('utf8',errors='strict').splitlines():
        parts = line.split()
        if len(parts) == 8 and parts[0].rstrip(':').isdigit():
            symbols.append(dict(zip(('number','value','size','type','binding','visibility','index','name'),parts)))
    sections_result=bounded_run(['/usr/bin/readelf','--section-headers','--wide',str(library)],work,environment,timeout=10,managed_scope=True)
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
    """Bind every reachable record/enum to AST-emitted GCC expressions."""
    bindings=receipt.get('gccTypeBindings',[])
    def reachable(d):
        result=[]
        if isinstance(d,dict):
            if d.get('kind') in ('record','enum'): result.append(d)
            for value in d.values(): result.extend(reachable(value))
        elif isinstance(d,list):
            for value in d: result.extend(reachable(value))
        return result
    needed=reachable(receipt.get('interfaces',{}))
    for d in needed:
        if not any(b.get('descriptor')==d for b in bindings):
            raise ValueError('helper omitted reachable GCC declaration binding')
    lines=['#include "'+str(source)+'"']
    def type_name(d):
        k=d['kind']
        if k=='integer':
            types={8:'char',16:'short',32:'int',64:'long'}
            return ('signed ' if d['signed'] else 'unsigned ')+types[d['bits']]
        if k=='float': return d['name']
        if k=='void': return 'void'
        if k=='enum': return type_name(d['integerType'])
        if k=='record':
            return next(b['expression'] for b in bindings if b['descriptor']==d)
        if k=='pointer':
            if d['pointee']['kind']=='function':
                f=d['pointee']; name='acp_assert_fn_'+str(len(lines))
                args=[type_name(p) for p in f['parameters']]
                if f['variadic']: args.append('...')
                lines.append('typedef '+type_name(f['return'])+' (*'+name+')('+(', '.join(args) or 'void')+');')
                return name
            return type_name(d['pointee'])+' *'
        raise ValueError('unsupported GCC assertion type')
    for b in bindings:
        expr=b['expression']; d=b['descriptor']
        if not isinstance(expr,str) or '\n' in expr or ';' in expr:
            raise ValueError('invalid assertion type expression')
        if d['kind']=='record':
            lines += [f'_Static_assert(sizeof({expr}) * 8 == {d["sizeBits"]}, "size");',f'_Static_assert(_Alignof({expr}) * 8 == {d["alignBits"]}, "align");']
            for f in d['fields']:
                if not f['name'].isidentifier(): raise ValueError('invalid field identity')
                lines.append(f'_Static_assert(__builtin_offsetof({expr}, {f["name"]}) * 8 == {f["offsetBits"]}, "offset");')
                t=type_name(f['type'])
                lines.append(f'_Static_assert(__builtin_types_compatible_p(__typeof__((({expr} *)0)->{f["name"]}), {t}), "field type");')
        elif d['kind']=='enum':
            t=type_name(d['integerType'])
            lines.append(f'_Static_assert(__builtin_types_compatible_p({expr}, {t}), "enum type");')
            for item in d['values']:
                if not item['name'].isidentifier(): raise ValueError('invalid enumerator')
                lines.append(f'_Static_assert({item["name"]} == {item["value"]}, "enumerator");')
    for name,d in receipt['interfaces'].items():
        if name not in REQUIRED: raise ValueError('unexpected required symbol')
        if d['kind']=='function':
            args=[type_name(p) for p in d['parameters']]
            if d['variadic']: args.append('...')
            expected_name='acp_expected_'+name
            lines.append('typedef '+type_name(d['return'])+' '+expected_name+'('+(', '.join(args) or 'void')+');')
            lines.append(f'_Static_assert(__builtin_types_compatible_p(__typeof__({name}), {expected_name}), "function type");')
        else:
            t=type_name(d)
            lines.append(f'_Static_assert(__builtin_types_compatible_p(__typeof__({name}), {t}), "state type");')
    return '\n'.join(lines)+'\n'
