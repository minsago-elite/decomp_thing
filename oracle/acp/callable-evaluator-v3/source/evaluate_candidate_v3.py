"""V3 bounded process comparison. Internal library/API activity is unverified."""
import hashlib
import json
from pathlib import Path
from bounded_runtime import bounded_run, digest, private_directory, public_result, write_json
from build_contract import profile, load_profile, verify_visible, _read_json
from interface_gate_v3 import compare_descriptors, probe, export_inventory, layout_assertions, resolve_declaration
BASE = Path(__file__).resolve().parent
SCENARIO_FAMILIES = ['acp_mix'] * 8 + ['acp_pair_scale'] * 4 + ['acp_update'] * 4 + ['acp_apply'] * 4 + ['acp_fold'] * 4
PROOF_FLAGS = ('launcherCreated', 'launcherPidIdentityVerified', 'scopeVerified', 'scopeAdmitted', 'captureComplete', 'waitComplete', 'cleanupVerified')
PHASES = ('preprocess','compile','link','exports','declarations','gccAssertions','load','behavior')


def validate_exchange(name, value):
    """Pinned repository JSON-schema engine; no native tools or network resolution."""
    import fastjsonschema
    from freeze_v3 import read_regular
    schema = json.loads(read_regular(BASE / 'contracts' / (name + '-schema.json'),1048576))
    fastjsonschema.compile(schema)(value)
    if name == 'report':
        expected = summarize(value['scenarios'], value['admitted'])
        if any(value[key] != item for key, item in expected.items() if key != 'behaviorStatus'):
            raise ValueError('report accounting disagreement')
        if value['phases']['behavior']['status'] != expected['behaviorStatus']:
            raise ValueError('report behavior disagreement')
        admission = all(value['phases'][key]['status'] == 'passed' for key in ('preprocess','compile','link','exports','declarations','gccAssertions'))
        if value['admitted'] != admission:
            raise ValueError('report admission disagreement')
        expected_load = {'status':'unverified' if value['runtimeRequestCount'] else 'not-attempted','value':None}
        if value['phases']['load'] != expected_load:
            raise ValueError('load activity is unverified, not a process phase assertion')
        known = set(value['evidenceFiles'].values())
        references = [phase.get('evidenceSha256') for phase in value['phases'].values()] + [row['evidenceSha256'] for row in value['scenarios']]
        if any(sha is not None and sha not in known for sha in references):
            raise ValueError('unbound execution evidence reference')
        if any(row['runtimeRequested'] and row['evidenceSha256'] is None for row in value['scenarios']):
            raise ValueError('runtime request lacks retained execution evidence')
    return value


def read_exchange(path, name, maximum=8388608):
    value, _ = _read_json(Path(path), maximum)
    return validate_exchange(name, value)


def process_observation(result):
    result = result or {}
    flags = {key: result.get(key) is True for key in PROOF_FLAGS}
    exit_code = result.get('exitCode')
    known = type(exit_code) is int
    complete = (all(flags.values()) and known and result.get('rootReaped') is True
                and result.get('finalAbsenceVerified') is True
                and result.get('kernelScope', {}).get('finalAbsenceVerified') is True
                and all(result.get(key) is False for key in ('timedOut','outputExceeded','infrastructureFailure')))
    termination = ({'kind':'signal' if exit_code < 0 else 'exit', 'value':abs(exit_code)} if known else None)
    stdout, stderr = result.get('stdout'), result.get('stderr')
    streams_present = isinstance(stdout, bytes) and isinstance(stderr, bytes)
    complete = complete and streams_present
    # A missing/malformed stream is not an explicitly captured empty byte stream.
    # Retain each actually available byte stream; raw receipts preserve bad fields.
    stdout_hex = stdout.hex() if isinstance(stdout, bytes) else None
    stderr_hex = stderr.hex() if isinstance(stderr, bytes) else None
    return {**flags, 'completed':bool(complete), 'termination':termination,
            'stdoutHex':stdout_hex, 'stderrHex':stderr_hex,
            'timedOut':bool(result.get('timedOut')), 'outputExceeded':bool(result.get('outputExceeded')),
            'infrastructureFailure':bool(result.get('infrastructureFailure'))}


def compare_process(expected, result):
    actual = process_observation(result)
    if not actual['completed'] or not expected.get('completed'):
        return 'unknown', actual
    keys = ('stdoutHex','stderrHex','termination')
    return ('matched' if all(actual[key] == expected[key] for key in keys) else 'mismatched'), actual


def scenario_entry(obs, result=None, requested=False, evidence=None):
    status, process = compare_process(obs['process'], result) if requested else ('admission-refused', None)
    internal = {'status':'unverified' if requested else 'not-attempted', 'value':None}
    return {'id':obs['id'], 'family':obs['family'], 'status':status, 'runtimeRequested':requested,
            'process':process, 'evidenceSha256':evidence, 'loadObservation':dict(internal),
            'apiEntryObservation':dict(internal), 'apiCompletionObservation':dict(internal),
            'callbackObservation':dict(internal)}


def summarize(scenarios, admitted):
    if len(scenarios) != 24 or [s['id'] for s in scenarios] != list(range(24)) or [s['family'] for s in scenarios] != SCENARIO_FAMILIES:
        raise ValueError('exact scenario identity/family coverage required')
    if any(s['runtimeRequested'] != admitted for s in scenarios):
        raise ValueError('runtime request/admission disagreement')
    for row in scenarios:
        process = row['process']
        if admitted:
            if process is None or row['status'] not in ('matched','mismatched','unknown'):
                raise ValueError('requested process evidence required')
            if (row['status'] in ('matched','mismatched')) != process['completed']:
                raise ValueError('process completion/status disagreement')
        elif row['status'] != 'admission-refused' or process is not None:
            raise ValueError('refused admission has process evidence')
        internal = {'status':'unverified' if admitted else 'not-attempted','value':None}
        if any(row[key] != internal for key in ('loadObservation','apiEntryObservation','apiCompletionObservation','callbackObservation')):
            raise ValueError('internal API activity is unverified')
    count = lambda status: sum(s['status'] == status for s in scenarios)
    completed = count('matched') + count('mismatched')
    matched, mismatched, unknown = count('matched'), count('mismatched'), count('unknown')
    return {'scenarioCount':24, 'runtimeRequestCount':sum(s['runtimeRequested'] for s in scenarios),
            'launcherCreatedCount':sum(bool(s['process'] and s['process']['launcherCreated']) for s in scenarios),
            'scopeVerifiedCount':sum(bool(s['process'] and s['process']['scopeVerified']) for s in scenarios),
            'completedScenarioProcessCount':completed, 'matchedScenarioProcessCount':matched,
            'mismatchedScenarioProcessCount':mismatched, 'unknownScenarioProcessCount':unknown,
            'admissionRefusedCount':count('admission-refused'),
            'processBehaviorRate':matched/completed if completed else None, 'processCoverage':completed/24,
            'apiEntryCount':None, 'apiCompletionCount':None, 'callbackCount':None,
            'apiCoverage':None, 'apiBehaviorRate':None,
            'behaviorStatus':('not-attempted' if not admitted else 'failed' if mismatched else 'passed' if matched == 24 else 'unknown')}


def environment(work):
    return {'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C','HOME':str(work),'TMPDIR':str(work),'TMP':str(work),'TEMP':str(work)}


def phase_command(work, arguments):
    command=['/usr/bin/bwrap','--unshare-all','--unshare-user','--die-with-parent','--new-session','--disable-userns','--cap-drop','ALL','--clearenv']
    for directory in ('/usr','/lib','/lib64'):
        if Path(directory).exists(): command += ['--ro-bind',directory,directory]
    return command+['--proc','/proc','--dev','/dev','--remount-ro','/dev','--size',str(load_profile()['bounds']['temporaryFilesystemBytes']),'--tmpfs','/tmp','--bind',str(work),'/work','--chdir','/work',*sum((['--setenv',k,v] for k,v in load_profile()['environment'].items()),[]),*arguments]


def runtime_command(caller, library, scenario):
    command=['/usr/bin/bwrap','--unshare-all','--unshare-user','--die-with-parent','--new-session','--disable-userns','--cap-drop','ALL','--clearenv']
    for directory in ('/usr','/lib','/lib64'):
        if Path(directory).exists(): command += ['--ro-bind',directory,directory]
    return command+['--proc','/proc','--dev','/dev','--remount-ro','/dev','--size',str(load_profile()['bounds']['temporaryFilesystemBytes']),'--tmpfs','/tmp','--dir','/workspace','--ro-bind',str(caller),'/caller','--ro-bind',str(library),'/library.so','--chdir','/workspace','--remount-ro','/',*sum((['--setenv',k,v] for k,v in load_profile()['environment'].items()),[]),'/caller','/library.so',str(scenario)]


def run(argv, work, timeout=None, phase='compiler'):
    p = load_profile()
    try:
        r=bounded_run(argv,work,environment(work),timeout=timeout if timeout is not None else p['bounds']['compilerSeconds'],output_limit=p['bounds']['outputBytesPerStream'],managed_scope=True,phase=phase)
        obs = process_observation(r)
        return {'status':('passed' if r['exitCode']==0 else 'failed') if obs['completed'] else 'unknown','execution':public_result(r)},r
    except Exception as e:
        r=getattr(e,'bounded_result',None)
        return {'status':'unknown','reason':type(e).__name__+':'+str(e)[:300], 'execution':public_result(r) if r else None},r


def validated_observations(path, caller):
    if not path.resolve(strict=True).is_relative_to(BASE):
        raise ValueError('observations outside trusted v3 namespace')
    value=read_exchange(path,'reference-observations')
    if value['sourceSha256']!=digest(BASE/'private/original.c') or value['callerSha256']!=digest(caller):
        raise ValueError('reference observations do not bind current fixture/caller')
    observations=value['observations']
    if [o['id'] for o in observations]!=list(range(24)) or [o['family'] for o in observations]!=SCENARIO_FAMILIES:
        raise ValueError('scenario identity drift')
    for obs in observations:
        if not obs['process']['completed'] or not all(obs['process'][flag] for flag in PROOF_FLAGS):
            raise ValueError('incomplete reference process')
        for field in ('stdoutHex','stderrHex'):
            if len(bytes.fromhex(obs['process'][field]))>load_profile()['bounds']['outputBytesPerStream']:
                raise ValueError('observation output exceeds bound')
        receipt_path=path.parent/('reference-process-'+str(obs['id'])+'.json')
        if digest(receipt_path)!=obs['evidenceSha256']:
            raise ValueError('reference process receipt drift')
        receipt,_=_read_json(receipt_path,1048576)
        execution=receipt.get('execution')
        if not isinstance(execution,dict):raise ValueError('reference execution evidence missing')
        execution={**execution,'stdout':bytes.fromhex(execution['stdoutHex']),'stderr':bytes.fromhex(execution['stderrHex'])}
        if process_observation(execution)!=obs['process']:
            raise ValueError('reference normalized process disagrees with raw evidence')
    return observations


def evaluate(candidate, output, helper, caller, visible, observations_path):
    if 'build/acp-decomp-effectiveness/callable-library-v3' not in str(BASE):
        raise ValueError('execution requires trusted v3 source copy')
    for path in (candidate,helper,caller,visible,observations_path):
        if not path.resolve(strict=True).is_relative_to(BASE): raise ValueError('input outside trusted v3 namespace')
    verify_visible(visible)
    observations=validated_observations(observations_path,caller)
    p=profile(); output=private_directory(output); work=private_directory(output/'work')
    evidence={}
    def retain(name, value):
        path=output/(name+'.json');write_json(path,value);sha=digest(path);evidence[path.name]=sha;return sha
    def phase_receipt(name, value):
        return {'status':value['status'], 'reason':str(value.get('reason',''))[:500], 'evidenceSha256':retain(name,value)}
    raw=candidate.read_bytes()
    if len(raw)>p['bounds']['sourceBytes'] or b'\0' in raw: raise ValueError('source bound')
    raw.decode('utf8'); (work/'candidate.c').write_bytes(raw)
    phases={n:{'status':'not-attempted','reason':'prior-phase-not-passed','evidenceSha256':None} for n in PHASES}
    for phase in ('preprocess','compile','link'):
        status,result=run(phase_command(work,p['commands'][phase]),work)
        phases[phase]=phase_receipt(phase,status)
        if status['status']!='passed':break
    expected=None;actual=None
    if phases['preprocess']['status']=='passed':
        try:
            expected_work=private_directory(output/'expected-probe-work')
            for name in ('original.c','original.h'):(expected_work/name).write_bytes((BASE/'private'/name).read_bytes())
            expected=probe(expected_work/'original.c',helper,expected_work,environment(expected_work))
            retain('expected-descriptors',expected)
            actual=probe(work/'candidate.i',helper,work,environment(work))
            retain('candidate-descriptors',actual)
            phases['declarations']=phase_receipt('declarations',compare_descriptors(expected,actual))
        except Exception as error:
            failure={'status':'unknown','reason':str(error)[:300]}
            if hasattr(error,'bounded_result'):failure['execution']=public_result(error.bounded_result)
            phases['declarations']=phase_receipt('declarations',failure)
    checks={'expected':{'status':'unknown','reason':'not-completed'},'candidate':{'status':'unknown','reason':'not-completed'}}
    if phases['declarations']['status']=='passed':
        for label,receipt in (('expected',expected),('candidate',actual)):
            try:
                assertion_work=work
                source=Path('/work/candidate.i')
                if label=='expected':
                    assertion_work=private_directory(output/'expected-gcc-work')
                    (assertion_work/'expected.c').write_bytes((BASE/'private/original.c').read_bytes())
                    (assertion_work/'original.h').write_bytes((BASE/'private/original.h').read_bytes())
                    pre,_=run(phase_command(assertion_work,['/usr/bin/gcc','-E','-P','-std=c11','/work/expected.c','-o','/work/expected.i']),assertion_work)
                    retain('gcc-expected-preprocess',pre)
                    if pre['status']!='passed':raise ValueError('expected preprocessing incomplete')
                    source=Path('/work/expected.i')
                assertions=assertion_work/(label+'-assertions.c');assertions.write_text(layout_assertions(source,receipt))
                checks[label],_=run(phase_command(assertion_work,['/usr/bin/gcc','-std=c11','-Werror','-fsyntax-only','/work/'+assertions.name]),assertion_work)
            except Exception as e:checks[label]={'status':'unknown','reason':str(e)[:300]}
        status='passed' if all(c['status']=='passed' for c in checks.values()) else 'unknown' if any(c['status'] in ('unknown','not-attempted') for c in checks.values()) else 'failed'
        phases['gccAssertions']=phase_receipt('gcc-assertions',{'status':status,'checks':checks})
    if phases['link']['status']=='passed':
        try:
            size=resolve_declaration(expected,expected['interfaces']['acp_state'])['sizeBits']//8 if expected and expected.get('status')=='supported' else -1
            phases['exports']=phase_receipt('exports',export_inventory(work/'libcandidate.so',size,work,environment(work)))
        except Exception as error:
            failure={'status':'unknown','reason':str(error)[:300]}
            if hasattr(error,'bounded_result'):failure['execution']=public_result(error.bounded_result)
            phases['exports']=phase_receipt('exports',failure)
    admitted=all(phases[n]['status']=='passed' for n in ('preprocess','compile','link','exports','declarations','gccAssertions'))
    scenarios=[]
    for obs in observations:
        result=None;sha=None
        if admitted:
            status,result=run(runtime_command(caller,work/'libcandidate.so',obs['id']),work,timeout=p['bounds']['runtimeSeconds'],phase='runtime')
            sha=retain('scenario-'+str(obs['id']),status)
        scenarios.append(scenario_entry(obs,result,admitted,sha))
    summary=summarize(scenarios,admitted)
    phases['load']={'status':'unverified' if summary['runtimeRequestCount'] else 'not-attempted','value':None}
    phases['behavior']={'status':summary.pop('behaviorStatus'),'reason':'completed-process-bytes-and-termination','evidenceSha256':None}
    report={'schemaVersion':3,'schema':'callable-library-candidate-evaluation-v3','candidateSha256':digest(candidate),'profileSha256':digest(BASE/'contracts/candidate-build-profile.json'),'phases':phases,'admitted':admitted,**summary,'scenarios':scenarios,'evidenceFiles':evidence,'formalStructuralScore':None,'abiAccuracy':'unassessed','productionFactoryQualified':False,'productionProviderQualified':False,'productionFilesystemQualified':False}
    validate_exchange('report',report);write_json(output/'receipt.json',report);return report
