"""V3 bounded process comparison. Internal library/API activity is unverified."""
import hashlib
import json
import os
import stat
import uuid
import re
from contextvars import ContextVar
from copy import deepcopy
from pathlib import Path
from bounded_runtime import (bounded_run, digest, private_directory, public_result, write_json,
                             worker_execution_complete, contained_command)
from worker_exec_proof import parse_proof, MAX_PROOF_BYTES
from build_contract import profile, load_profile, verify_visible, _read_json
from interface_gate_v3 import compare_descriptors, probe, export_inventory, layout_assertions, resolve_declaration
BASE = Path(__file__).resolve().parent
SCENARIO_FAMILIES = ['acp_mix'] * 8 + ['acp_pair_scale'] * 4 + ['acp_update'] * 4 + ['acp_apply'] * 4 + ['acp_fold'] * 4
PROOF_FLAGS = ('launcherCreated', 'launcherPidIdentityVerified', 'scopeVerified', 'scopeAdmitted', 'captureComplete', 'waitComplete', 'cleanupVerified', 'workerExecVerified', 'workerTerminationVerified')
PHASES = ('preprocess','compile','link','exports','declarations','gccAssertions','load','behavior')


def validate_exchange(name, value):
    """Pinned repository JSON-schema engine; no native tools or network resolution."""
    import fastjsonschema
    from freeze_v3 import read_regular
    schema = json.loads(read_regular(BASE / 'contracts' / (name + '-schema.json'),1048576))
    fastjsonschema.compile(schema)(value)
    if name == 'reference-observations':
        for row in value['observations']:
            if not observation_complete(row['process']) or not row['process']['completed']:
                raise ValueError('reference requires complete protected worker evidence')
            _bound_runtime_inputs(row['process'],{'caller':{'path':value['callerPath'],'sha256':value['callerSha256']},'library':{'path':value['libraryPath'],'sha256':value['librarySha256']}},value['profileSha256'])
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
        if value['admitted'] != (value['runtimeInputs'] is not None):
            raise ValueError('runtime input binding/admission disagreement')
        for row in value['scenarios']:
            if row['process'] and row['process']['completed']:
                _bound_runtime_inputs(row['process'],value['runtimeInputs'],value['profileSha256'])
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


def _hex_stream(result, label):
    if label in result:
        return result[label].hex() if type(result[label]) is bytes else None
    value = result.get(label + 'Hex')
    return value if type(value) is str and re.fullmatch(r'(?:[0-9a-f]{2})*', value) else None


def _proof_bytes(result):
    if 'workerProofRaw' in result:
        value = result['workerProofRaw']
        return value if type(value) is bytes and len(value) <= MAX_PROOF_BYTES else b''
    text = result.get('workerProofRawHex')
    if type(text) is str and len(text) <= 2 * MAX_PROOF_BYTES and re.fullmatch(r'(?:[0-9a-f]{2})*', text):
        return bytes.fromhex(text)
    return b''


def _proof_replays(result):
    if not worker_execution_complete(result):
        return False
    try:
        raw = _proof_bytes(result)
        parsed = parse_proof(raw, result['workerProofBindings']['expected'])
        return (parsed['status'] == 'verified' and parsed['proofSha256'] == result['workerProof']['proofSha256']
                and parsed['workerTermination'] == result['workerTermination']
                and parsed['exitCode'] == result['exitCode'])
    except (KeyError, TypeError, ValueError):
        return False


def process_observation(result):
    result = result if type(result) is dict else {}
    bounds = result.get('bounds') if type(result.get('bounds')) is dict else {}
    phase = bounds.get('phase')
    profile_sha = bounds.get('profileSha256')
    profile_sha = profile_sha if type(profile_sha) is str and re.fullmatch('[0-9a-f]{64}', profile_sha) else None
    # Retain controller-authenticated diagnostic facts. Only a replayed protected
    # exec+terminal proof and the complete controller chain produce behavior.
    complete = _proof_replays(result) and phase == 'runtime'
    worker_term = result.get('workerTermination')
    if (type(worker_term) is not dict or set(worker_term) != {'kind','value','rawWaitStatus'}
            or worker_term['kind'] not in ('exit','signal')
            or type(worker_term['value']) is not int or type(worker_term['rawWaitStatus']) is not int):
        worker_term = None
    return {**{key:result.get(key) is True for key in PROOF_FLAGS},
            'rootReaped':result.get('rootReaped') is True,
            'finalAbsenceVerified':result.get('finalAbsenceVerified') is True,
            'scopeAbsenceVerified':type(result.get('kernelScope')) is dict and result['kernelScope'].get('finalAbsenceVerified') is True,
            'launcherExitCode':result.get('launcherExitCode') if type(result.get('launcherExitCode')) is int else None,
            'workerExitCode':result.get('exitCode') if type(result.get('exitCode')) is int else None,
            'provisioningOnly':result.get('provisioningOnly') if type(result.get('provisioningOnly')) is bool else None,
            'phase':phase if phase in ('runtime','compiler','probe','elf-inspection','caller-build','helper-build','toolchain-inspection','unspecified') else None,
            'profileSha256':profile_sha,
            'workerProof':deepcopy(result.get('workerProof')) if type(result.get('workerProof')) is dict else None,
            'workerProofBindings':deepcopy(result.get('workerProofBindings')) if type(result.get('workerProofBindings')) is dict else None,
            'launchInputPins':deepcopy(result.get('launchInputPins')) if type(result.get('launchInputPins')) is dict else None,
            'workerProofRawHex':_proof_bytes(result).hex(),
            'workerTermination':deepcopy(worker_term), 'completed':complete,
            'termination':({'kind':worker_term['kind'],'value':worker_term['value']} if complete else None),
            'stdoutHex':_hex_stream(result,'stdout'), 'stderrHex':_hex_stream(result,'stderr'),
            'streamsUnambiguous':not any(label in result and label+'Hex' in result for label in ('stdout','stderr')),
            **{key:result.get(key) if type(result.get(key)) is bool else None
               for key in ('timedOut','outputExceeded','infrastructureFailure')}}


def observation_complete(value):
    if type(value) is not dict or value.get('phase') != 'runtime' or value.get('streamsUnambiguous') is not True:
        return False
    raw = {key:value.get(key) for key in (*PROOF_FLAGS,'rootReaped','finalAbsenceVerified','launcherExitCode',
           'provisioningOnly','workerProof','workerProofBindings','launchInputPins','workerProofRawHex',
           'workerTermination','stdoutHex','stderrHex','timedOut','outputExceeded','infrastructureFailure')}
    raw.update(exitCode=value.get('workerExitCode'),
               kernelScope={'finalAbsenceVerified':value.get('scopeAbsenceVerified')},
               bounds={'phase':value.get('phase'),'profileSha256':value.get('profileSha256')})
    term=value.get("workerTermination")
    return (_proof_replays(raw) and type(term) is dict
            and value.get("termination")=={"kind":term["kind"],"value":term["value"]})


def compare_process(expected, result):
    actual = process_observation(result)
    if not actual['completed'] or expected.get('completed') is not True or not observation_complete(expected):
        return 'unknown', actual
    # Proof identities/PIDs/nonces differ per invocation. They establish usable
    # observation provenance, never the behavior equality criterion.
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
            if process['completed'] != observation_complete(process):
                raise ValueError('worker proof/controller completion disagreement')
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
    return dict(load_profile()['environment'])



def control_passed(control, report):
    """Pure finite preflight policy shared with the trusted coordinator.

    Reports must already satisfy their closed schema/accounting contract. This
    predicate grants no runtime or native-qualification authority.
    """
    kind = control['expected']
    if kind == 'matched':
        return report['admitted'] and report['matchedScenarioProcessCount'] == 24 and report['unknownScenarioProcessCount'] == 0
    if kind == 'mismatched':
        return report['admitted'] and report['mismatchedScenarioProcessCount'] > 0 and report['phases']['behavior']['status'] == 'failed'
    if kind == 'unknown':
        return report['admitted'] and report['unknownScenarioProcessCount'] > 0
    return (not report['admitted'] and report['runtimeRequestCount'] == 0 and report['admissionRefusedCount'] == 24
            and report['phases'][control['stage']]['status'] in (('failed',) if kind == 'build-failed' else ('refused', 'unknown')))


def phase_command(work, arguments, read_only_files=()):
    command=['/usr/bin/bwrap','--unshare-all','--unshare-user','--die-with-parent','--new-session','--disable-userns','--cap-drop','ALL','--clearenv']
    for directory in ('/usr','/lib','/lib64'):
        if Path(directory).exists(): command += ['--ro-bind',directory,directory]
    for path in load_profile()['analysisIsolation']['readOnlySystemFiles']:
        command += ['--ro-bind',path,path]
    command += ['--proc','/proc','--dev','/dev','--remount-ro','/dev','--size',str(load_profile()['bounds']['temporaryFilesystemBytes']),'--tmpfs','/tmp','--bind',str(work),'/work']
    for source in read_only_files:
        source=Path(source)
        if source != source.resolve(strict=True) or not source.is_file() or not source.is_relative_to(work):
            raise ValueError('compiler input must be an explicit canonical file inside its isolated leaf')
        command += ['--ro-bind',str(source),'/work/'+str(source.relative_to(work))]
    return command+['--chdir','/work',*sum((['--setenv',k,v] for k,v in environment(work).items()),[]),*arguments]


def runtime_command(caller, library, scenario):
    command=['/usr/bin/bwrap','--unshare-all','--unshare-user','--die-with-parent','--new-session','--disable-userns','--cap-drop','ALL','--clearenv']
    for directory in ('/usr','/lib','/lib64'):
        if Path(directory).exists(): command += ['--ro-bind',directory,directory]
    for path in load_profile()['analysisIsolation']['readOnlySystemFiles']:
        command += ['--ro-bind',path,path]
    return command+['--proc','/proc','--dev','/dev','--remount-ro','/dev','--size',str(load_profile()['bounds']['temporaryFilesystemBytes']),'--tmpfs','/tmp','--dir','/workspace','--ro-bind',str(caller),'/caller','--ro-bind',str(library),'/library.so','--chdir','/workspace','--remount-ro','/',*sum((['--setenv',k,v] for k,v in load_profile()['environment'].items()),[]),'/caller','/library.so',str(scenario)]


def run(argv, work, timeout=None, phase='compiler'):
    # Associate the same cleanup result with every owned mount source, not
    # just the writable cwd. Runtime mounts the link leaf's library read-only.
    mounted = [Path(argv[index + 1]) for index, argument in enumerate(argv[:-1])
               if argument in ('--bind', '--ro-bind', '--bind-try', '--ro-bind-try')]
    return _leaf_call(work, lambda: _run(argv, work, timeout, phase), mounted)


def _run(argv, work, timeout=None, phase='compiler'):
    p = load_profile()
    try:
        if not argv or argv[0] != '/usr/bin/bwrap':
            raise ValueError('worker requires an explicit contained recipe')
        r=bounded_run(argv,work,environment(work),timeout=timeout if timeout is not None else p['bounds']['compilerSeconds'],output_limit=p['bounds']['outputBytesPerStream'],managed_scope=True,phase=phase)
        complete = (_proof_replays(r) and r["bounds"]["phase"] == phase
                    and r["bounds"]["profileSha256"] == digest(BASE/"contracts/candidate-build-profile.json"))
        return {'status':('passed' if r['exitCode']==0 else 'failed') if complete else 'unknown','execution':public_result(r)},r
    except Exception as e:
        r=getattr(e,'bounded_result',None)
        return {'status':'unknown','reason':type(e).__name__+':'+str(e)[:300], 'execution':public_result(r) if r else None},r


# Invocation-local authority: no pathname discovered from a previous run grants
# reclamation rights. Held directory descriptors survive pathname replacement.
_LEAF_SCOPE = ContextVar('candidate_worker_leaves', default=None)


def _cleanup_proven(result):
    return (type(result) is dict and all(result.get(key) is True for key in
            ('cleanupVerified', 'finalAbsenceVerified', 'rootReaped', 'scopeVerified', 'scopeAdmitted'))
            and type(result.get('kernelScope')) is dict
            and result['kernelScope'].get('finalAbsenceVerified') is True)


class WorkerLeaves:
    def __init__(self):
        self.leaves = {}

    def own(self, path):
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        self.leaves[path] = {'fd': fd, 'identity': os.fstat(fd), 'safe': True}

    def call(self, path, operation, mounted=()):
        involved = [row for leaf, row in self.leaves.items()
                    if leaf == path or any(source == leaf or source.is_relative_to(leaf)
                                           for source in mounted)]
        if not involved:
            return operation()
        prior = [row['safe'] for row in involved]
        for row in involved: row['safe'] = False
        try:
            value = operation()
        except BaseException as error:
            proven = _cleanup_proven(getattr(error, 'bounded_result', None))
            for row, was_safe in zip(involved, prior): row['safe'] = was_safe and proven
            raise
        results = ([value[1]] if type(value) is tuple else
                   [value.get(key) for key in ('execution', 'sectionsExecution') if key in value])
        proven = bool(results) and all(_cleanup_proven(r) for r in results)
        for row, was_safe in zip(involved, prior): row['safe'] = was_safe and proven
        return value

    def close(self):
        # Outputs have been consumed before this invocation-final cleanup. Only
        # bounded flat leaves are reclaimed; unexpected trees remain for audit.
        for path, row in self.leaves.items():
            fd = row['fd']
            try:
                if not row['safe']:
                    continue
                held = row['identity']; current = path.lstat()
                if (current.st_dev, current.st_ino) != (held.st_dev, held.st_ino):
                    continue
                # Reopen the held directory itself for a fresh enumeration
                # (some filesystems snapshot entries when the FD is opened).
                scan_fd = os.open('.', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC, dir_fd=fd)
                names = []
                try:
                    with os.scandir(scan_fd) as scan:
                        for entry in scan:
                            names.append(entry.name)
                            if len(names) > 256: break
                finally:
                    os.close(scan_fd)
                if len(names) > 256:
                    continue
                entries = {name: os.stat(name, dir_fd=fd, follow_symlinks=False) for name in names}
                if any(not (stat.S_ISREG(v.st_mode) or stat.S_ISLNK(v.st_mode)) for v in entries.values()):
                    continue
                for name, before in entries.items():
                    after = os.stat(name, dir_fd=fd, follow_symlinks=False)
                    if (before.st_dev, before.st_ino, before.st_mode) != (after.st_dev, after.st_ino, after.st_mode):
                        raise ValueError('worker leaf entry changed during cleanup')
                    os.unlink(name, dir_fd=fd)
                # rmdir never follows a replacement symlink; identity is checked
                # again immediately before removing this exact owned leaf.
                current = path.lstat()
                if (current.st_dev, current.st_ino) == (held.st_dev, held.st_ino):
                    os.rmdir(path)
            except (OSError, ValueError):
                pass  # Reclamation cannot replace the evaluation's primary result.
            finally:
                try: os.close(fd)
                except OSError: pass


def _leaf_call(path, operation, mounted=()):
    scope = _LEAF_SCOPE.get()
    return scope.call(path, operation, mounted) if scope is not None else operation()


def new_worker_leaf(label):
    """One controller-owned empty leaf, never an output/control/source parent."""
    if label not in ('preprocess','compile','link','probe','assertions','expected-preprocess','inspection','runtime','caller-build'):
        raise ValueError('unknown worker leaf role')
    parent=BASE/'worker-work'
    parent.mkdir(mode=0o700,exist_ok=True)
    metadata=parent.lstat()
    if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid!=os.getuid()
            or stat.S_IMODE(metadata.st_mode)&0o077 or parent.resolve()!=parent):
        raise ValueError('worker leaf parent must be private, owned and canonical')
    leaf = private_directory(parent/(label+'-'+uuid.uuid4().hex))
    scope = _LEAF_SCOPE.get()
    if scope is not None: scope.own(leaf)
    return leaf


def copy_input(source, destination, *, executable=False):
    """Bounded controller copy after the producing worker has fully stopped."""
    from freeze_v3 import read_regular
    source=Path(source);destination=Path(destination)
    data=read_regular(source,load_profile()['bounds']['fileSizeBytes'])
    with destination.open('xb') as stream:stream.write(data)
    destination.chmod(0o500 if executable else 0o400)
    return destination


def compile_sequence(source, headers=(), retain=None):
    """Unchanged profile argv; isolated leaf and exact RO inputs per phase."""
    p=load_profile();files={};statuses={};previous=Path(source)
    for phase,input_name,output_name in (('preprocess','candidate.c','candidate.i'),('compile','candidate.i','candidate.o'),('link','candidate.o','libcandidate.so')):
        leaf=new_worker_leaf(phase)
        inputs=[copy_input(previous,leaf/input_name)]
        if phase=='preprocess':
            inputs += [copy_input(header,leaf/Path(header).name) for header in headers]
        status,result=run(phase_command(leaf,p['commands'][phase],read_only_files=inputs),leaf)
        output=leaf/output_name
        if status['status']=='passed':
            try:
                from freeze_v3 import read_regular
                read_regular(output,p['bounds']['fileSizeBytes'])
            except (OSError,ValueError):
                status={**status,'status':'unknown','reason':'compiler output missing or outside bounded regular-file policy'}
        statuses[phase]=status
        if retain is not None:retain(phase,status)
        if status['status']!='passed':break
        files[phase]=output;previous=output
    return statuses,files


def _bound_runtime_inputs(process, inputs, profile_sha, admitted_pins=None):
    if process.get('profileSha256')!=profile_sha:
        raise ValueError('process profile binding differs')
    pins=process.get('launchInputPins') or {}
    for item in inputs.values():
        path=Path(item['path'])
        if not path.is_absolute() or '..' in path.parts or str(path)!=item['path']:
            raise ValueError('runtime input path is not canonical')
        if admitted_pins is not None and pins.get(item['path'])!=admitted_pins.get(item['path']):
            raise ValueError('runtime input physical identity differs from admitted preparation')
        if pins.get(item['path'],{}).get('sha256')!=item['sha256']:
            raise ValueError('runtime input file binding missing or changed')
    binding=process.get('workerProofBindings') or {}
    expected=binding.get('expected') or {}
    caller_pin=pins.get(inputs['caller']['path'],{})
    if (binding.get('targetSha256')!=inputs['caller']['sha256']
            or (caller_pin.get('device'),caller_pin.get('inode'))!=(expected.get('targetDevice'),expected.get('targetInode'))):
        raise ValueError('runtime target is not the bound caller')


def validated_observations(path, caller, preparation):
    # The coordinator chooses this root separately from the observation JSON.
    # Fixed names cannot be redirected by a self-consistent receipt/pin row.
    from freeze_v3 import admit_files, TreeBudget
    preparation=Path(preparation)
    if preparation!=preparation.resolve(strict=True) or not preparation.is_relative_to(BASE):
        raise ValueError('reference preparation root outside trusted v3 namespace')
    library=preparation/'reference/libcandidate.so'
    if path!=preparation/'reference-observations.json' or caller!=preparation/'caller':
        raise ValueError('reference paths differ from independently selected preparation')
    def admitted():
        return admit_files((caller,library),TreeBudget(files=2,bytes=2*load_profile()['bounds']['fileSizeBytes']),root=preparation)['files']
    inputs=admitted()
    expected_pins={name:{'device':record['identity'][0],'inode':record['identity'][1],
                         'mode':stat.S_IMODE(record['identity'][2]),'sha256':record['sha256']}
                   for name,record in inputs.items()}
    if not path.resolve(strict=True).is_relative_to(BASE):
        raise ValueError('observations outside trusted v3 namespace')
    value=read_exchange(path,'reference-observations')
    if (value['sourceSha256']!=digest(BASE/'private/original.c') or value['callerSha256']!=inputs[str(caller)]['sha256']
            or value['callerPath']!=str(caller)
            or value['libraryPath']!=str(library)
            or value['librarySha256']!=inputs[str(library)]['sha256']
            or value['profileSha256']!=digest(BASE/'contracts/candidate-build-profile.json')):
        raise ValueError('reference observations do not bind current fixture/caller')
    observations=value['observations']
    if [o['id'] for o in observations]!=list(range(24)) or [o['family'] for o in observations]!=SCENARIO_FAMILIES:
        raise ValueError('scenario identity drift')
    for obs in observations:
        if not obs['process']['completed'] or not observation_complete(obs['process']):
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
        if process_observation(execution)!=obs['process']:
            raise ValueError('reference normalized process disagrees with raw evidence')
        _bound_runtime_inputs(obs['process'],{'caller':{'path':value['callerPath'],'sha256':value['callerSha256']},'library':{'path':value['libraryPath'],'sha256':value['librarySha256']}},value['profileSha256'],expected_pins)
    if admitted()!=inputs:
        raise ValueError('reference preparation inputs changed during replay')
    return observations


def evaluate(candidate, output, helper, caller, visible, observations_path):
    scope = WorkerLeaves()
    token = _LEAF_SCOPE.set(scope)
    try:
        return _evaluate(candidate, output, helper, caller, visible, observations_path)
    finally:
        _LEAF_SCOPE.reset(token)
        scope.close()


def _evaluate(candidate, output, helper, caller, visible, observations_path):
    if 'build/acp-decomp-effectiveness/callable-library-v3' not in str(BASE):
        raise ValueError('execution requires trusted v3 source copy')
    for path in (candidate,helper,caller,visible,observations_path):
        if not path.resolve(strict=True).is_relative_to(BASE): raise ValueError('input outside trusted v3 namespace')
    verify_visible(visible)
    observations=validated_observations(observations_path,caller,visible)
    p=profile(); output=private_directory(output)
    evidence={}
    def retain(name, value):
        path=output/(name+'.json');write_json(path,value);sha=digest(path);evidence[path.name]=sha;return sha
    def phase_receipt(name, value):
        return {'status':value['status'], 'reason':str(value.get('reason',''))[:500], 'evidenceSha256':retain(name,value)}
    from freeze_v3 import read_regular
    raw=read_regular(candidate,p['bounds']['sourceBytes'])
    if len(raw)>p['bounds']['sourceBytes'] or b'\0' in raw: raise ValueError('source bound')
    raw.decode('utf8'); source_snapshot=output/'candidate-source.c';source_snapshot.write_bytes(raw)
    phases={n:{'status':'not-attempted','reason':'prior-phase-not-passed','evidenceSha256':None} for n in PHASES}
    def retain_build(phase,status):phases[phase]=phase_receipt(phase,status)
    build_statuses,artifacts=compile_sequence(source_snapshot,retain=retain_build)
    expected=None;actual=None
    if phases['preprocess']['status']=='passed':
        try:
            expected_work=new_worker_leaf('probe')
            for name in ('original.c','original.h'):copy_input(BASE/'private'/name,expected_work/name)
            expected=_leaf_call(expected_work, lambda: probe(expected_work/'original.c',helper,expected_work,dict(p['analysisIsolation']['environment'])))
            retain('expected-descriptors',expected)
            actual_work=new_worker_leaf('probe')
            actual_source=copy_input(artifacts['preprocess'],actual_work/'candidate.i')
            actual=_leaf_call(actual_work, lambda: probe(actual_source,helper,actual_work,dict(p['analysisIsolation']['environment'])))
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
                assertion_work=new_worker_leaf('assertions')
                if label=='expected':
                    prework=new_worker_leaf('expected-preprocess')
                    inputs=[copy_input(BASE/'private'/name,prework/name) for name in ('original.c','original.h')]
                    pre,_=run(phase_command(prework,['/usr/bin/gcc','-E','-P','-std=c11','/work/original.c','-o','/work/expected.i'],read_only_files=inputs),prework)
                    retain('gcc-expected-preprocess',pre)
                    if pre['status']!='passed':raise ValueError('expected preprocessing incomplete')
                    input_file=copy_input(prework/'expected.i',assertion_work/'expected.i')
                else:
                    input_file=copy_input(artifacts['preprocess'],assertion_work/'candidate.i')
                source=Path('/work')/input_file.name
                assertions=assertion_work/(label+'-assertions.c');assertions.write_text(layout_assertions(source,receipt))
                checks[label],_=run(phase_command(assertion_work,['/usr/bin/gcc','-std=c11','-Werror','-fsyntax-only','/work/'+assertions.name],read_only_files=(assertions,input_file)),assertion_work)
            except Exception as e:checks[label]={'status':'unknown','reason':str(e)[:300]}
        status='passed' if all(c['status']=='passed' for c in checks.values()) else 'unknown' if any(c['status'] in ('unknown','not-attempted') for c in checks.values()) else 'failed'
        phases['gccAssertions']=phase_receipt('gcc-assertions',{'status':status,'checks':checks})
    if phases['link']['status']=='passed':
        try:
            size=resolve_declaration(expected,expected['interfaces']['acp_state'])['sizeBits']//8 if expected and expected.get('status')=='supported' else -1
            inspection=new_worker_leaf('inspection')
            library=copy_input(artifacts['link'],inspection/'libcandidate.so')
            phases['exports']=phase_receipt('exports',_leaf_call(inspection, lambda: export_inventory(library,size,inspection,environment(inspection))))
        except Exception as error:
            failure={'status':'unknown','reason':str(error)[:300]}
            if hasattr(error,'bounded_result'):failure['execution']=public_result(error.bounded_result)
            phases['exports']=phase_receipt('exports',failure)
    admitted=all(phases[n]['status']=='passed' for n in ('preprocess','compile','link','exports','declarations','gccAssertions'))
    runtime_inputs=({'caller':{'path':str(caller.resolve(strict=True)),'sha256':digest(caller)},
                     'library':{'path':str(artifacts['link'].resolve(strict=True)),'sha256':digest(artifacts['link'])}} if admitted else None)
    scenarios=[]
    for obs in observations:
        result=None;sha=None
        if admitted:
            runtime_work=new_worker_leaf('runtime')
            status,result=run(runtime_command(caller,artifacts['link'],obs['id']),runtime_work,timeout=p['bounds']['runtimeSeconds'],phase='runtime')
            sha=retain('scenario-'+str(obs['id']),status)
        scenarios.append(scenario_entry(obs,result,admitted,sha))
    summary=summarize(scenarios,admitted)
    phases['load']={'status':'unverified' if summary['runtimeRequestCount'] else 'not-attempted','value':None}
    phases['behavior']={'status':summary.pop('behaviorStatus'),'reason':'completed-process-bytes-and-termination','evidenceSha256':None}
    report={'schemaVersion':3,'schema':'callable-library-candidate-evaluation-v3','candidateSha256':hashlib.sha256(raw).hexdigest(),'profileSha256':digest(BASE/'contracts/candidate-build-profile.json'),'runtimeInputs':runtime_inputs,'phases':phases,'admitted':admitted,**summary,'scenarios':scenarios,'evidenceFiles':evidence,'formalStructuralScore':None,'abiAccuracy':'unassessed','productionFactoryQualified':False,'productionProviderQualified':False,'productionFilesystemQualified':False}
    validate_exchange('report',report);write_json(output/'receipt.json',report);return report
