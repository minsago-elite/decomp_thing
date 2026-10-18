"""V2 control evaluator. Preparation/freeze and model execution are not provided."""
import json
from pathlib import Path
from bounded_runtime import bounded_run, digest, private_directory, public_result, write_json
from build_contract import profile, verify_visible
from interface_gate_v2 import compare_descriptors, probe, export_inventory, layout_assertions
BASE = Path(__file__).resolve().parent

def environment(work):
    return {'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C','HOME':str(work),'TMPDIR':str(work),'TMP':str(work),'TEMP':str(work)}

def phase_command(work, arguments):
    command=['/usr/bin/bwrap','--unshare-all','--unshare-user','--die-with-parent','--new-session','--disable-userns','--cap-drop','ALL','--clearenv']
    for directory in ('/usr','/lib','/lib64'):
        if Path(directory).exists(): command += ['--ro-bind',directory,directory]
    return command+['--proc','/proc','--dev','/dev','--remount-ro','/dev','--size','16777216','--tmpfs','/tmp','--bind',str(work),'/work','--chdir','/work',*sum((['--setenv',k,v] for k,v in profile()['environment'].items()),[]),*arguments]

def runtime_command(caller, library, scenario):
    command=['/usr/bin/bwrap','--unshare-all','--unshare-user','--die-with-parent','--new-session','--disable-userns','--cap-drop','ALL','--clearenv']
    for directory in ('/usr','/lib','/lib64'):
        if Path(directory).exists(): command += ['--ro-bind',directory,directory]
    return command+['--proc','/proc','--dev','/dev','--remount-ro','/dev','--size','16777216','--tmpfs','/tmp','--dir','/workspace','--ro-bind',str(caller),'/caller','--ro-bind',str(library),'/library.so','--chdir','/workspace','--remount-ro','/',*sum((['--setenv',k,v] for k,v in profile()['environment'].items()),[]),'/caller','/library.so',str(scenario)]

def run(argv, work, timeout=None):
    try:
        r=bounded_run(argv,work,environment(work),timeout=timeout if timeout is not None else profile()['bounds']['compilerSeconds'],output_limit=profile()['bounds']['outputBytesPerStream'],managed_scope=True)
        return {'status':'passed' if r['exitCode']==0 else 'failed','execution':public_result(r)},r
    except Exception as e:
        return {'status':'unknown','reason':type(e).__name__+':'+str(e)[:300], 'execution':public_result(e.bounded_result) if hasattr(e,'bounded_result') else None},getattr(e,'bounded_result',None)

def validated_observations(path, caller):
    if not path.resolve(strict=True).is_relative_to(BASE):
        raise ValueError('observations outside v2 namespace')
    value=json.loads(path.read_bytes())
    if value.get('schemaVersion')!=2 or value.get('sourceSha256')!=digest(BASE/'private/original.c') or value.get('callerSha256')!=digest(caller):
        raise ValueError('reference observations are not bound to current v2 fixture/caller')
    observations=value.get('observations',[])
    if len(observations)!=24 or [o['id'] for o in observations]!=list(range(24)):
        raise ValueError('scenario identity drift')
    for obs in observations:
        for field in ('stdoutHex','stderrHex'):
            if len(bytes.fromhex(obs[field]))>profile()['bounds']['outputBytesPerStream']:
                raise ValueError('observation output exceeds bound')
        if not isinstance(obs['exitCode'],int) or not isinstance(obs['family'],str):
            raise ValueError('invalid observation schema')
    return observations

def evaluate(candidate, output, helper, caller, visible, observations_path):
    for path in (candidate,helper,caller,visible,observations_path):
        if not path.resolve(strict=True).is_relative_to(BASE):
            raise ValueError('evaluation input outside v2 namespace')
    verify_visible(visible)
    observations=validated_observations(observations_path,caller)
    p=profile(); output=private_directory(output); work=private_directory(output/'work')
    raw=candidate.read_bytes()
    if len(raw)>p['bounds']['sourceBytes'] or b'\0' in raw: raise ValueError('source bound')
    raw.decode('utf8'); (work/'candidate.c').write_bytes(raw)
    phases={n:{'status':'not-attempted','reason':'prior-phase-not-passed'} for n in ('preprocess','compile','link','exports','declarations','gccAssertions','load','behavior')}
    for phase in ('preprocess','compile','link'):
        phases[phase],result=run(phase_command(work,p['commands'][phase]),work)
        if result is None or result['exitCode']!=0: break
    declaration = None; expected=None; actual=None
    if phases['preprocess']['status']=='passed':
        try:
            expected_probe_work=private_directory(output/'expected-probe-work')
            (expected_probe_work/'original.c').write_bytes((BASE/'private/original.c').read_bytes())
            (expected_probe_work/'original.h').write_bytes((BASE/'private/original.h').read_bytes())
            expected=probe(expected_probe_work/'original.c',helper,expected_probe_work,environment(expected_probe_work))
            actual=probe(work/'candidate.i',helper,work,environment(work))
            write_json(output/'expected-descriptors.json',expected); write_json(output/'candidate-descriptors.json',actual)
            declaration=compare_descriptors(expected,actual); phases['declarations']=declaration
            if declaration['accepted']:
                # Candidate and expected each need GCC agreement with every reachable record/enum.
                expected_work=private_directory(output/'expected-gcc-work')
                (expected_work/'expected.c').write_bytes((BASE/'private/original.c').read_bytes())
                (expected_work/'original.h').write_bytes((BASE/'private/original.h').read_bytes())
                expected_preprocess,_=run(phase_command(expected_work,['/usr/bin/gcc','-E','-P','-std=c11','/work/expected.c','-o','/work/expected.i']),expected_work)
                if expected_preprocess['status']!='passed': raise ValueError('expected GCC preprocessing failed')
                write_json(output/'gcc-expected-preprocess.json',expected_preprocess)
                phases['gccAssertions']={'status':'passed','checks':{}}
                for label,source,receipt,assertion_work in [('expected',Path('/work/expected.i'),expected,expected_work),('candidate',Path('/work/candidate.i'),actual,work)]:
                    assertions=assertion_work/(label+'-assertions.c'); assertions.write_text(layout_assertions(source,receipt))
                    status,res=run(phase_command(assertion_work,['/usr/bin/gcc','-std=c11','-Werror','-fsyntax-only','/work/'+assertions.name]),assertion_work)
                    phases['gccAssertions']['checks'][label]=status
                    if status['status']!='passed':
                        phases['gccAssertions']['status']=status['status'];break
        except Exception as e: phases['declarations']={'status':'unknown','accepted':False,'reason':str(e)[:300]}
    if phases['link']['status']=='passed':
        try:
            size=expected['interfaces']['acp_state']['sizeBits']//8 if expected and expected.get('status')=='supported' else -1
            phases['exports']=export_inventory(work/'libcandidate.so',size,work,environment(work))
        except Exception as e: phases['exports']={'status':'unknown','reason':str(e)[:300]}
    admitted=all(phases[n]['status']=='passed' for n in ('preprocess','compile','link','exports','declarations','gccAssertions'))
    scenarios=[]; launches=0; calls=0; runtime_executed=False
    for obs in observations:
        entry={'id':obs['id'],'family':obs['family'],'status':'admission-refused','candidateCalled':False,'loadStatus':'not-attempted'}
        if admitted:
            launches+=1
            entry['loadStatus']='unknown'
            status,r=run(runtime_command(caller,work/'libcandidate.so',obs['id']),work,timeout=p['bounds']['runtimeSeconds'])
            entry['runtime']=status
            entry['constructorMarkerObserved']=bool(r and b'REFUSED_CONSTRUCTOR_EXECUTED' in r['stderr'])
            if r is None:
                entry['status']='runtime-failed'
            else:
                stderr=r['stderr']; runtime_executed |= b'ACP_V2_LOAD_BEGIN\n' in stderr
                loaded=b'ACP_V2_LOAD_OK\n' in stderr
                entry['loadStatus']='passed' if loaded else 'failed' if b'ACP_V2_LOAD_BEGIN\n' in stderr else 'unknown'
                count=stderr.count(b'ACP_V2_CALL\n'); calls+=count
                entry['candidateCalled']=count>0; entry['recordedCalls']=count
                cleaned=stderr.replace(b'ACP_V2_LOAD_BEGIN\n',b'').replace(b'ACP_V2_LOAD_OK\n',b'').replace(b'ACP_V2_CALL\n',b'')
                entry['status']=('load-failed' if not loaded else 'runtime-failed' if r['exitCode']!=0 else 'matched' if r['stdout'].hex()==obs['stdoutHex'] and cleaned.hex()==obs['stderrHex'] else 'mismatched')
                entry['expectedStdoutHex']=obs['stdoutHex']
        scenarios.append(entry)
    executed=sum(s['candidateCalled'] for s in scenarios); matched=sum(s['status']=='matched' for s in scenarios)
    if admitted:
        phases['load']={'status':'passed' if all(s['loadStatus']=='passed' for s in scenarios) else 'failed' if any(s['loadStatus']=='failed' for s in scenarios) else 'unknown'}
        phases['behavior']={'status':'passed' if matched==24 else 'failed'}
    report={'schemaVersion':2,'schema':'callable-library-candidate-evaluation-v2','candidateSha256':digest(candidate),'profileSha256':digest(BASE/'contracts/candidate-build-profile.json'),'phases':phases,'admitted':admitted,'callerLaunchCount':launches,'recordedCallCount':calls,'candidateCalled':calls>0,'runtimeExecutionAttempted':runtime_executed,'scenarioCount':24,'executedScenarios':executed,'matched':matched,'mismatched':sum(s['status']=='mismatched' for s in scenarios),'admissionRefused':sum(s['status']=='admission-refused' for s in scenarios),'behaviorRate':matched/executed if executed else None,'scenarios':scenarios,'formalStructuralScore':None,'abiAccuracy':'unassessed','productionFactoryQualified':False,'productionProviderQualified':False,'productionFilesystemQualified':False}
    write_json(output/'receipt.json',report)
    return report
