"""Create a reviewed immutable preparation only; contains no model/auth/trial path."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
from bounded_runtime import BASE, digest, private_directory, write_json

def inventory(root):
    return {str(p.relative_to(root)):digest(p) for p in sorted(root.rglob('*')) if p.is_file()}

def freeze(preflight, review, output, toolchain_pin, acceptance):
    for path in (preflight,output,toolchain_pin):
        if not path.resolve().is_relative_to(BASE): raise ValueError('outside v2 ownership')
    matrix=json.loads((preflight/'matrix.json').read_bytes())
    if not matrix.get('allControlsPassed') or not matrix.get('executionDependenciesUnchanged'): raise ValueError('preflight not accepted')
    bindings=json.loads((preflight/'execution-bindings.json').read_bytes())
    for path,expected in bindings['initialSha256'].items():
        if digest(Path(path))!=expected: raise ValueError('implementation changed after preflight:'+path)
    manifest=json.loads((preflight/'controls/manifest.json').read_bytes())
    expected_names={c['name'] for c in manifest['controls']}
    if len(matrix['rows'])!=len(expected_names) or {r['name'] for r in matrix['rows']}!=expected_names: raise ValueError('control coverage mismatch')
    for row in matrix['rows']:
        receipt=Path(row['receipt'])
        if not receipt.resolve().is_relative_to(preflight) or not row.get('passed') or digest(receipt)!=row['receiptSha256']: raise ValueError('reviewed control receipt mismatch')
    preflight_inventory=inventory(preflight)
    inventory_hash=hashlib.sha256(json.dumps(preflight_inventory,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    text=review.read_text()
    if 'Verdict: **OKAY**' not in text or digest(preflight/'matrix.json') not in text or inventory_hash not in text or digest(toolchain_pin) not in text or digest(BASE/'toolchain-001/helper-pin-007.json') not in text: raise ValueError('review lacks exact approved matrix binding')
    if acceptance.resolve()==review.resolve() or digest(acceptance)==digest(review): raise ValueError('acceptance must be a distinct independent artifact')
    accepted=acceptance.read_text()
    if 'Verdict: **CLEAR**' not in accepted or digest(preflight/'matrix.json') not in accepted or inventory_hash not in accepted: raise ValueError('acceptance lacks exact CLEAR matrix/inventory binding')
    pin=json.loads(toolchain_pin.read_bytes())
    for path,expected in pin['dependencies'].items():
        if digest(Path(path))!=expected: raise ValueError('toolchain/environment changed:'+path)
    historical=BASE.parent/'callable-library-v1'
    before=json.loads((BASE/'toolchain-001/historical-before.json').read_bytes())
    if inventory(historical)!=before: raise ValueError('historical preservation mismatch')
    private_directory(output)
    artifacts=output/'artifacts';artifacts.mkdir()
    shutil.copytree(preflight,artifacts/'preflight')
    shutil.copy2(review,artifacts/'independent-review.md')
    shutil.copy2(acceptance,artifacts/'independent-acceptance.md')
    shutil.copy2(toolchain_pin,artifacts/'toolchain-environment-pin.json')
    source=artifacts/'execution';source.mkdir()
    for path in sorted(BASE.glob('*.py')):shutil.copy2(path,source/path.name)
    shutil.copy2(BASE/'record_identity_probe.cpp',source/'record_identity_probe.cpp')
    for name in ('contracts','private'):
        shutil.copytree(BASE/name,source/name)
    shutil.copy2(preflight/'record_identity_probe',source/'record_identity_probe')
    shutil.copy2(BASE/'toolchain-001/helper-pin-007.json',artifacts/'helper-pin-007.json')
    expected_copies={
        'independent-review.md':digest(review),
        'independent-acceptance.md':digest(acceptance),
        'toolchain-environment-pin.json':digest(toolchain_pin),
        'helper-pin-007.json':digest(BASE/'toolchain-001/helper-pin-007.json'),
        'execution/record_identity_probe':digest(preflight/'record_identity_probe'),
        'execution/record_identity_probe.cpp':digest(BASE/'record_identity_probe.cpp'),
    }
    expected_copies.update({'preflight/'+k:v for k,v in preflight_inventory.items()})
    expected_copies.update({'execution/'+p.name:digest(p) for p in BASE.glob('*.py')})
    for name in ('contracts','private'):
        expected_copies.update({'execution/'+name+'/'+k:v for k,v in inventory(BASE/name).items()})
    # All test/build/support receipts are already hash-bound in execution-snapshot.
    copied=inventory(artifacts)
    if copied!=expected_copies: raise ValueError('complete immutable copy verification failed')
    # Verify every copied byte before sealing; external tools remain hash-pinned inputs.
    original=inventory(preflight)
    if {k.removeprefix('preflight/'):v for k,v in copied.items() if k.startswith('preflight/')}!=original: raise ValueError('copy verification failed')
    if inventory(historical)!=before: raise ValueError('historical changed during preparation')
    report={'schemaVersion':2,'status':'prepared-no-model-call','modelCallCount':0,'authenticationReleased':False,'trialAuthorized':False,'preflightMatrixSha256':digest(preflight/'matrix.json'),'reviewedPreflightInventorySha256':inventory_hash,'independentReviewSha256':digest(review),'independentAcceptanceSha256':digest(acceptance),'supersedesPreparation':'preparation-001-unusable-host-probe-boundary','toolchainEnvironmentPinSha256':digest(toolchain_pin),'historicalInventory':before,'historicalPreservationVerified':True,'artifacts':copied,'externalDependencies':pin['dependencies'],'externalDependenciesCopied':False,'externalDependenciesRequireReverification':True,'issue1506ByteEvidence':'not-bound-no-useful-trial-authority','abiAccuracy':'unassessed','formalStructuralScore':None,'productionFactoryQualified':False,'productionProviderQualified':False,'productionFilesystemQualified':False}
    write_json(output/'freeze.json',report)
    for path in sorted(output.rglob('*'),reverse=True):path.chmod(0o555 if path.is_dir() or path.stat().st_mode & 0o111 else 0o444)
    output.chmod(0o555)
    return {'freeze':str(output/'freeze.json'),'sha256':digest(output/'freeze.json'),'status':report['status']}
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('preflight','review','output','toolchain-pin','acceptance'):p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args();print(json.dumps(freeze(a.preflight.resolve(),a.review.resolve(),a.output.resolve(),a.toolchain_pin.resolve(),a.acceptance.resolve()),indent=2))
