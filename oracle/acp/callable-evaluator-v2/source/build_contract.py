"""One visible command contract, consumed by rendering and execution."""
import json
from pathlib import Path
from bounded_runtime import digest
BASE = Path(__file__).resolve().parent
PROFILE_PATH = BASE / 'contracts/candidate-build-profile.json'
def profile():
    value=json.loads(PROFILE_PATH.read_bytes())
    fixed={'memoryBytes':536870912,'swapBytes':0,'tasks':32,'virtualAddressSpaceBytes':2147483648,'cpuSeconds':30}
    if any(value['bounds'].get(k)!=v for k,v in fixed.items()):
        raise ValueError('profile differs from enforced kernel/process bounds')
    identity=value.get('gccIdentity')
    if identity and (str(Path(identity['executable']).resolve())!=identity['realpath'] or digest(Path(identity['realpath']))!=identity['sha256']):
        raise ValueError('GCC executable differs from visible profile identity')
    return value
def render():
    p = profile()
    return '\n'.join(['Candidate build contract v2', p['target'], *(' '.join(p['commands'][k]) for k in ('preprocess','compile','link')), p['exports'], 'Full machine-readable contract:', json.dumps(p,sort_keys=True,indent=2)]) + '\n'
def verify_visible(directory):
    p = profile()
    manifest = json.loads((directory/'visible-manifest.json').read_bytes())
    if manifest != {'schemaVersion': 2, 'profile': p, 'profileSha256': digest(PROFILE_PATH)}:
        raise ValueError('visible manifest/profile disagreement')
    if (directory/'prompt.txt').read_text() != render():
        raise ValueError('visible prompt/profile disagreement')
def write_visible(directory):
    (directory/'prompt.txt').write_text(render())
    (directory/'visible-manifest.json').write_text(json.dumps({'schemaVersion':2,'profile':profile(),'profileSha256':digest(PROFILE_PATH)}, sort_keys=True,indent=2)+'\n')
