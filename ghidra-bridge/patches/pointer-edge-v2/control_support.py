"""Repository-local output routing and bounded compiler process groups; no runtime activation."""
from pathlib import Path
import os, signal, subprocess


def evidence_root(root):
    allowed = (root / 'build/orchestration/exporter-v20-pointer-dependency-remediation').resolve()
    selected = Path(os.environ.get('OWNED_POINTER_EVIDENCE', str(allowed))).resolve()
    assert selected.is_relative_to(allowed), 'Evidence must stay in the NEW remediation root'
    selected.mkdir(parents=True, exist_ok=True)
    return selected


def bounded_run(command, *, timeout, **kwargs):
    assert kwargs.pop('capture_output', True)
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               start_new_session=True, **kwargs)
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.communicate()
        raise
    return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
