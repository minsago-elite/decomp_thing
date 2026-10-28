"""Repository-local synthetic fixtures for the public static test suite."""
import ast
import hashlib
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[1]
REPOSITORY = SOURCE.parents[3]
if SOURCE.relative_to(REPOSITORY).parts != ('oracle', 'acp', 'callable-evaluator-v3', 'source'):
    raise ValueError('static fixtures require the declared repository layout')
HISTORICAL_SHA256 = '57dd58f2fdfb292defdbd31561e78fdc4120b2a102efd4e3b9af7cc31b3b0c1b'


def static_temp(area):
    if area not in ('static-process', 'static-process-correction-001', 'static-ci/test-tmp'):
        raise ValueError('unknown static fixture area')
    path = REPOSITORY / 'build/acp-decomp-effectiveness/callable-library-v3' / area
    if not path.resolve().is_relative_to(REPOSITORY):
        raise ValueError('static fixture parent outside repository')
    path.mkdir(parents=True, exist_ok=True)
    return path


def historical_namespace(**bindings):
    """Load hash-pinned authored AST models, without ignored/private inputs."""
    path = SOURCE / 'tests/fixtures/historical_counterexamples.py'
    raw = path.read_bytes()
    if len(raw) > 32768 or hashlib.sha256(raw).hexdigest() != HISTORICAL_SHA256:
        raise ValueError('public historical counterexample fixture changed')
    tree = ast.parse(raw)
    functions = [node for node in tree.body if isinstance(node, ast.FunctionDef)]
    if {node.name for node in functions} != {'process_observation', 'compare_process', 'validate_exchange', 'inventory'}:
        raise ValueError('unexpected counterexample functions')
    namespace = dict(bindings)
    exec(compile(ast.Module(body=functions, type_ignores=[]), str(path), 'exec'), namespace)
    return namespace
