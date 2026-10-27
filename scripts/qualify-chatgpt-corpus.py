#!/usr/bin/env python3
"""Exercise the installed reconstruction CLI across every numbered binary, without executing them."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import time
import zipfile


def digest(path):
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(65536), b''):
            value.update(block)
    return value.hexdigest()


def publish(path, value):
    temporary = path.with_suffix('.tmp')
    with temporary.open('w') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def qualify(output, expected_input, log):
    summary = json.loads((output / 'reconstruction.json').read_text())
    assert summary['inputSha256'] == expected_input, 'summary identifies another input'
    assert summary['buildExitCode'] == 0, 'project build failed'
    archive = output / 'source-tree.zip'
    assert archive.is_file() and not archive.is_symlink(), 'archive absent or linked'
    assert digest(archive) == summary['archiveSha256'], 'archive digest differs'
    with zipfile.ZipFile(archive) as bundle:
        assert bundle.testzip() is None, 'archive CRC verification failed'
    manifest = json.loads((output / 'source-tree/source_tree_manifest.json').read_text())
    assert manifest['inputSha256'] == expected_input, 'source manifest identifies another input'
    assert not manifest['unresolvedImplementationIds'], 'implementations remain unresolved'
    run_path = None
    for line in log.read_text(errors='replace').splitlines():
        if line.startswith('run history: '):
            candidate = Path(line[len('run history: '):])
            if candidate.is_dir():
                run_path = candidate
                break
    assert run_path is not None, 'full run history was not retained'
    metadata = json.loads((run_path / 'run.json').read_text())
    assert metadata['state'] == 'closed' and metadata['complete'], 'run history is incomplete'
    assert metadata.get('lastPhase') == 'completed', 'run did not reach completed phase'
    events = [json.loads(line)['event'] for line in (run_path / 'events.jsonl').read_text().splitlines()]
    context = next(event for event in events if event['kind'] == 'run_context')
    assert context['inputSha256'] == expected_input, 'run history identifies another input'
    return {
        'archiveSha256': summary['archiveSha256'], 'modules': summary['moduleCount'],
        'functions': summary['functionCount'], 'globals': summary['globalCount'],
        'agentTasks': sum(event['kind'] == 'task_started' for event in events),
        'cachedModules': sum(event['kind'] == 'diagnostic' and event.get('text', '').endswith('cached') for event in events),
        'runId': metadata['runId'], 'runHistory': str(run_path),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input-directory', type=Path, required=True)
    parser.add_argument('--output-directory', type=Path, required=True)
    parser.add_argument('--reports', type=Path, required=True)
    parser.add_argument('--cli', type=Path, default=Path('build/install/llm_bin_patch/bin/llm_bin_patch'))
    parser.add_argument('--rounds', type=int, default=2)
    parser.add_argument('--case-timeout-seconds', type=int, default=1800)
    options = parser.parse_args()
    assert 1 <= options.rounds <= 10
    assert options.case_timeout_seconds > 0
    inputs = sorted((path for path in options.input_directory.iterdir()
                     if re.fullmatch(r'binary_[0-9]+', path.name) and path.is_file()),
                    key=lambda path: int(path.name.split('_')[1]))
    assert inputs, 'no numbered binary inputs found'
    options.reports.mkdir(parents=True, exist_ok=True, mode=0o700)
    implementation_jars = list((options.cli.resolve().parent.parent / 'lib').glob('llm-bin-patch-*.jar'))
    assert len(implementation_jars) == 1, 'installed application JAR is absent or ambiguous'
    implementation_jar = implementation_jars[0]
    report = {'schemaVersion': 1, 'startedAt': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'inputDirectory': str(options.input_directory.resolve()),
              'outputDirectory': str(options.output_directory.resolve()),
              'inputs': [{'name': path.name, 'sha256': digest(path)} for path in inputs], 'results': []}
    report_path = options.reports / 'qualification.json'
    publish(report_path, report)
    for round_index in range(1, options.rounds + 1):
        for path, identity in zip(inputs, report['inputs']):
            log = options.reports / f'round-{round_index}-{path.name}.log'
            started = time.monotonic()
            result = {'round': round_index, 'input': path.name, 'inputSha256': identity['sha256'], 'log': str(log),
                      'implementationSha256': digest(implementation_jar)}
            argv = [str(options.cli.resolve()), 'reconstruct', '--harness', 'chatgpt-plan', str(path.resolve()),
                    '--output', str(options.output_directory.resolve())]
            print(f'round={round_index} input={path.name} started', flush=True)
            with log.open('wb') as stream:
                process = subprocess.Popen(argv, stdout=stream, stderr=subprocess.STDOUT, start_new_session=True)
                try:
                    result['exitCode'] = process.wait(timeout=options.case_timeout_seconds)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGTERM)
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        os.killpg(process.pid, signal.SIGKILL)
                        process.wait()
                    result['exitCode'] = process.returncode
                    result['failure'] = 'case-timeout'
            result['elapsedSeconds'] = round(time.monotonic() - started, 3)
            try:
                assert result['exitCode'] == 0, 'CLI exited unsuccessfully'
                assert digest(path) == identity['sha256'], 'input changed during qualification'
                assert digest(implementation_jar) == result['implementationSha256'], 'installation changed during qualification'
                result.update(qualify(options.output_directory, identity['sha256'], log))
                if round_index > 1:
                    assert result['agentTasks'] == 0 and result['cachedModules'] == result['modules'], 'resume did not reuse all accepted module checkpoints'
                result['status'] = 'passed'
            except (AssertionError, OSError, ValueError, KeyError, StopIteration, zipfile.BadZipFile) as failure:
                result['status'] = 'failed'
                result['failure'] = type(failure).__name__ + ': ' + str(failure)[:512]
            report['results'].append(result)
            publish(report_path, report)
            print(f"round={round_index} input={path.name} {result['status']} exit={result['exitCode']} seconds={result['elapsedSeconds']}", flush=True)
    report['completedAt'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    report['passed'] = all(result['status'] == 'passed' for result in report['results']) and len({
        result['implementationSha256'] for result in report['results']}) == 1
    publish(report_path, report)
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
