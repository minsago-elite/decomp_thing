"""Trusted private benchmark gate: wait for parent kernel-limit verification."""
import json
import os
from pathlib import Path
import sys
import time

from build_contract import load_profile


def main():
    bounds = load_profile()['bounds']
    gate = Path(sys.argv[1]).resolve()
    assert gate.is_relative_to(Path(__file__).resolve().parent)
    text = Path('/proc/self/stat').read_text()
    fields = text[text.rfind(')') + 2:].split()
    record = {'pid': os.getpid(), 'start': int(fields[19])}
    temporary = gate / 'gate.tmp'
    with temporary.open('x') as stream:
        json.dump(record, stream)
    os.replace(temporary, gate / 'gate.json')
    deadline = time.monotonic() + bounds['scopeAdmissionSeconds']
    while not (gate / 'admit').exists():
        if time.monotonic() >= deadline:
            raise SystemExit(70)
        time.sleep(bounds['scopeAdmissionPollSeconds'])
    assert (gate / 'admit').read_bytes() == b'1\n'
    os.execv(sys.argv[2], sys.argv[2:])


if __name__ == '__main__':
    main()
