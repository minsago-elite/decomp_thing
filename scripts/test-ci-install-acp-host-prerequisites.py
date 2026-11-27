#!/usr/bin/env python3
"""Exercise the isolated APT command boundary without changing host packages."""

import json
import os
from pathlib import Path
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/ci-install-acp-host-prerequisites.sh"


def main():
    build = ROOT / "build"
    build.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="apt-prereq-test-", dir=build) as tmp:
        tmp = Path(tmp)
        fakebin = tmp / "bin"
        fakebin.mkdir()
        log = tmp / "apt.jsonl"
        apt = fakebin / "apt-get"
        apt.write_text("""#!/usr/bin/env python3
import json, os, sys
args = sys.argv[1:]
source_path = next((args[i + 1].split('=', 1)[1] for i, arg in enumerate(args[:-1]) if arg == '-o' and args[i + 1].startswith('Dir::Etc::sourcelist=')), None)
with open(os.environ['APT_LOG'], 'a') as f:
    f.write(json.dumps({'args': args, 'sources': open(source_path).read() if source_path else None}) + '\\n')
if os.environ.get('APT_FAIL') and os.environ['APT_FAIL'] in args:
    sys.exit(37)
""")
        apt.chmod(0o755)
        sudo = fakebin / "sudo"
        sudo.write_text("#!/bin/sh\nexec \"$@\"\n")
        sudo.chmod(0o755)
        deps = tmp / "deb.deps"
        expressions = ["libasound2t64 (>= 1.0)", "libx11-6 (>= 2.0)"]
        deps.write_text("\n".join(expressions) + "\n")

        def run(*args, fail=None):
            log.unlink(missing_ok=True)
            env = os.environ | {"PATH": f"{fakebin}:{os.environ['PATH']}", "APT_LOG": str(log)}
            if fail:
                env["APT_FAIL"] = fail
            else:
                env.pop("APT_FAIL", None)
            result = subprocess.run(["bash", str(SCRIPT), *args], cwd=ROOT, env=env)
            calls = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
            return result.returncode, calls

        def options(record):
            call = record["args"]
            i = call.index("-o")
            found = {}
            while i < len(call) and call[i] == "-o":
                key, value = call[i + 1].split("=", 1)
                found[key] = value
                i += 2
            return found, call[i:]

        code, calls = run("browser", str(deps))
        assert code == 0 and len(calls) == 3, (code, calls)
        expected_stanzas = [
            "deb [arch=amd64 signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] http://archive.ubuntu.com/ubuntu noble main restricted universe multiverse",
            "deb [arch=amd64 signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] http://archive.ubuntu.com/ubuntu noble-updates main restricted universe multiverse",
            "deb [arch=amd64 signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] http://archive.ubuntu.com/ubuntu noble-backports main restricted universe multiverse",
            "deb [arch=amd64 signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] http://security.ubuntu.com/ubuntu noble-security main restricted universe multiverse",
        ]
        shared_options = None
        for call in calls:
            opts, _ = options(call)
            assert set(opts) == {"Dir::Etc::sourcelist", "Dir::Etc::sourceparts", "APT::Update::Error-Mode", "Dir::State::lists"}, opts
            assert opts["Dir::Etc::sourceparts"] == "-", opts
            assert opts["APT::Update::Error-Mode"] == "any", opts
            assert opts["Dir::Etc::sourcelist"].endswith("/ubuntu.sources.list"), opts
            assert opts["Dir::State::lists"].endswith("/lists"), opts
            if shared_options is None:
                shared_options = opts
            assert opts == shared_options, opts
            assert [line for line in call["sources"].splitlines() if line.startswith("deb ")] == expected_stanzas
            assert len(call["sources"].splitlines()) == len(expected_stanzas) + 1
        assert options(calls[0])[1] == ["update"]
        assert options(calls[1])[1] == ["satisfy", "-y", "--no-install-recommends", *expressions]
        assert options(calls[2])[1] == ["install", "-y", "--no-install-recommends", "xvfb"]

        code, calls = run()
        assert code == 0 and len(calls) == 2, (code, calls)
        assert options(calls[1])[1] == ["install", "-y", "--no-install-recommends", "bubblewrap", "binutils", "build-essential", "dbus-user-session", "python3", "systemd", "util-linux"]

        for failed_operation in ("update", "satisfy", "install"):
            code, calls = run("browser", str(deps), fail=failed_operation)
            assert code == 37, (failed_operation, code)
            assert options(calls[-1])[1][0] == failed_operation

        for invalid_args in (("invalid",), ("acp", "extra"), ("browser",), ("browser", str(tmp / "missing"))):
            code, calls = run(*invalid_args)
            assert code == 2 and not calls, (invalid_args, code, calls)
        for invalid_contents in ("", "libx11-6\n  \n"):
            deps.write_text(invalid_contents)
            code, calls = run("browser", str(deps))
            assert code == 2 and not calls, (code, calls)
        print("isolated browser and ACP APT command checks passed")


if __name__ == "__main__":
    main()
