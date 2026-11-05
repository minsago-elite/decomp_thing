#!/usr/bin/env python3
"""Create bounded synthetic PKCS12 identities for the C4a loopback TLS tests."""

import argparse
import os
from pathlib import Path
import shutil
import selectors
import signal
import subprocess
import sys
import time


MAX_OUTPUT = 32 * 1024
COMMAND_TIMEOUT_SECONDS = 30
KILL_TIMEOUT_SECONDS = 5


def exit_status(process: subprocess.Popen[bytes]) -> int | None:
    if os.name != "posix":
        return process.poll()
    # Keep the direct child unreaped so its PID/process-group identity cannot be reused
    # before the final group signal. Never use poll()/wait() ahead of that signal.
    observed = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOWAIT | os.WNOHANG)
    if observed is None:
        return None
    if observed.si_pid != process.pid or observed.si_code not in (os.CLD_EXITED, os.CLD_KILLED, os.CLD_DUMPED):
        raise RuntimeError("keytool exit observation is inconsistent")
    return observed.si_status if observed.si_code == os.CLD_EXITED else -observed.si_status


def terminate(process: subprocess.Popen[bytes]) -> None:
    if process.returncode is not None:
        return
    try:
        if os.name == "posix":
            # Confirm this is still our unreaped direct child, including an exited leader.
            # A failure to observe ownership must never authorize a numeric group signal.
            exit_status(process)
            os.killpg(process.pid, signal.SIGKILL)
        else:
            process.kill()
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=KILL_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired as error:
        raise RuntimeError("keytool child did not exit after forced termination") from error


def run_keytool(keytool: Path, output: Path, alias: str, host: str) -> None:
    if os.name == "posix" and not all(hasattr(os, name) for name in ("waitid", "WNOWAIT", "WNOHANG")):
        raise RuntimeError("nonreaping keytool child observation is unavailable")
    command = [
        str(keytool), "-J-XX:-UsePerfData", f"-J-Djava.io.tmpdir={output.parent}", "-genkeypair", "-alias", alias,
        "-keystore", str(output), "-storetype", "PKCS12",
        "-storepass", "fixture-password", "-keypass", "fixture-password",
        "-keyalg", "RSA", "-keysize", "2048", "-validity", "30",
        "-dname", f"CN={host}", "-ext", f"SAN=dns:{host}", "-noprompt",
    ]
    process = subprocess.Popen(
        command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        start_new_session=(os.name == "posix"),
    )
    failure: BaseException | None = None
    try:
        assert process.stdout is not None
        os.set_blocking(process.stdout.fileno(), False)
        deadline = time.monotonic() + COMMAND_TIMEOUT_SECONDS
        output_bytes = 0
        ended = False
        eof = False
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while not (ended and eof):
                if not ended:
                    status = exit_status(process)
                    if status is not None:
                        # Terminate any remaining same-group members before reaping even
                        # on success. This reaps only our direct child, not descendants.
                        terminate(process)
                        ended = True
                        if status != 0:
                            raise RuntimeError(f"keytool failed ({status})")
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise RuntimeError("keytool exceeded its 30-second deadline")
                for key, _ in selector.select(min(remaining, 0.025)):
                    chunk = os.read(key.fd, min(4096, MAX_OUTPUT - output_bytes + 1))
                    if not chunk:
                        selector.unregister(key.fileobj)
                        eof = True
                    elif len(chunk) > MAX_OUTPUT - output_bytes:
                        raise RuntimeError("keytool output exceeded 32 KiB")
                    else:
                        output_bytes += len(chunk)
                    # Output is counted and discarded; no child output is written to disk.
        if not output.is_file() or output.stat().st_size > 128 * 1024:
            raise RuntimeError("keytool output store is absent or exceeds 128 KiB")
        if os.name == "posix":
            output.chmod(0o600)
    except BaseException as error:
        failure = error
        raise
    finally:
        try:
            terminate(process)
        except BaseException as cleanup_error:
            if failure is None:
                raise
            failure.add_note(f"keytool cleanup failed: {type(cleanup_error).__name__}")
        finally:
            if process.stdout is not None:
                process.stdout.close()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--keytool", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if not args.keytool.is_absolute() or not args.keytool.is_file() or not os.access(args.keytool, os.X_OK):
        parser.error("--keytool must be an absolute executable from the pinned JDK")
    root = args.output.resolve()
    build_root = Path.cwd().resolve() / "build"
    if root == build_root or not root.is_relative_to(build_root):
        parser.error("--output must be under the repository build/ directory")
    if root.exists():
        shutil.rmtree(root)
    root.mkdir(parents=True)
    try:
        run_keytool(args.keytool, root / "server.p12", "c4a-server", "api.openai.com")
        run_keytool(args.keytool, root / "wrong.p12", "c4a-wrong-host", "wrong.invalid")
    except BaseException:
        shutil.rmtree(root, ignore_errors=True)
        raise
    print(f"C4a loopback TLS fixture stores generated by pinned JDK keytool {args.keytool.resolve()}; 2 stores, no external connections")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"C4a fixture generation failed: {error}", file=sys.stderr)
        raise SystemExit(1)
