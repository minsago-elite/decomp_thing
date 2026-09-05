"""Benign ACP repair fixture: bounded protocol exchanges and authorized source edits only."""
import json
import sys


MODE = sys.argv[1]
SESSION = "trace-repair-fixture-session"


def read_message():
    line = sys.stdin.readline()
    return json.loads(line) if line else None


def send(message):
    sys.stdout.write(json.dumps(message, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def respond(request, result):
    send({"jsonrpc": "2.0", "id": request["id"], "result": result})


def update(value):
    send({"jsonrpc": "2.0", "method": "session/update",
          "params": {"sessionId": SESSION, "update": value}})


def callback(method, path, identifier, **extra):
    send({"jsonrpc": "2.0", "id": identifier, "method": method,
          "params": {"sessionId": SESSION, "path": path, **extra}})
    result = read_message()
    assert result["id"] == identifier and "error" not in result, result
    return result["result"]


initialize = read_message()
assert initialize["method"] == "initialize"
respond(initialize, {"protocolVersion": 1, "agentCapabilities": {},
                     "agentInfo": {"name": "trace-repair-fixture", "version": "1.0"}})
session = read_message()
assert session["method"] == "session/new"
cwd = session["params"]["cwd"]
respond(session, {"sessionId": SESSION})
prompt = read_message()
assert prompt["method"] == "session/prompt"
text = "\n".join(block.get("text", "") for block in prompt["params"]["prompt"])
assert "Repair the " in text and "failure in the authorized project workspace" in text
assert "dependency-indexed-repair-context" in text
assert "retained-regression-inputs" in text and "default" in text and "argument" in text
assert "6b6570740a" in text  # Exact retained stdin bytes: kept\n.
assert "src/program.c" in text and "include/fixture.h" in text
assert "src/unrelated.c" not in text
assert "Compile command:" in text or "Structured behavior diff" in text
update({"sessionUpdate": "agent_message_chunk",
        "content": {"type": "text", "text": "Reviewing retained repair cases."}})
if MODE in ("no-change", "refused", "limit"):
    reason = {"no-change": "end_turn", "refused": "refusal", "limit": "max_tokens"}[MODE]
    respond(prompt, {"stopReason": reason})
    sys.stdin.read()
    raise SystemExit(0)
if MODE == "crash":
    raise SystemExit(17)
source = cwd + "/src/program.c"
assert "main" in callback("fs/read_text_file", source, 801)["content"]
assert "FIXTURE" in callback("fs/read_text_file", cwd + "/include/fixture.h", 802)["content"]
if MODE == "compile-invalid":
    replacement = '#include "fixture.h"\nint main(void) {\n'
else:
    expression = '"argument"' if MODE == "retained-regression" else 'argc > 1 ? "argument" : "default"'
    replacement = ('#include <stdio.h>\n#include "fixture.h"\n'
                   'int main(int argc, char **argv) { (void)argc; (void)argv; '
                   'puts(' + expression + '); return 0; }\n')
update({"sessionUpdate": "tool_call", "toolCallId": "repair-edit", "title": "Update source",
        "kind": "edit", "status": "in_progress"})
callback("fs/write_text_file", source, 803, content=replacement)
update({"sessionUpdate": "tool_call_update", "toolCallId": "repair-edit", "status": "completed"})
respond(prompt, {"stopReason": "end_turn", "usage": {"inputTokens": 11, "outputTokens": 7, "totalTokens": 18}})
sys.stdin.read()
