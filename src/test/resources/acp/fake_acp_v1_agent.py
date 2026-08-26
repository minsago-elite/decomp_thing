import json
import os
import signal
import subprocess
import sys
import time


MODE = sys.argv[1]
SENTINEL = sys.argv[2] if len(sys.argv) > 2 else ""
READY = sys.argv[3] if len(sys.argv) > 3 else ""


def send(message):
    sys.stdout.write(json.dumps(message, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def read_message():
    line = sys.stdin.readline()
    if line == "":
        return None
    return json.loads(line)


def respond(request, result=None, error=None):
    message = {"jsonrpc": "2.0", "id": request["id"]}
    if error is None:
        message["result"] = result if result is not None else {}
    else:
        message["error"] = error
    send(message)


def update(value):
    send({
        "jsonrpc": "2.0",
        "method": "session/update",
        "params": {"sessionId": "fixture-session", "update": value},
    })


sys.stderr.write("fixture-stderr:" + SENTINEL + "\n")
if MODE == "stderr-overflow":
    sys.stderr.write("x" * 70000)
sys.stderr.flush()

if MODE == "no-initialize":
    time.sleep(30)
    raise SystemExit(0)

initialize = read_message()
if initialize is None or initialize.get("method") != "initialize":
    raise SystemExit(91)

if MODE == "malformed-initialize":
    sys.stdout.write("{not-json\n")
    sys.stdout.flush()
    time.sleep(30)
    raise SystemExit(0)

if MODE == "unsupported-version":
    respond(initialize, {"protocolVersion": 2, "agentCapabilities": {}})
    time.sleep(30)
    raise SystemExit(0)

if MODE == "missing-protocol-version":
    respond(initialize, {"agentCapabilities": {}})
    time.sleep(30)
    raise SystemExit(0)

if MODE == "unknown-response-id":
    send({"jsonrpc": "2.0", "id": "not-pending", "result": {}})
    time.sleep(30)
    raise SystemExit(0)

capabilities = {
    "loadSession": MODE == "load-session-capability",
    "promptCapabilities": {"image": False, "audio": False, "embeddedContext": False},
    "mcpCapabilities": {"http": False, "sse": False},
    "sessionCapabilities": {},
}
initialize_result = {
    "protocolVersion": 1,
    "agentCapabilities": capabilities,
    "agentInfo": {"name": "scripted-fixture", "version": "1.0"},
}
respond(initialize, initialize_result)

if MODE == "duplicate-response-id":
    respond(initialize, initialize_result)
    time.sleep(30)
    raise SystemExit(0)

if MODE == "crash-after-initialize":
    raise SystemExit(17)

session_new = read_message()
if session_new is None or session_new.get("method") != "session/new":
    raise SystemExit(92)
cwd = session_new.get("params", {}).get("cwd", "")
if not os.path.isabs(cwd):
    respond(session_new, error={"code": -32602, "message": "cwd must be absolute"})
    raise SystemExit(93)
if MODE == "auth-required":
    respond(session_new, error={"code": -32000, "message": "authenticate first"})
    time.sleep(30)
    raise SystemExit(0)
if MODE == "no-session-response":
    time.sleep(30)
    raise SystemExit(0)
respond(session_new, {"sessionId": "fixture-session"})

prompt = read_message()
if prompt is None or prompt.get("method") != "session/prompt":
    raise SystemExit(94)
prompt_text = prompt.get("params", {}).get("prompt", [{}])[0].get("text", "")
if "edit the fixture" not in prompt_text or "compiler evidence" not in prompt_text:
    respond(prompt, error={"code": -32602, "message": "prompt lost objective or context"})
    raise SystemExit(95)
if READY and MODE != "cancel-after-response":
    with open(READY, "w", encoding="utf-8") as ready:
        ready.write("ready\n")

if MODE == "malformed-prompt":
    sys.stdout.write("[]\n")
    sys.stdout.flush()
    time.sleep(30)
    raise SystemExit(0)

if MODE == "invalid-utf8-prompt":
    sys.stdout.buffer.write(b"\xff\n")
    sys.stdout.buffer.flush()
    time.sleep(30)
    raise SystemExit(0)

if MODE == "oversized-frame-prompt":
    sys.stdout.write("{" + ("x" * 70000))
    sys.stdout.flush()
    time.sleep(30)
    raise SystemExit(0)

if MODE in (
    "contaminated-prompt",
    "missing-jsonrpc-prompt",
    "wrong-jsonrpc-prompt",
    "numeric-jsonrpc-prompt",
    "result-and-error-prompt",
):
    payload = {"id": prompt["id"], "result": {"stopReason": "end_turn"}}
    prefix = ""
    if MODE == "contaminated-prompt":
        payload["jsonrpc"] = "2.0"
        prefix = "debug output: "
    elif MODE == "wrong-jsonrpc-prompt":
        payload["jsonrpc"] = "1.0"
    elif MODE == "numeric-jsonrpc-prompt":
        payload["jsonrpc"] = 2.0
    elif MODE == "result-and-error-prompt":
        payload["jsonrpc"] = "2.0"
        payload["error"] = {"code": -32603, "message": "must not coexist with result"}
    sys.stdout.write(prefix + json.dumps(payload, separators=(",", ":")) + "\n")
    sys.stdout.flush()
    time.sleep(30)
    raise SystemExit(0)

if MODE == "crash-prompt":
    raise SystemExit(23)

if MODE == "eof-prompt":
    raise SystemExit(0)

if MODE in ("wait-for-cancel", "ignore-cancel"):
    if MODE == "ignore-cancel":
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        time.sleep(30)
        raise SystemExit(0)
    while True:
        message = read_message()
        if message is None:
            raise SystemExit(0)
        if message.get("method") == "session/cancel":
            respond(prompt, {"stopReason": "cancelled"})
            raise SystemExit(0)

if MODE == "invalid-update":
    update({
        "sessionUpdate": "tool_call",
        "toolCallId": "",
        "title": "invalid tool id",
        "status": "in_progress",
    })
    time.sleep(30)
    raise SystemExit(0)

if MODE == "success-child-hang":
    child = subprocess.Popen([
        sys.executable,
        "-c",
        "import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(30)",
    ])
    if READY:
        with open(READY, "w", encoding="utf-8") as ready:
            ready.write(str(child.pid) + "\n")

update({
    "sessionUpdate": "agent_message_chunk",
    "content": {"type": "text", "text": "editing fixture"},
    "messageId": "message-1",
})
if MODE == "update-then-hang":
    time.sleep(30)
    raise SystemExit(0)

update({
    "sessionUpdate": "plan",
    "entries": [{"content": "edit source", "priority": "high", "status": "in_progress"}],
})
update({
    "sessionUpdate": "tool_call",
    "toolCallId": "tool-1",
    "title": "Edit source",
    "kind": "edit",
    "status": "in_progress",
})

source = os.path.join(cwd, "src", "module.c")
with open(source, "w", encoding="utf-8") as output:
    output.write("new source\n")

update({
    "sessionUpdate": "tool_call_update",
    "toolCallId": "tool-1",
    "title": "Edit source",
    "kind": "edit",
    "status": "completed",
})
respond(prompt, {
    "stopReason": "end_turn",
    "usage": {
        "inputTokens": -1 if MODE == "negative-usage" else 11,
        "outputTokens": 7,
        "totalTokens": 18,
        "cachedReadTokens": 3,
    },
})

if MODE == "response-then-crash":
    raise SystemExit(31)

if MODE == "response-then-delayed-crash":
    time.sleep(0.04)
    raise SystemExit(32)

if MODE == "cancel-after-response":
    # Host stdin closes only after it accepted the final response and entered shutdown.
    sys.stdin.read()
    with open(READY, "w", encoding="utf-8") as ready:
        ready.write("cancel final snapshot\n")
    raise SystemExit(0)

if MODE in ("success-hang", "success-child-hang"):
    time.sleep(30)
