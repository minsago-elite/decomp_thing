import json
import posix as os
import _signal as signal
import sys
import time


MODE = sys.argv[1]
SENTINEL = sys.argv[2] if len(sys.argv) > 2 else ""
READY = sys.argv[3] if len(sys.argv) > 3 else ""
GENERIC_CONTRACT_MODES = {
    "fragmented-stdout",
    "pipelined-callbacks",
    "unknown-methods",
    "forbidden-write",
    "physical-newline-in-string",
    "terminal-kill-lifecycle",
    "stop-max-tokens",
    "stop-max-turn-requests",
    "stop-refusal",
}


def send(message):
    encoded = json.dumps(message, separators=(",", ":")) + "\n"
    if MODE == "fragmented-stdout":
        # Split every frame across fixed, flushed writes, including the line delimiter.  The
        # receiver must assemble a stream rather than assuming one write equals one frame.
        first = 1
        second = max(first + 1, len(encoded) - 1)
        for fragment in (encoded[:first], encoded[first:second], encoded[second:]):
            if fragment:
                sys.stdout.write(fragment)
                sys.stdout.flush()
                time.sleep(0.003)
        return
    sys.stdout.write(encoded)
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


def write_workspace_file(path, content, request_id):
    """Exercise the client filesystem broker; the outer agent has no host workspace bind."""
    send({
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "fs/write_text_file",
        "params": {
            "sessionId": "fixture-session",
            "path": path,
            "content": content,
        },
    })
    response = read_message()
    if response is None or response.get("id") != request_id or "error" in response:
        raise SystemExit(120)


def join_path(root, relative):
    return root.rstrip("/") + "/" + relative.lstrip("/")


sys.stderr.write("fixture-stderr:" + SENTINEL + "\n")
if MODE == "stderr-overflow":
    sys.stderr.write("x" * 70000)
sys.stderr.flush()
if MODE == "stderr-flood":
    chunk = b"x" * 8192
    while True:
        os.write(2, chunk)

if MODE == "no-initialize":
    time.sleep(30)
    raise SystemExit(0)

initialize = read_message()
if initialize is None or initialize.get("method") != "initialize":
    raise SystemExit(91)

expected_fs = {
    "fs-read-write": {"readTextFile": True, "writeTextFile": True},
    "fs-denied-outside": {"readTextFile": True, "writeTextFile": True},
    "fs-cap-read-only": {"readTextFile": True, "writeTextFile": False},
    "fs-cap-write-only": {"readTextFile": False, "writeTextFile": True},
    "fs-cap-none": None,
}.get(MODE, "unchecked")
if expected_fs != "unchecked":
    actual_fs = initialize.get("params", {}).get("clientCapabilities", {}).get("fs")
    if actual_fs != expected_fs:
        respond(initialize, error={
            "code": -32602,
            "message": "unexpected client filesystem capabilities",
        })
        raise SystemExit(96)
if MODE in (
    "terminal-lifecycle",
    "terminal-kill-lifecycle",
    "terminal-cancelled-orphan",
    "terminal-cross-session-hang",
    "terminal-missing-session-hang",
    "terminal-near-wall",
):
    actual_terminal = initialize.get("params", {}).get("clientCapabilities", {}).get("terminal")
    if actual_terminal is not True:
        respond(initialize, error={"code": -32602, "message": "terminal capability was not enabled"})
        raise SystemExit(104)

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
if not cwd.startswith("/"):
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
if MODE == "terminal-cross-session-hang":
    # Deliberately pipeline the forged callback directly behind session/new. The host must bind
    # from the raw response before its transport can enqueue or dispatch this adjacent frame.
    send({
        "jsonrpc": "2.0",
        "id": 115,
        "method": "terminal/create",
        "params": {
            "sessionId": "other-session",
            "command": "/usr/bin/echo",
            "args": ["wire-terminal"],
            "cwd": cwd,
            "env": [],
            "outputByteLimit": 4096,
        },
    })

prompt = read_message()
if prompt is None or prompt.get("method") != "session/prompt":
    raise SystemExit(94)
prompt_text = prompt.get("params", {}).get("prompt", [{}])[0].get("text", "")
expected_objective = "exercise the protocol fixture" if MODE in GENERIC_CONTRACT_MODES else "edit the fixture"
expected_context = "protocol evidence" if MODE in GENERIC_CONTRACT_MODES else "compiler evidence"
if expected_objective not in prompt_text or expected_context not in prompt_text:
    respond(prompt, error={"code": -32602, "message": "prompt lost objective or context"})
    raise SystemExit(95)

if MODE in ("fs-cap-read-only", "fs-cap-write-only", "fs-cap-none"):
    respond(prompt, {"stopReason": "end_turn"})
    raise SystemExit(0)

if MODE == "protocol-frame-flood":
    # Each tiny notification is valid JSON-RPC, but the host must reject the aggregate frame
    # count before the SDK's internally unbounded transport queues can amplify it in memory.
    for ordinal in range(64):
        send({
            "jsonrpc": "2.0",
            "method": "contract/unknown_notification",
            "params": {"ordinal": ordinal},
        })
    time.sleep(30)
    raise SystemExit(0)

if MODE == "fs-denied-outside":
    outside = cwd.rstrip("/").rsplit("/", 1)[0] + "/outside.txt"
    send({
        "jsonrpc": "2.0",
        "id": 102,
        "method": "fs/read_text_file",
        "params": {
            "sessionId": "fixture-session",
            "path": outside,
        },
    })
    denied_response = read_message()
    if denied_response is None or denied_response.get("id") != 102:
        raise SystemExit(100)
    if denied_response.get("error", {}).get("code") != -32602:
        raise SystemExit(101)
    respond(prompt, {"stopReason": "end_turn"})
    raise SystemExit(0)

if MODE == "fs-read-write":
    source = join_path(cwd, "src/module.c")
    send({
        "jsonrpc": "2.0",
        "id": 100,
        "method": "fs/read_text_file",
        "params": {
            "sessionId": "fixture-session",
            "path": source,
            "line": 1,
            "limit": 1,
        },
    })
    read_response = read_message()
    if read_response is None or read_response.get("id") != 100:
        raise SystemExit(97)
    if read_response.get("result", {}).get("content") != "old source\n":
        raise SystemExit(98)
    send({
        "jsonrpc": "2.0",
        "id": 101,
        "method": "fs/write_text_file",
        "params": {
            "sessionId": "fixture-session",
            "path": source,
            "content": "new source through broker\n",
        },
    })
    write_response = read_message()
    if write_response is None or write_response.get("id") != 101 or "error" in write_response:
        raise SystemExit(99)
if MODE == "pipelined-callbacks":
    source = join_path(cwd, "contract/artifact.txt")
    for request_id in (130, 131):
        send({
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "fs/read_text_file",
            "params": {
                "sessionId": "fixture-session",
                "path": source,
                "line": 1,
                "limit": 1,
            },
        })
    responses = [read_message(), read_message()]
    responses_by_id = {
        response.get("id"): response
        for response in responses
        if isinstance(response, dict)
    }
    if set(responses_by_id) != {130, 131}:
        raise SystemExit(121)
    if any(
        response.get("result", {}).get("content") != "original artifact\n"
        for response in responses_by_id.values()
    ):
        raise SystemExit(122)
    respond(prompt, {"stopReason": "end_turn"})
    raise SystemExit(0)
if MODE == "unknown-methods":
    send({
        "jsonrpc": "2.0",
        "id": 132,
        "method": "contract/unknown_request",
        "params": {"opaque": "generic-value"},
    })
    send({
        "jsonrpc": "2.0",
        "method": "contract/unknown_notification",
        "params": {"opaque": "generic-value"},
    })
    unknown_response = read_message()
    if unknown_response is None or unknown_response.get("id") != 132:
        raise SystemExit(123)
    if unknown_response.get("error", {}).get("code") != -32601:
        raise SystemExit(124)
    respond(prompt, {"stopReason": "end_turn"})
    raise SystemExit(0)
if MODE == "forbidden-write":
    send({
        "jsonrpc": "2.0",
        "id": 133,
        "method": "fs/write_text_file",
        "params": {
            "sessionId": "fixture-session",
            "path": join_path(cwd, "forbidden-canary.txt"),
            "content": "attempted overwrite payload\n",
        },
    })
    denied_response = read_message()
    if denied_response is None or denied_response.get("id") != 133:
        raise SystemExit(131)
    if denied_response.get("error", {}).get("code") != -32602:
        raise SystemExit(132)
    respond(prompt, {"stopReason": "end_turn"})
    raise SystemExit(0)
if MODE == "permission-default-deny":
    send({
        "jsonrpc": "2.0",
        "id": 103,
        "method": "session/request_permission",
        "params": {
            "sessionId": "fixture-session",
            "toolCall": {
                "sessionUpdate": "tool_call_update",
                "toolCallId": "permission-tool",
                "title": "Run exact fixture command",
                "kind": "execute",
                "status": "pending",
            },
            "options": [
                {"optionId": "allow", "name": "Allow once", "kind": "allow_once"},
                {"optionId": "reject", "name": "Reject once", "kind": "reject_once"},
            ],
        },
    })
    permission_response = read_message()
    outcome = (permission_response or {}).get("result", {}).get("outcome", {})
    if permission_response is None or permission_response.get("id") != 103:
        raise SystemExit(102)
    if outcome.get("outcome") != "selected" or outcome.get("optionId") != "reject":
        raise SystemExit(103)
if MODE == "terminal-lifecycle":
    terminal_argument = "wire-terminal"
    send({
        "jsonrpc": "2.0",
        "id": 104,
        "method": "terminal/create",
        "params": {
            "sessionId": "fixture-session",
            "command": "/usr/bin/echo",
            "args": [terminal_argument],
            "cwd": cwd,
            "env": [],
            "outputByteLimit": 4096,
        },
    })
    create_response = read_message()
    terminal_id = (create_response or {}).get("result", {}).get("terminalId")
    if create_response is None or create_response.get("id") != 104 or not terminal_id:
        raise SystemExit(105)
    # A permission callback carries a real ToolCallUpdate. Binding the terminal here exercises
    # the callback-only path: the client must validate/count the tool call before the terminal
    # side effect, exactly as it does for session/update notifications.
    send({
        "jsonrpc": "2.0",
        "id": 105,
        "method": "session/request_permission",
        "params": {
            "sessionId": "fixture-session",
            "toolCall": {
                "sessionUpdate": "tool_call_update",
                "toolCallId": "terminal-tool",
                "title": "Run exact fixture command",
                "kind": "execute",
                "status": "in_progress",
                "content": [{"type": "terminal", "terminalId": terminal_id}],
            },
            "options": [
                {"optionId": "allow", "name": "Allow once", "kind": "allow_once"},
                {"optionId": "reject", "name": "Reject once", "kind": "reject_once"},
            ],
        },
    })
    permission_response = read_message()
    permission_outcome = (permission_response or {}).get("result", {}).get("outcome", {})
    if permission_response is None or permission_response.get("id") != 105:
        raise SystemExit(106)
    if permission_outcome.get("outcome") != "selected" or permission_outcome.get("optionId") != "reject":
        raise SystemExit(107)
    send({
        "jsonrpc": "2.0",
        "id": 106,
        "method": "terminal/wait_for_exit",
        "params": {"sessionId": "fixture-session", "terminalId": terminal_id},
    })
    wait_response = read_message()
    if wait_response is None or wait_response.get("id") != 106:
        raise SystemExit(108)
    if wait_response.get("result", {}).get("exitCode") != 0:
        raise SystemExit(109)
    send({
        "jsonrpc": "2.0",
        "id": 107,
        "method": "terminal/output",
        "params": {"sessionId": "fixture-session", "terminalId": terminal_id},
    })
    output_response = read_message()
    if output_response is None or output_response.get("id") != 107:
        raise SystemExit(110)
    if output_response.get("result", {}).get("output") != "wire-terminal\n":
        raise SystemExit(111)
    send({
        "jsonrpc": "2.0",
        "id": 108,
        "method": "terminal/release",
        "params": {"sessionId": "fixture-session", "terminalId": terminal_id},
    })
    release_response = read_message()
    if release_response is None or release_response.get("id") != 108 or "error" in release_response:
        raise SystemExit(112)
    respond(prompt, {"stopReason": "end_turn"})
    raise SystemExit(0)
if MODE == "terminal-kill-lifecycle":
    send({
        "jsonrpc": "2.0",
        "id": 117,
        "method": "terminal/create",
        "params": {
            "sessionId": "fixture-session",
            "command": "/usr/bin/sleep",
            "args": ["30"],
            "cwd": cwd,
            "env": [],
            "outputByteLimit": 4096,
        },
    })
    create_response = read_message()
    terminal_id = (create_response or {}).get("result", {}).get("terminalId")
    if create_response is None or create_response.get("id") != 117 or not terminal_id:
        raise SystemExit(125)
    send({
        "jsonrpc": "2.0",
        "id": 118,
        "method": "session/request_permission",
        "params": {
            "sessionId": "fixture-session",
            "toolCall": {
                "sessionUpdate": "tool_call_update",
                "toolCallId": "terminal-kill-tool",
                "title": "Exercise terminal kill lifecycle",
                "kind": "execute",
                "status": "in_progress",
                "content": [{"type": "terminal", "terminalId": terminal_id}],
            },
            "options": [
                {"optionId": "allow", "name": "Allow once", "kind": "allow_once"},
                {"optionId": "reject", "name": "Reject once", "kind": "reject_once"},
            ],
        },
    })
    permission_response = read_message()
    permission_outcome = (permission_response or {}).get("result", {}).get("outcome", {})
    if permission_response is None or permission_response.get("id") != 118:
        raise SystemExit(126)
    if permission_outcome.get("outcome") != "selected" or permission_outcome.get("optionId") != "reject":
        raise SystemExit(127)
    send({
        "jsonrpc": "2.0",
        "id": 119,
        "method": "terminal/kill",
        "params": {"sessionId": "fixture-session", "terminalId": terminal_id},
    })
    kill_response = read_message()
    if kill_response is None or kill_response.get("id") != 119 or "error" in kill_response:
        raise SystemExit(128)
    send({
        "jsonrpc": "2.0",
        "id": 120,
        "method": "terminal/wait_for_exit",
        "params": {"sessionId": "fixture-session", "terminalId": terminal_id},
    })
    wait_response = read_message()
    if wait_response is None or wait_response.get("id") != 120:
        raise SystemExit(129)
    if wait_response.get("result", {}).get("signal") not in ("SIGTERM", "SIGKILL"):
        raise SystemExit(130)
    send({
        "jsonrpc": "2.0",
        "id": 121,
        "method": "terminal/output",
        "params": {"sessionId": "fixture-session", "terminalId": terminal_id},
    })
    output_response = read_message()
    if output_response is None or output_response.get("id") != 121 or "error" in output_response:
        raise SystemExit(133)
    send({
        "jsonrpc": "2.0",
        "id": 122,
        "method": "terminal/release",
        "params": {"sessionId": "fixture-session", "terminalId": terminal_id},
    })
    release_response = read_message()
    if release_response is None or release_response.get("id") != 122 or "error" in release_response:
        raise SystemExit(134)
    respond(prompt, {"stopReason": "end_turn"})
    raise SystemExit(0)
if MODE == "terminal-cancelled-orphan":
    send({
        "jsonrpc": "2.0",
        "id": 109,
        "method": "terminal/create",
        "params": {
            "sessionId": "fixture-session",
            "command": "/usr/bin/echo",
            "args": ["wire-terminal"],
            "cwd": cwd,
            "env": [],
            "outputByteLimit": 4096,
        },
    })
    create_response = read_message()
    if create_response is None or create_response.get("id") != 109:
        raise SystemExit(113)
    if not (create_response.get("result", {}).get("terminalId")):
        raise SystemExit(114)
    # This is an agent-selected protocol stop reason, not host cancellation. The deliberately
    # orphaned terminal must therefore be validated and rejected by finishSession.
    respond(prompt, {"stopReason": "cancelled"})
    raise SystemExit(0)
if MODE == "terminal-cross-session-hang":
    # A fatal cross-session callback must end the host exchange even if the peer never sends a
    # prompt response and ignores the callback error. The callback was pipelined above.
    time.sleep(30)
    raise SystemExit(0)
if MODE == "terminal-missing-session-hang":
    send({
        "jsonrpc": "2.0",
        "id": 116,
        "method": "terminal/create",
        "params": {
            "command": "/usr/bin/echo",
            "args": ["wire-terminal"],
            "cwd": cwd,
            "env": [],
            "outputByteLimit": 4096,
        },
    })
    # Missing correlation must also be fatal instead of becoming an SDK callback error that the
    # peer can ignore while leaving session/prompt pending.
    time.sleep(30)
    raise SystemExit(0)
if MODE == "terminal-near-wall":
    write_workspace_file(join_path(cwd, "src/module.c"), "near-wall terminal requested\n", 110)
    time.sleep(0.65)
    send({
        "jsonrpc": "2.0",
        "id": 111,
        "method": "terminal/create",
        "params": {
            "sessionId": "fixture-session",
            "command": "/usr/bin/sleep",
            "args": ["30"],
            "cwd": cwd,
            "env": [],
            "outputByteLimit": 4096,
        },
    })
    create_response = read_message()
    if create_response is None:
        raise SystemExit(0)
    time.sleep(30)
    raise SystemExit(0)
if READY and MODE != "cancel-after-response":
    write_workspace_file(READY, "ready\n", 801)

if MODE == "physical-newline-in-string":
    # This is an actual LF byte inside the JSON string, not the valid two-byte JSON escape `\\n`.
    prefix = '{"jsonrpc":"2.0","id":' + json.dumps(prompt["id"]) + ',"result":{"stopReason":"end'
    sys.stdout.write(prefix + "\nturn" + '"}}\n')
    sys.stdout.flush()
    time.sleep(30)
    raise SystemExit(0)

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

stop_reasons = {
    "stop-max-tokens": "max_tokens",
    "stop-max-turn-requests": "max_turn_requests",
    "stop-refusal": "refusal",
}
if MODE in stop_reasons:
    respond(prompt, {"stopReason": stop_reasons[MODE]})
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
    child_pid = os.fork()
    if child_pid == 0:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        time.sleep(30)
        os._exit(0)
    if READY:
        write_workspace_file(READY, str(child_pid) + "\n", 802)

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

source = join_path(
    cwd,
    "contract/artifact.txt" if MODE == "fragmented-stdout" else "src/module.c",
)
if MODE != "fs-read-write":
    content = "updated artifact\n" if MODE == "fragmented-stdout" else "new source\n"
    write_workspace_file(source, content, 803)

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

if MODE == "response-then-stderr-burst":
    # Wait until the host has accepted the clean response and entered protocol shutdown, then
    # write just over the fixture's aggregate limit and exit. This fits in a pipe, so the host
    # must prove natural EOF rather than relying on writer backpressure before counting it.
    sys.stdin.read()
    os.write(2, b"z" * ((16 * 1024) + 1))
    raise SystemExit(0)

if MODE == "response-then-stdout-burst":
    # The protocol flow is no longer allowed to parse frames after the clean response, but the
    # raw stdout descriptor still belongs to the aggregate produced-output accountant.
    sys.stdin.read()
    os.write(1, b"q" * (128 * 1024))
    raise SystemExit(0)

if MODE == "cancel-after-response":
    # Host stdin closes only after it accepted the final response and entered shutdown.
    sys.stdin.read()
    raise SystemExit(0)

if MODE in ("success-hang", "success-child-hang"):
    time.sleep(30)
