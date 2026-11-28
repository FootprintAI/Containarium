"""Stub Anthropic Messages endpoint for the #3761 verification.

Scripts the tool calls from the issue's verify steps and logs every request
body to /out/requests.jsonl. Synthetic values only; no real account.

Step is chosen from the number of tool_result blocks in the conversation:
  0 -> Read /work/.env                                   (verify step 1)
  1 -> Write /work/out.txt with the [[EMAIL:..]] marker  (verify step 2)
  2 -> Bash "cat /work/.env; false"                      (verify step 3)
  3 -> Bash that prints numbers                           (verify step 4)
  4 -> end_turn
Requests that carry no Read/Write/Bash tools (side calls) get a short text.
"""
import json
import re
import sys
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOG = "/out/requests.jsonl"


def tool_results(messages):
    out = []
    for m in messages:
        if m.get("role") != "user" or not isinstance(m.get("content"), list):
            continue
        for b in m["content"]:
            if b.get("type") == "tool_result":
                c = b.get("content")
                if isinstance(c, list):
                    c = "".join(x.get("text", "") for x in c if isinstance(x, dict))
                out.append(c or "")
    return out


def plan(body):
    names = {t.get("name") for t in body.get("tools", []) if isinstance(t, dict)}
    if not {"Read", "Write", "Bash"} <= names:
        return ("text", "ok")
    results = tool_results(body.get("messages", []))
    step = len(results)
    if step == 0:
        return ("tool", "Read", {"file_path": "/work/.env"})
    if step == 1:
        m = re.search(r"\[\[EMAIL:[0-9a-f]{12}\]\]", results[0])
        marker = m.group(0) if m else "NO_EMAIL_MARKER_IN_RESULT"
        return ("tool", "Write", {"file_path": "/work/out.txt", "content": "owner " + marker + "\n"})
    if step == 2:
        return ("tool", "Bash", {"command": "cat /work/.env; false", "description": "failed command"})
    if step == 3:
        return ("tool", "Bash", {"command": "echo 42; echo 3.14", "description": "numbers"})
    return ("text", "done")


def sse(handler, events):
    handler.send_response(200)
    handler.send_header("content-type", "text/event-stream")
    handler.send_header("cache-control", "no-cache")
    handler.end_headers()
    for name, data in events:
        handler.wfile.write(f"event: {name}\ndata: {json.dumps(data)}\n\n".encode())
        handler.wfile.flush()


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.end_headers()
        self.wfile.write(b"{}")

    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get("content-length", 0)))
        with open(LOG, "a") as f:
            f.write(json.dumps({"path": self.path, "body": raw.decode("utf-8", "replace")}) + "\n")
        if "count_tokens" in self.path:
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"input_tokens": 10}')
            return
        body = json.loads(raw or b"{}")
        p = plan(body)
        model = body.get("model", "stub")
        mid = "msg_" + uuid.uuid4().hex[:12]
        start = {"type": "message_start", "message": {"id": mid, "type": "message", "role": "assistant",
                 "model": model, "content": [], "stop_reason": None, "stop_sequence": None,
                 "usage": {"input_tokens": 1, "output_tokens": 1}}}
        if p[0] == "tool":
            _, name, inp = p
            blocks = [("content_block_start", {"type": "content_block_start", "index": 0, "content_block":
                       {"type": "tool_use", "id": "toolu_" + uuid.uuid4().hex[:12], "name": name, "input": {}}}),
                      ("content_block_delta", {"type": "content_block_delta", "index": 0, "delta":
                       {"type": "input_json_delta", "partial_json": json.dumps(inp)}})]
            stop = "tool_use"
        else:
            blocks = [("content_block_start", {"type": "content_block_start", "index": 0, "content_block":
                       {"type": "text", "text": ""}}),
                      ("content_block_delta", {"type": "content_block_delta", "index": 0, "delta":
                       {"type": "text_delta", "text": p[1]}})]
            stop = "end_turn"
        if not body.get("stream"):
            content = ([{"type": "tool_use", "id": "toolu_x", "name": p[1], "input": p[2]}] if p[0] == "tool"
                       else [{"type": "text", "text": p[1]}])
            msg = dict(start["message"], content=content, stop_reason=stop)
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(msg).encode())
            return
        sse(self, [("message_start", start)] + blocks + [
            ("content_block_stop", {"type": "content_block_stop", "index": 0}),
            ("message_delta", {"type": "message_delta", "delta": {"stop_reason": stop, "stop_sequence": None},
                               "usage": {"output_tokens": 1}}),
            ("message_stop", {"type": "message_stop"})])


if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
