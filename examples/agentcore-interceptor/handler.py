"""PoC AgentCore Gateway interceptor — the input/output gate, as a Lambda.

Proves four things the spike (docs/AGENTCORE-GATEWAY-INTERCEPTOR-SPIKE.md)
claims are possible, and one it says is unknown:

  1. REQUEST  — read `params.arguments` of a tools/call.
  2. REQUEST  — short-circuit with a deny the gateway returns verbatim.
  3. RESPONSE — redact a tool result before it re-enters the agent's context.
  4. Both     — emit an audit event for the hash chain.
  5. FAILMODE — crash on purpose, so we can observe whether the gateway fails
                open (call proceeds) or closed (call is refused). The docs do
                not say. Until that is measured, none of this is a control.

Python, not Go, on purpose: it matches AWS's documented examples exactly and
needs no build step, so the fail-open question gets answered in hours rather
than after a packaging detour. Production should either compile the Go
inspection engine to a Lambda or make this a thin proxy to it — the detection
logic here is deliberately shallow.

Payload contracts (both handled):
  MCP targets  — `event["mcp"]`,  bodies are parsed JSON.
  HTTP targets — `event["http"]`, bodies are base64-encoded strings. Inference
                 targets share this shape.
"""

import base64
import json
import logging
import os
import re
import urllib.request

logger = logging.getLogger()
logger.setLevel(logging.INFO)

OUTPUT_VERSION = "1.0"

# Where audit events go. Unset = log only, which is the default so the PoC
# runs standalone.
AUDIT_URL = os.environ.get("CONTAINARIUM_AUDIT_URL", "")
AUDIT_TOKEN = os.environ.get("CONTAINARIUM_AUDIT_TOKEN", "")

# Deliberate-failure switch for experiment 5. "crash" raises, "timeout" hangs
# past the Lambda deadline. Never set in production.
FAILMODE = os.environ.get("CONTAINARIUM_INTERCEPTOR_FAILMODE", "")

# --- detection ---------------------------------------------------------------
# Shallow on purpose. The real engine is rules + semantic; this is enough to
# prove the mechanism carries a verdict.

# Secrets that should never appear in a tool call's arguments — the exfil
# direction. AWS access key ids, private key headers, and long base64 blobs
# riding in a URL query (the classic "GET /?d=<dump>" channel).
_EXFIL_PATTERNS = [
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "aws_access_key_id"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "private_key"),
    (re.compile(r"[?&][a-z_]{1,16}=[A-Za-z0-9+/]{120,}={0,2}"), "long_blob_in_query"),
]

# Injection markers in data flowing INTO the agent's context. The markdown-image
# rule is EchoLeak's (CVE-2025-32711) actual exfil vector: untrusted content
# embeds an image whose URL carries the stolen data, and the renderer fetches it
# with no user action at all.
_INJECTION_PATTERNS = [
    (re.compile(r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions", re.I),
     "instruction_override"),
    (re.compile(r"^\s*(system|assistant)\s*:", re.I | re.M), "role_spoof"),
    (re.compile(r"!\[[^\]]*\]\(\s*https?://[^)]*[?&][^)]*\)"), "markdown_image_exfil"),
    (re.compile(r"<\s*img[^>]+src\s*=\s*[\"']https?://[^\"']*[?&]", re.I), "html_image_exfil"),
]


def scan_exfil(text):
    """Return the first exfil rule this text trips, or None."""
    for pattern, name in _EXFIL_PATTERNS:
        if pattern.search(text):
            return name
    return None


def scan_injection(text):
    """Return every injection rule this text trips."""
    return [name for pattern, name in _INJECTION_PATTERNS if pattern.search(text)]


def redact(text):
    """Neutralise injection vectors in place, preserving the surrounding text.

    Redaction rather than blocking: a tool result is usually mostly legitimate
    data the agent genuinely needs. Dropping the whole result to kill one
    embedded image turns a security control into an outage.
    """
    text = re.sub(r"!\[([^\]]*)\]\(\s*https?://[^)]*\)", r"[\1 — image removed]", text)
    text = re.sub(r"<\s*img[^>]*>", "[image removed]", text, flags=re.I)
    text = re.sub(
        r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions",
        "[redacted instruction]", text, flags=re.I,
    )
    return text


# --- audit -------------------------------------------------------------------

def emit_audit(action, detail):
    """Ship one event toward the Containarium audit hash chain.

    Fail-soft by design: the interceptor's verdict must not depend on the audit
    plane being reachable. A dropped audit event is a gap in evidence; a
    dropped tool call is an outage. Both are bad, and they are not equally bad.
    """
    event = {"action": action, "detail": detail}
    logger.info("audit %s", json.dumps(event))
    if not AUDIT_URL:
        return
    try:
        req = urllib.request.Request(
            AUDIT_URL,
            data=json.dumps(event).encode(),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {AUDIT_TOKEN}",
            },
        )
        urllib.request.urlopen(req, timeout=2).close()
    except Exception as exc:  # noqa: BLE001 — see docstring
        logger.warning("audit emit failed: %s", exc)


# --- MCP path ----------------------------------------------------------------

def deny(request_body, rule):
    """A JSON-RPC error the gateway hands straight back to the caller.

    Presence of transformedGatewayResponse is what makes the gateway skip the
    target entirely — this IS the block primitive.
    """
    return {
        "interceptorOutputVersion": OUTPUT_VERSION,
        "mcp": {
            "transformedGatewayResponse": {
                "statusCode": 200,
                "body": {
                    "jsonrpc": "2.0",
                    "id": request_body.get("id"),
                    "error": {
                        "code": -32001,
                        "message": f"blocked by Containarium output gate: {rule}",
                    },
                },
            }
        },
    }


def handle_mcp_request(mcp):
    body = mcp.get("gatewayRequest", {}).get("body", {}) or {}
    if body.get("method") != "tools/call":
        return {"interceptorOutputVersion": OUTPUT_VERSION,
                "mcp": {"transformedGatewayRequest": {"body": body}}}

    params = body.get("params", {}) or {}
    tool = params.get("name", "unknown")
    args = json.dumps(params.get("arguments", {}))

    rule = scan_exfil(args)
    if rule:
        emit_audit("output_gate.action_blocked", {"tool": tool, "rule": rule})
        return deny(body, rule)

    emit_audit("output_gate.action_allowed", {"tool": tool})
    return {"interceptorOutputVersion": OUTPUT_VERSION,
            "mcp": {"transformedGatewayRequest": {"body": body}}}


def handle_mcp_response(mcp):
    response = mcp.get("gatewayResponse", {}) or {}
    body = response.get("body", {}) or {}
    result = body.get("result")

    # Only tool results carry untrusted external data. tools/list and friends
    # are gateway-generated and not a taint source.
    if not isinstance(result, dict) or "content" not in result:
        return _passthrough_mcp(response, body)

    hits, changed = [], False
    for item in result.get("content", []):
        if not isinstance(item, dict) or item.get("type") != "text":
            continue
        text = item.get("text", "")
        found = scan_injection(text)
        if found:
            hits.extend(found)
            item["text"] = redact(text)
            changed = True

    if changed:
        emit_audit("input_gate.redacted", {"rules": sorted(set(hits))})

    return _passthrough_mcp(response, body)


def _passthrough_mcp(response, body):
    return {
        "interceptorOutputVersion": OUTPUT_VERSION,
        "mcp": {
            "transformedGatewayResponse": {
                "statusCode": response.get("statusCode", 200),
                "body": body,
            }
        },
    }


# --- HTTP path (AgentCore Runtime + inference targets) -----------------------

def handle_http(http):
    """Base64 bodies, and the response body may be absent.

    When a payload filter excludes RESPONSE_BODY to stay under the 6 MB Lambda
    cap, `body` arrives as None — and DLP on that body is simply not possible.
    That blind spot is the reason the spike lists a payload-limit strategy as
    an open item; here we just record it rather than pretend to have scanned.
    """
    response = http.get("gatewayResponse")
    if response is None:
        return {"interceptorOutputVersion": OUTPUT_VERSION, "http": {}}

    encoded = response.get("body")
    if encoded is None:
        emit_audit("input_gate.skipped", {"reason": "response_body_excluded"})
        return {"interceptorOutputVersion": OUTPUT_VERSION, "http": {}}

    try:
        text = base64.b64decode(encoded).decode("utf-8", errors="replace")
    except (ValueError, TypeError) as exc:
        logger.warning("undecodable http body, passing through: %s", exc)
        return {"interceptorOutputVersion": OUTPUT_VERSION, "http": {}}

    hits = scan_injection(text)
    if not hits:
        return {"interceptorOutputVersion": OUTPUT_VERSION, "http": {}}

    emit_audit("input_gate.redacted", {"rules": sorted(set(hits))})
    cleaned = base64.b64encode(redact(text).encode()).decode()
    return {
        "interceptorOutputVersion": OUTPUT_VERSION,
        "http": {"transformedGatewayResponse": {"body": cleaned}},
    }


# --- entry point -------------------------------------------------------------

def lambda_handler(event, context):
    if FAILMODE == "crash":
        raise RuntimeError("deliberate interceptor failure (fail-open experiment)")
    if FAILMODE == "timeout":
        import time
        time.sleep(900)

    if "http" in event:
        return handle_http(event["http"])

    mcp = event.get("mcp", {}) or {}
    # A RESPONSE interceptor is distinguished only by gatewayResponse being
    # present and non-null — there is no explicit type field in the payload.
    if mcp.get("gatewayResponse") is not None:
        return handle_mcp_response(mcp)
    return handle_mcp_request(mcp)
