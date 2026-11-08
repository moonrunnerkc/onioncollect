"""The write socket's line protocol, shared by the writer and its client. One JSON object a line: the op and its
fields in; `ok` with a result, or `ok` false with an error code and a reason, out. Standard library only."""
import json

# A page is capped at 2 MB inflated; a snapshot of it, JSON-escaped, fits with room for the envelope.
LINE_CAP = 4 * 1024 * 1024

# The request could not be read as one of the writer's ops. The writer answers, then closes the connection.
NOT_JSON = "not_json"
OVERSIZE = "oversize"
UNKNOWN_OP = "unknown_op"
BAD_REQUEST = "bad_request"
INTERNAL = "internal"
CLOSING = frozenset({NOT_JSON, OVERSIZE, UNKNOWN_OP, BAD_REQUEST, INTERNAL})
# A well-formed request the stores turned down. The connection stays open.
REFUSED = "refused"
NOT_CHANGED = "not_changed"


def encode(message: dict) -> bytes:
    return json.dumps(message, ensure_ascii=False, separators=(",", ":")).encode() + b"\n"


def answer(result=None) -> dict:
    return {"ok": True, "result": result}


def error(code: str, reason: str) -> dict:
    return {"ok": False, "error": code, "reason": reason}
