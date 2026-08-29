"""
Attack Scene Graph (ASG) construction, persistence, and attack-chain extraction.

This module materialises the scene-aware part of SceneStrike inside the ctfSolver
agent. It takes the raw pages that ``flaghunter`` has explored (each page is a
JSON file under ``tasks/<task_id>/pages/`` that records the request/response of
one API call) and infers three kinds of cross-API dependencies:

* **Control dependency** — one API call must execute before another because it
  changes application state (login, register, payment, ...).
* **Data dependency** — the response of one API call feeds the request of
  another (e.g. the ``token`` returned by ``/login`` is sent in the header of
  ``/api/user``).
* **Semantic dependency** — two endpoints are related by URL / REST convention
  (prefix, parent path, resource hierarchy) even when there is no observable
  runtime link.

The inferred dependencies form the **Attack Scene Graph (ASG)**. The ASG is
serialised as JSON next to the page artefacts so that downstream agents (and
the LLM-exposed ``asg`` addon) can read and reason over it.

The module is intentionally self-contained and side-effect free except for
``save_asg`` / ``load_asg`` which touch the task directory.
"""

from __future__ import annotations

import json
import os
import re
import uuid
from collections import defaultdict, deque
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# Node / edge helpers
# ---------------------------------------------------------------------------

# Methods that typically mutate server state and therefore produce control
# dependencies for downstream calls.
STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

# Common key names that flow between auth flows.
AUTH_KEYS = {
    "token", "access_token", "refreshtoken", "refresh_token",
    "session", "sessionid", "session_id", "sid", "jsessionid",
    "authorization", "cookie", "set-cookie", "phpsessid",
    "x-auth-token", "x-csrf-token", "csrf", "csrf_token", "csrfmiddlewaretoken",
    "userid", "user_id", "uid", "uuid", "openid",
}

# URL path segment keywords that imply stateful / sequential semantics.
SEMANTIC_GROUPS = {
    "auth":       {"login", "signin", "register", "signup", "logout", "signout",
                   "auth", "authenticate", "oauth", "sso", "token", "password",
                   "forgot", "reset", "verify", "captcha", "2fa", "mfa"},
    "user":       {"user", "users", "profile", "account", "me", "member",
                   "settings", "preferences", "avatar", "password"},
    "order":      {"order", "orders", "cart", "checkout", "pay", "payment",
                   "billing", "invoice", "refund", "coupon", "discount"},
    "admin":      {"admin", "manage", "management", "dashboard", "console",
                   "panel", "backstage", "system", "config"},
    "resource":   {"api", "v1", "v2", "v3", "rest", "graphql", "rpc"},
    "file":       {"upload", "download", "file", "files", "attachment",
                   "attachments", "image", "images", "media", "document"},
    "data":       {"list", "create", "read", "update", "delete", "search",
                   "query", "find", "get", "post", "edit"},
}

# Vulnerable HTTP status patterns that suggest the call touched something
# interesting during vuln detection.
INTERESTING_STATUS = {200, 201, 204, 301, 302, 400, 401, 403, 500, 502}


def _safe_json(value: Any) -> Any:
    """Best-effort JSON decode that never raises."""
    if isinstance(value, (dict, list, int, float, bool)) or value is None:
        return value
    if isinstance(value, str):
        s = value.strip()
        if not s:
            return None
        try:
            return json.loads(s)
        except Exception:
            return None
    return None


def _flatten_json(obj: Any, prefix: str = "") -> Dict[str, Any]:
    """Flatten a nested JSON object into a ``{dotted.path: value}`` mapping."""
    out: Dict[str, Any] = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = f"{prefix}.{k}" if prefix else str(k)
            out.update(_flatten_json(v, key))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            key = f"{prefix}[{i}]"
            out.update(_flatten_json(v, key))
    else:
        out[prefix] = obj
    return out


def _request_summary(req: Any) -> Dict[str, Any]:
    """Normalise a request object (dict or JSON string) into a flat summary."""
    data = _safe_json(req) or {}
    if not isinstance(data, dict):
        return {"raw": str(req)}
    method = (data.get("method") or data.get("type") or "GET").upper()
    url = data.get("url") or data.get("uri") or ""
    headers = data.get("header") or data.get("headers") or {}
    if isinstance(headers, str):
        headers = _safe_json(headers) or {}
    params = data.get("param") or data.get("params") or data.get("data") or {}
    if isinstance(params, str):
        params = _safe_json(params) or {}
    body = data.get("body") or data.get("json")
    if body is not None and not params:
        params = body
    return {
        "method": method,
        "url": url,
        "path": urlparse(url).path if url else "",
        "headers": {str(k).lower(): str(v) for k, v in (headers or {}).items()},
        "params": params or {},
    }


def _response_keys(resp: Any) -> Tuple[List[str], List[str], List[str]]:
    """Return (json_keys, header_keys, cookie_keys) for a response object."""
    data = _safe_json(resp) or {}
    if not isinstance(data, dict):
        return [], [], []
    body = data.get("content") or data.get("body") or data.get("text") or ""
    if isinstance(body, (dict, list)):
        flat = _flatten_json(body)
    else:
        flat = _flatten_json(_safe_json(body) or {})
    cookies = []
    headers = data.get("headers") or {}
    if isinstance(headers, str):
        headers = _safe_json(headers) or {}
    header_keys = [str(k).lower() for k in (headers or {}).keys()]
    set_cookie = headers.get("Set-Cookie") or headers.get("set-cookie")
    if set_cookie:
        cookies = [c.split("=", 1)[0].strip() for c in str(set_cookie).split(";,") if "=" in c]
    return list(flat.keys()), header_keys, cookies


def _page_to_node(page: Dict[str, Any]) -> Dict[str, Any]:
    """Convert a raw page record into an ASG node."""
    name = page.get("name") or page.get("id") or uuid.uuid4().hex[:8]
    req = _request_summary(page.get("request"))
    json_keys, header_keys, cookies = _response_keys(page.get("response"))
    desc = page.get("description") or page.get("desc") or ""
    key = page.get("key") or ""
    return {
        "id": page.get("id") or name,
        "name": name,
        "method": req["method"],
        "url": req["url"],
        "path": req["path"],
        "request_headers": list(req["headers"].keys()),
        "request_params": list((req["params"] or {}).keys()) if isinstance(req["params"], dict) else [],
        "response_json_keys": json_keys,
        "response_header_keys": header_keys,
        "response_cookies": cookies,
        "description": desc,
        "key": key,
        "vuln": bool(page.get("vuln")),
    }


# ---------------------------------------------------------------------------
# Dependency inference
# ---------------------------------------------------------------------------

def _common_prefix_len(a: str, b: str) -> int:
    """Length of the common URL path prefix (segment-aligned)."""
    if not a or not b:
        return 0
    a_parts = [p for p in a.split("/") if p]
    b_parts = [p for p in b.split("/") if p]
    i = 0
    while i < len(a_parts) and i < len(b_parts) and a_parts[i] == b_parts[i]:
        i += 1
    return i


def _semantic_group(path: str) -> Optional[str]:
    """Bucket a path by the first keyword it shares with ``SEMANTIC_GROUPS``."""
    if not path:
        return None
    parts = [p.lower() for p in path.split("/") if p]
    for group, keywords in SEMANTIC_GROUPS.items():
        for p in parts:
            if p in keywords:
                return group
    return None


def _is_child_path(parent: str, child: str) -> bool:
    """True if ``child`` is a strict sub-path of ``parent``."""
    if not parent or not child or parent == child:
        return False
    return child.startswith(parent.rstrip("/") + "/")


def infer_dependencies(pages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Infer control / data / semantic edges between pages.

    The output is a list of edge dicts::

        {"src": <page_id>, "dst": <page_id>, "type": "data", "key": "token"}

    Edges are deduplicated by ``(src, dst, type, key)``.
    """
    nodes = [_page_to_node(p) for p in pages]
    node_by_id = {n["id"]: n for n in nodes}
    edges: List[Dict[str, Any]] = []
    seen = set()

    def add(src: str, dst: str, etype: str, **extra: Any) -> None:
        if not src or not dst or src == dst:
            return
        key = (src, dst, etype, extra.get("key", ""))
        if key in seen:
            return
        seen.add(key)
        edge = {"src": src, "dst": dst, "type": etype}
        edge.update({k: v for k, v in extra.items() if v is not None})
        edges.append(edge)

    # Pre-compute the flattened param / header sets per node for fast lookup.
    node_param_set: Dict[str, set] = {
        n["id"]: {(k or "").lower() for k in (n["request_params"] or [])}
        for n in nodes
    }
    node_header_set: Dict[str, set] = {
        n["id"]: {(k or "").lower() for k in (n["request_headers"] or [])}
        for n in nodes
    }
    node_resp_keys: Dict[str, set] = {
        n["id"]: {(k.split(".")[-1] or "").lower() for k in (n["response_json_keys"] or [])}
        for n in nodes
    }
    node_resp_cookies: Dict[str, set] = {
        n["id"]: {(c or "").lower() for c in (n["response_cookies"] or [])}
        for n in nodes
    }

    # Generic header / cookie names that signal the request is auth-bound.
    # If a response produces an auth-shaped payload and the destination uses
    # any of these, we add a data edge even when the literal key name does
    # not match — that is the common case for ``token -> cookie`` flows.
    AUTH_HEADER_TOKENS = {"cookie", "authorization", "x-auth-token",
                          "x-csrf-token", "x-access-token"}

    for src in nodes:
        for dst in nodes:
            if src["id"] == dst["id"]:
                continue
            # ---- Data dependency -----------------------------------------
            # Response JSON key of src matches a request param of dst.
            for k in node_resp_keys.get(src["id"], set()):
                if k and k in node_param_set.get(dst["id"], set()):
                    add(src["id"], dst["id"], "data", key=k, channel="param")
            # Response cookie / header of src matches a request header of dst.
            for c in node_resp_cookies.get(src["id"], set()):
                if c and (c in node_header_set.get(dst["id"], set()) or c == "cookie"):
                    add(src["id"], dst["id"], "data", key=c, channel="cookie")
            # Any auth-shaped key from src flows into dst's headers/params.
            src_auth_keys = node_resp_keys.get(src["id"], set()) | node_resp_cookies.get(src["id"], set())
            for k in src_auth_keys:
                if k in AUTH_KEYS:
                    dst_uses_auth = (
                        k in node_param_set.get(dst["id"], set())
                        or k in node_header_set.get(dst["id"], set())
                        or any(h in AUTH_HEADER_TOKENS
                               for h in node_header_set.get(dst["id"], set()))
                    )
                    if dst_uses_auth:
                        add(src["id"], dst["id"], "data", key=k, channel="auth")

            # ---- Control dependency --------------------------------------
            # src is a state-changing call, dst is anything that depends on
            # the state (e.g. requires auth, or sits in a child path).
            if src["method"] in STATE_CHANGING_METHODS:
                # Same resource: child / sibling write → read.
                if _is_child_path(src["path"], dst["path"]) or _is_child_path(dst["path"], src["path"]):
                    add(src["id"], dst["id"], "control", reason="state-mutating-same-resource")
                # Auth call → subsequent call that uses auth-shaped params.
                if any(k in node_param_set.get(dst["id"], set())
                       or k in node_header_set.get(dst["id"], set())
                       for k in AUTH_KEYS):
                    if any(kw in (src["path"] or "").lower() for kw in ("login", "signin", "auth", "register", "token")):
                        add(src["id"], dst["id"], "control", reason="auth-gate")

            # ---- Semantic dependency -------------------------------------
            # Parent / child path.
            if _is_child_path(src["path"], dst["path"]):
                add(src["id"], dst["id"], "semantic", reason="child-path")
            elif _is_child_path(dst["path"], src["path"]):
                add(dst["id"], src["id"], "semantic", reason="child-path")
            # Same semantic group and shared URL prefix.
            sg_src = _semantic_group(src["path"])
            sg_dst = _semantic_group(dst["path"])
            if sg_src and sg_src == sg_dst and _common_prefix_len(src["path"], dst["path"]) >= 1:
                add(src["id"], dst["id"], "semantic", reason=f"group:{sg_src}")
            # Conventional auth chain: register → login → user.
            if any(k in (src["path"] or "").lower() for k in ("register", "signup")) \
                    and any(k in (dst["path"] or "").lower() for k in ("login", "signin", "auth")):
                add(src["id"], dst["id"], "semantic", reason="register-before-login")
            if any(k in (src["path"] or "").lower() for k in ("login", "signin", "auth")) \
                    and any(k in (dst["path"] or "").lower() for k in ("user", "profile", "me", "account")):
                add(src["id"], dst["id"], "semantic", reason="login-before-user")

    return edges


# ---------------------------------------------------------------------------
# Graph building, persistence, attack chains
# ---------------------------------------------------------------------------

def build_asg(pages: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Build the full ASG document for a list of pages."""
    nodes = [_page_to_node(p) for p in pages]
    edges = infer_dependencies(pages)
    # Adjacency for chain extraction.
    fwd: Dict[str, List[str]] = defaultdict(list)
    for e in edges:
        fwd[e["src"]].append(e["dst"])
    return {
        "version": 1,
        "stats": {
            "node_count": len(nodes),
            "edge_count": len(edges),
            "data_edges": sum(1 for e in edges if e["type"] == "data"),
            "control_edges": sum(1 for e in edges if e["type"] == "control"),
            "semantic_edges": sum(1 for e in edges if e["type"] == "semantic"),
        },
        "nodes": nodes,
        "edges": edges,
        "adjacency": {k: sorted(set(v)) for k, v in fwd.items()},
    }


def save_asg(asg: Dict[str, Any], path: str) -> str:
    """Write the ASG to ``path`` as pretty JSON. Returns the path."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(asg, f, ensure_ascii=False, indent=2)
    return path


def load_asg(path: str) -> Optional[Dict[str, Any]]:
    """Read an ASG from disk. Returns ``None`` on failure."""
    if not path or not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def _vuln_set(asg: Dict[str, Any]) -> set:
    return {n["id"] for n in asg.get("nodes", []) if n.get("vuln")}


def _incoming(asg: Dict[str, Any]) -> Dict[str, List[str]]:
    inc: Dict[str, List[str]] = defaultdict(list)
    for e in asg.get("edges", []):
        inc[e["dst"]].append(e["src"])
    return inc


def _all_simple_paths(asg: Dict[str, Any], start: str,
                      goals: Iterable[str], max_len: int = 6,
                      max_paths: int = 20) -> List[List[str]]:
    """Enumerate bounded-length simple paths from ``start`` to any node in ``goals``."""
    fwd = asg.get("adjacency", {}) or {}
    goal_set = set(goals)
    found: List[List[str]] = []

    def dfs(node: str, path: List[str], depth: int) -> None:
        if len(found) >= max_paths:
            return
        if node in goal_set and len(path) > 1:
            found.append(list(path))
            return
        if depth >= max_len:
            return
        for nxt in fwd.get(node, []) or []:
            if nxt in path:
                continue
            dfs(nxt, path + [nxt], depth + 1)

    if start in goal_set:
        return [[start]]
    dfs(start, [start], 0)
    return found


def _entry_nodes(asg: Dict[str, Any]) -> List[str]:
    """
    Nodes that act as scene entry points — i.e. they do not depend on any
    other API via a data-flow or control-flow edge.

    A node is an entry when no other node produces a *required* input for it
    (data or control). Semantic-only incoming edges do not count, because
    semantic dependency merely says the endpoints are related by URL — it
    does not imply that one must be called first.
    """
    nodes = [n["id"] for n in asg.get("nodes", [])]
    incoming_required: Dict[str, set] = defaultdict(set)
    for e in asg.get("edges", []):
        if e.get("type") in ("data", "control"):
            incoming_required[e["dst"]].add(e["src"])
    return [n for n in nodes if not incoming_required.get(n)]


def extract_attack_chains(asg: Dict[str, Any], max_len: int = 6,
                          max_chains: int = 20) -> List[Dict[str, Any]]:
    """
    Return a list of candidate attack chains, each shaped as::

        {
          "chain": [<node_id>, ...],
          "steps": [{...node, edge_to_next: {...}}, ...],
          "score": float
        }

    A chain is a path from an entry node to a node that has been flagged
    vulnerable (``node.vuln == True``). The score rewards data-flow edges and
    auth gates, which are the most exploitable signal in SceneStrike.
    """
    nodes_by_id = {n["id"]: n for n in asg.get("nodes", [])}
    edge_index: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for e in asg.get("edges", []):
        # Keep the highest-priority edge between a pair (data > control > semantic).
        priority = {"data": 3, "control": 2, "semantic": 1}.get(e.get("type"), 0)
        prev = edge_index.get((e["src"], e["dst"]))
        if prev is None or priority > prev.get("_prio", 0):
            edge_index[(e["src"], e["dst"])] = {**e, "_prio": priority}

    vulns = _vuln_set(asg)
    if not vulns:
        return []

    chains: List[Dict[str, Any]] = []
    for start in _entry_nodes(asg):
        for path in _all_simple_paths(asg, start, vulns,
                                      max_len=max_len, max_paths=max_chains):
            steps = []
            score = 0.0
            for i, nid in enumerate(path):
                node = dict(nodes_by_id.get(nid, {"id": nid, "name": nid}))
                if i + 1 < len(path):
                    edge = edge_index.get((nid, path[i + 1]), {})
                    node["edge_to_next"] = {
                        "type": edge.get("type"),
                        "key": edge.get("key"),
                        "reason": edge.get("reason"),
                        "channel": edge.get("channel"),
                    }
                    if edge.get("type") == "data":
                        score += 3.0
                    elif edge.get("type") == "control":
                        score += 2.0
                    else:
                        score += 1.0
                    if edge.get("channel") == "auth":
                        score += 1.5
                steps.append(node)
            chains.append({"chain": path, "steps": steps, "score": round(score, 2)})

    chains.sort(key=lambda c: c["score"], reverse=True)
    return chains[:max_chains]


# ---------------------------------------------------------------------------
# Convenience helpers for the agent loop
# ---------------------------------------------------------------------------

def load_pages_from_task(task_path: str) -> List[Dict[str, Any]]:
    """Load every ``*.json`` page artefact under ``<task_path>/pages/``."""
    pages_dir = os.path.join(task_path, "pages")
    if not os.path.isdir(pages_dir):
        return []
    pages: List[Dict[str, Any]] = []
    for fn in sorted(os.listdir(pages_dir)):
        if not fn.endswith(".json"):
            continue
        full = os.path.join(pages_dir, fn)
        try:
            with open(full, "r", encoding="utf-8") as f:
                page = json.load(f)
            if not page.get("id"):
                page["id"] = os.path.splitext(fn)[0]
            pages.append(page)
        except Exception:
            continue
    return pages


def update_asg_for_task(task_path: str, vuln_pages: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """
    Rebuild the ASG from the on-disk pages and persist it. Returns the new ASG.

    Pass ``vuln_pages`` to mark nodes as vulnerable before serialising.
    """
    pages = load_pages_from_task(task_path)
    if vuln_pages:
        vuln_ids = {p.get("id") or p.get("name") for p in vuln_pages}
        for p in pages:
            if (p.get("id") or p.get("name")) in vuln_ids:
                p["vuln"] = True
    asg = build_asg(pages)
    chains = extract_attack_chains(asg)
    asg["chains"] = chains
    asg_path = os.path.join(task_path, "asg.json")
    save_asg(asg, asg_path)
    return asg
