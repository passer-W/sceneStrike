"""
ASG (Attack Scene Graph) tool exposed to the LLM agent.

The tool answers three kinds of questions:

* ``read_asg``         — get a compact summary of the current scene graph.
* ``get_attack_chains``— get ranked multi-step attack chains that reach a
                         known vulnerable node.
* ``get_subgraph``     — get the neighbours of a node (both directions) so the
                         agent can reason about the local context.

The ASG itself is rebuilt and persisted by ``utils.asg.update_asg_for_task``;
this addon only reads from ``<task_path>/asg.json`` so it never mutates the
graph.
"""

from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, List, Optional

from utils import asg as _asg
from utils.logger import logger


# ---------------------------------------------------------------------------
# Path resolution
# ---------------------------------------------------------------------------

def _resolve_task_path(task_path: Optional[str] = None) -> Optional[str]:
    """Pick the ASG file path. Prefer the explicit override, then ``TASK_ID``."""
    if task_path:
        return os.path.join(task_path, "asg.json")
    # Lazy import: ``config`` initialises random API keys on import which can
    # fail in a clean shell (empty API_KEYS). We only need TASK_ID here.
    try:
        from config import config  # noqa: WPS433
        task_id = getattr(config, "TASK_ID", None)
    except Exception:
        task_id = None
    if task_id:
        candidate = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                 "tasks", str(task_id), "asg.json")
        if os.path.exists(candidate):
            return candidate
    # Fall back to the most recent task directory.
    tasks_root = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tasks")
    if os.path.isdir(tasks_root):
        candidates = []
        for entry in os.listdir(tasks_root):
            full = os.path.join(tasks_root, entry, "asg.json")
            if os.path.exists(full):
                candidates.append((os.path.getmtime(full), full))
        if candidates:
            candidates.sort(reverse=True)
            return candidates[0][1]
    return None


def _load(task_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    path = _resolve_task_path(task_path)
    if not path:
        return None
    asg = _asg.load_asg(path)
    if asg:
        asg.setdefault("source_path", path)
    return asg


# ---------------------------------------------------------------------------
# Tool entry points
# ---------------------------------------------------------------------------

def read_asg(task_path: Optional[str] = None, max_nodes: int = 80) -> str:
    """
    Return a compact textual summary of the current ASG.

    The summary lists every node (truncated to ``max_nodes``) together with the
    aggregate edge statistics. Use ``get_subgraph`` for details on a single node.
    """
    asg = _load(task_path)
    if not asg:
        return "[asg] no ASG available — explore more pages first"

    stats = asg.get("stats", {})
    nodes = asg.get("nodes", [])[:max_nodes]
    lines = [
        "[asg] version={ver} nodes={n} edges={e} (data={d} control={c} semantic={s})".format(
            ver=asg.get("version", 1),
            n=stats.get("node_count", len(asg.get("nodes", []))),
            e=stats.get("edge_count", len(asg.get("edges", []))),
            d=stats.get("data_edges", 0),
            c=stats.get("control_edges", 0),
            s=stats.get("semantic_edges", 0),
        ),
        "[asg] source: {}".format(asg.get("source_path", "?")),
        "[asg] nodes:",
    ]
    for n in nodes:
        marker = " [VULN]" if n.get("vuln") else ""
        lines.append(
            "  - id={id} {method} {url}{marker}".format(
                id=n.get("id", ""),
                method=n.get("method", "?"),
                url=n.get("url") or n.get("path") or "?",
                marker=marker,
            )
        )
    if len(asg.get("nodes", [])) > max_nodes:
        lines.append("  ... ({} more nodes, increase max_nodes to see them)".format(
            len(asg["nodes"]) - max_nodes))
    return "\n".join(lines)


def get_attack_chains(task_path: Optional[str] = None, top_k: int = 5,
                      max_len: int = 6) -> str:
    """
    Return the top-K ranked attack chains (entry → vulnerable node).

    A chain is a path in the ASG. Each step is annotated with the edge type
    that connects it to the next step so the agent can decide whether the
    chain is data-flow driven, control-flow driven, or only semantically
    related.
    """
    asg = _load(task_path)
    if not asg:
        return "[asg] no ASG available — explore more pages first"

    chains = asg.get("chains") or _asg.extract_attack_chains(asg, max_len=max_len, max_chains=top_k)
    if not chains:
        return "[asg] no attack chain reaches a known vulnerable node yet"

    out: List[str] = []
    for i, c in enumerate(chains[:top_k], 1):
        steps = c.get("steps", [])
        bullets: List[str] = []
        for j, s in enumerate(steps):
            edge = s.get("edge_to_next") or {}
            edge_str = ""
            if edge:
                bits = [edge.get("type", "?")]
                if edge.get("key"):
                    bits.append("key={}".format(edge["key"]))
                if edge.get("channel"):
                    bits.append("channel={}".format(edge["channel"]))
                if edge.get("reason"):
                    bits.append("reason={}".format(edge["reason"]))
                edge_str = "  --[{}]-->".format(", ".join(bits))
            bullets.append(
                "      {i}. {method} {url}{edge}".format(
                    i=j + 1,
                    method=s.get("method", "?"),
                    url=s.get("url") or s.get("path") or "?",
                    edge=edge_str,
                )
            )
        out.append(
            "[asg] chain #{i} (score={score}, length={n}):\n{id_path}\n{steps}".format(
                i=i,
                score=c.get("score", 0),
                n=len(steps),
                id_path="  path: " + " -> ".join(c.get("chain", [])),
                steps="\n".join(bullets),
            )
        )
    return "\n\n".join(out)


def get_subgraph(node_id: str, task_path: Optional[str] = None,
                 depth: int = 1, max_neighbours: int = 10) -> str:
    """
    Return the local neighbourhood of ``node_id`` up to ``depth`` hops.

    Useful when the agent wants to reason about which upstream API calls a
    given endpoint depends on, or which downstream calls become reachable
    after a successful exploit.
    """
    asg = _load(task_path)
    if not asg:
        return "[asg] no ASG available — explore more pages first"

    nodes_by_id = {n["id"]: n for n in asg.get("nodes", [])}
    if node_id not in nodes_by_id:
        # Tolerate fuzzy matching by URL or name.
        for n in asg.get("nodes", []):
            if n.get("url") == node_id or n.get("name") == node_id or n.get("path") == node_id:
                node_id = n["id"]
                break
        else:
            return "[asg] node '{}' not found in ASG".format(node_id)

    fwd: Dict[str, List[Dict[str, Any]]] = {}
    inc: Dict[str, List[Dict[str, Any]]] = {}
    for e in asg.get("edges", []):
        fwd.setdefault(e["src"], []).append(e)
        inc.setdefault(e["dst"], []).append(e)

    visited = {node_id}
    frontier_up: set = set(inc.get(node_id, []) and [e["src"] for e in inc[node_id]] or [])
    frontier_dn: set = set(fwd.get(node_id, []) and [e["dst"] for e in fwd[node_id]] or [])
    for _ in range(max(0, depth - 1)):
        new_up, new_dn = set(), set()
        for u in frontier_up - visited:
            for e in inc.get(u, []):
                new_up.add(e["src"])
        for d in frontier_dn - visited:
            for e in fwd.get(d, []):
                new_dn.add(e["dst"])
        visited |= frontier_up | frontier_dn
        frontier_up, frontier_dn = new_up - visited, new_dn - visited
    visited |= frontier_up | frontier_dn

    selected = [n for n in asg.get("nodes", []) if n["id"] in visited]
    sel_ids = {n["id"] for n in selected}
    edges = [e for e in asg.get("edges", []) if e["src"] in sel_ids and e["dst"] in sel_ids]

    def _render(n: Dict[str, Any]) -> str:
        marker = " [VULN]" if n.get("vuln") else ""
        centre = " *" if n["id"] == node_id else ""
        return "  - {id}{c}: {method} {url}{m}".format(
            id=n.get("id", ""),
            c=centre,
            method=n.get("method", "?"),
            url=n.get("url") or n.get("path") or "?",
            m=marker,
        )

    def _render_edge(e: Dict[str, Any]) -> str:
        bits = [e.get("type", "?")]
        if e.get("key"):
            bits.append("key=" + str(e["key"]))
        if e.get("reason"):
            bits.append("reason=" + str(e["reason"]))
        return "    {src} --[{meta}]--> {dst}".format(
            src=e["src"], dst=e["dst"], meta=", ".join(bits),
        )

    # Trim if too many neighbours.
    if len(selected) > max_neighbours + 1:
        kept = [nodes_by_id[node_id]] + [n for n in selected if n["id"] != node_id][:max_neighbours]
        kept_ids = {n["id"] for n in kept}
        edges = [e for e in edges if e["src"] in kept_ids and e["dst"] in kept_ids]
        selected = kept

    lines = ["[asg] subgraph around '{}' (depth={}, nodes={}, edges={}):".format(
        node_id, depth, len(selected), len(edges))]
    lines.extend(_render(n) for n in selected)
    lines.extend(_render_edge(e) for e in edges)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Dispatcher used by ``executor.execute_tool``
# ---------------------------------------------------------------------------

_TOOL_DISPATCH = {
    "read_asg": read_asg,
    "get_attack_chains": get_attack_chains,
    "get_subgraph": get_subgraph,
}


def run(xml_payload: str) -> str:
    """
    Router invoked by the agent's tool executor.

    ``xml_payload`` is an XML string produced by the LLM. It must contain a
    ``<action>`` element naming the tool and the arguments for that tool::

        <value>
            <action>read_asg</action>
        </value>

        <value>
            <action>get_attack_chains</action>
            <top_k>5</top_k>
        </value>

        <value>
            <action>get_subgraph</action>
            <node_id>page_login</node_id>
            <depth>2</depth>
        </value>
    """
    try:
        import xmltodict
    except ImportError:
        return "[asg] xmltodict not available"

    if not isinstance(xml_payload, str):
        return "[asg] invalid payload"

    try:
        payload = xmltodict.parse(xml_payload).get("value", {}) or {}
    except Exception as exc:
        return "[asg] failed to parse XML: {}".format(exc)

    action = payload.get("action")
    if not action:
        return "[asg] missing <action> in payload"
    if action not in _TOOL_DISPATCH:
        return "[asg] unknown action '{}'. Available: {}".format(
            action, ", ".join(sorted(_TOOL_DISPATCH)))

    fn = _TOOL_DISPATCH[action]
    kwargs: Dict[str, Any] = {}
    for k in ("task_path", "max_nodes", "top_k", "max_len", "depth", "max_neighbours"):
        if k in payload and payload[k] not in (None, ""):
            try:
                kwargs[k] = int(payload[k])
            except (TypeError, ValueError):
                kwargs[k] = payload[k]
    if "node_id" in payload:
        kwargs["node_id"] = payload["node_id"]
    try:
        result = fn(**kwargs)
    except TypeError:
        # Fall back to calling with the positional node_id when needed.
        if action == "get_subgraph" and "node_id" in payload:
            result = fn(payload["node_id"])
        else:
            raise
    logger.info("[asg] tool %s -> %d chars", action, len(result))
    return result
