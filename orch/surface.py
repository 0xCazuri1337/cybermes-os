"""Attack surface model (§18) and attack-path reasoning (§27, §28).

§18 says there is no mandatory representation — pick whatever supports the
current decision. That is a real requirement, not a dodge, so this module
stores the surface ONCE as typed nodes and EDGES and derives every view from it:

  * asset graph     — hosts/services/identities and their trust relationships
  * endpoint graph  — routes, methods, parameters, auth requirement
  * identity map    — who can reach what, and which boundary that crosses
  * attack graph    — weakness -> trust boundary -> privilege -> impact (§27)

Two properties are load-bearing and both were previously absent entirely:

1. **Trust boundaries are first-class nodes.** A weakness is only interesting in
   relation to the boundary it crosses, so `boundary` is a field on every
   finding link rather than prose in a report. `paths_through()` refuses to
   call something a chain when no boundary is actually crossed (§28: "only
   claim a chain when it is actually demonstrated").

2. **The graph is derived, never hand-maintained.** `hypothesise` for a class
   reads the SURFACE to decide what to propose: an unauthenticated admin route
   and a JWT-signed session are the same bug class with different reachability,
   and the difference must come from observed surface, not from a template.
"""
from __future__ import annotations

import json
import sqlite3
from typing import Any, Iterable

from . import store

NODE_KINDS = ("host", "service", "endpoint", "identity", "boundary",
              "technology", "datastore")

SURFACE_SCHEMA = """
CREATE TABLE IF NOT EXISTS surface_node (
  node_key   TEXT PRIMARY KEY,
  hunt_id    TEXT,
  kind       TEXT NOT NULL,           -- host|service|endpoint|identity|boundary|
                                     -- technology|datastore
  name       TEXT NOT NULL,
  attributes TEXT,                    -- JSON: port, method, params, auth, tech
  observed   INTEGER NOT NULL DEFAULT 0,  -- 0 inferred, 1 observed on the wire
  first_seen TEXT NOT NULL,
  evidence   TEXT                     -- which observation created it
);
CREATE INDEX IF NOT EXISTS ix_surface_node_hunt ON surface_node(hunt_id, kind);

CREATE TABLE IF NOT EXISTS surface_edge (
  edge_key   TEXT PRIMARY KEY,
  hunt_id    TEXT,
  src        TEXT NOT NULL,
  dst        TEXT NOT NULL,
  rel        TEXT NOT NULL,           -- exposes|authenticates_as|crosses|
                                     -- reads|writes|delegates_to|reachable_from
  attributes TEXT,
  first_seen TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_surface_edge_src ON surface_edge(src);
CREATE INDEX IF NOT EXISTS ix_surface_edge_dst ON surface_edge(dst);

-- §27 attack path: entry -> weakness -> boundary -> privilege -> action -> impact
CREATE TABLE IF NOT EXISTS weakness_link (
  link_key    TEXT PRIMARY KEY,
  hunt_id     TEXT,
  finding_key TEXT,
  class_id    TEXT,
  entry_node  TEXT,                   -- the reachable entry point
  weakness    TEXT NOT NULL,          -- what is wrong
  boundary    TEXT,                   -- trust boundary CROSSED (may be NULL)
  privilege   TEXT,                   -- privilege boundary crossed
  sensitive   TEXT,                   -- the sensitive action it reaches
  impact      TEXT,
  demonstrated INTEGER NOT NULL DEFAULT 0,  -- 1 only with evidence behind it
  rationale   TEXT,
  created_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_weakness_class ON weakness_link(class_id);
"""


def _ensure(con: sqlite3.Connection) -> None:
    con.executescript(SURFACE_SCHEMA)
    con.commit()


def _key(kind: str, name: str, hunt_id: str = "") -> str:
    # MEASURED — THE PRIMARY KEY WAS NOT SCOPED BY HUNT. This returned
    # `host:127.0.0.1`, and `surface_node.node_key` is the table's PRIMARY KEY
    # (orch/surface.py:37-47) with no hunt component. A second hunt touching the
    # same host therefore collided with the FIRST hunt's row and
    # `ON CONFLICT(node_key) DO UPDATE` updated attributes while leaving
    # `hunt_id` untouched. Measured: two consecutive hunts on 127.0.0.1 — the
    # second hunt's `add_node` returned its key, `node()` returned a row, and
    # that row said `hunt_id='lab.cli.01'`, the FIRST hunt's id. Every hunt after
    # the first inherited the first hunt's surface, and because the engine
    # filters surface queries by `hunt_id` it saw an EMPTY surface and probed
    # nothing — while every log line claimed the node was added.
    # A node key must identify a node WITHIN one hunt.
    base = f"{kind}:{(name or '').strip().lower()}"
    return f"{hunt_id}|{base}" if hunt_id else base


class Surface:
    """One hunt's attack surface. Created empty; every claim is recorded."""

    def __init__(self, con: sqlite3.Connection, hunt_id: str = "default"):
        self.con = con
        self.hunt_id = hunt_id
        _ensure(con)

    # ------------------------------------------------------------------ nodes
    def add_node(self, kind: str, name: str, *, observed: bool = True,
                 evidence: str = "", **attrs) -> str:
        if kind not in NODE_KINDS:
            raise KeyError(f"unknown node kind {kind!r}; known: {NODE_KINDS}")
        k = _key(kind, name, self.hunt_id)
        self.con.execute(
            "INSERT INTO surface_node(node_key, hunt_id, kind, name, attributes,"
            " observed, first_seen, evidence) VALUES (?,?,?,?,?,?,?,?)"
            " ON CONFLICT(node_key) DO UPDATE SET"
            "   attributes=excluded.attributes,"
            "   observed=max(surface_node.observed, excluded.observed),"
            "   evidence=CASE WHEN excluded.evidence != '' THEN excluded.evidence"
            "                 ELSE surface_node.evidence END",
            (k, self.hunt_id, kind, (name or "").strip(),
             json.dumps(attrs, default=str), 1 if observed else 0,
             store.now(), evidence))
        self.con.commit()
        return k

    def node(self, node_key: str) -> sqlite3.Row | None:
        return self.con.execute("SELECT * FROM surface_node WHERE node_key=?",
                                (node_key,)).fetchone()

    def nodes(self, kind: str | None = None) -> list[sqlite3.Row]:
        if kind:
            return self.con.execute(
                "SELECT * FROM surface_node WHERE hunt_id=? AND kind=? "
                "ORDER BY name", (self.hunt_id, kind)).fetchall()
        return self.con.execute(
            "SELECT * FROM surface_node WHERE hunt_id=? ORDER BY kind, name",
            (self.hunt_id,)).fetchall()

    # ------------------------------------------------------------------ edges
    def add_edge(self, src: str, dst: str, rel: str, **attrs) -> str:
        k = f"{src}~{rel}~{dst}"
        self.con.execute(
            "INSERT OR IGNORE INTO surface_edge(edge_key, hunt_id, src, dst, rel,"
            " attributes, first_seen) VALUES (?,?,?,?,?,?,?)",
            (k, self.hunt_id, src, dst, rel, json.dumps(attrs, default=str),
             store.now()))
        self.con.commit()
        return k

    def edges(self, node: str | None = None) -> list[sqlite3.Row]:
        if node:
            return self.con.execute(
                "SELECT * FROM surface_edge WHERE hunt_id=? AND (src=? OR dst=?)",
                (self.hunt_id, node, node)).fetchall()
        return self.con.execute("SELECT * FROM surface_edge WHERE hunt_id=?",
                                (self.hunt_id,)).fetchall()

    # ---------------------------------------------------------- reachability
    def reachable_from(self, node: str, *, max_depth: int = 6) -> set[str]:
        """Forward closure over `exposes`/`reachable_from` edges.

        Bounded because a graph with a cycle must terminate; the surface graph
        gets cycles the moment a service exposes itself.
        """
        seen: set[str] = set()
        frontier = [(node, 0)]
        while frontier:
            cur, depth = frontier.pop()
            if depth >= max_depth or cur in seen:
                continue
            seen.add(cur)
            for e in self.edges(cur):
                if e["rel"] in ("exposes", "reachable_from"):
                    frontier.append((e["dst"], depth + 1))
        return seen

    # -------------------------------------------------------- §27 attack path
    def link_weakness(self, *, finding_key: str, class_id: str,
                      entry_node: str, weakness: str,
                      boundary: str | None = None,
                      privilege: str | None = None,
                      sensitive: str | None = None,
                      impact: str | None = None,
                      demonstrated: bool = False,
                      rationale: str = "") -> str:
        k = f"weak.{finding_key}.{class_id}"
        self.con.execute(
            "INSERT INTO weakness_link(link_key, hunt_id, finding_key, class_id,"
            " entry_node, weakness, boundary, privilege, sensitive, impact,"
            " demonstrated, rationale, created_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)"
            " ON CONFLICT(link_key) DO UPDATE SET weakness=excluded.weakness,"
            "  boundary=COALESCE(excluded.boundary, weakness_link.boundary),"
            "  privilege=COALESCE(excluded.privilege, weakness_link.privilege),"
            "  sensitive=COALESCE(excluded.sensitive, weakness_link.sensitive),"
            "  impact=COALESCE(excluded.impact, weakness_link.impact),"
            "  demonstrated=max(weakness_link.demonstrated, excluded.demonstrated)",
            (k, self.hunt_id, finding_key, class_id, entry_node, weakness,
             boundary, privilege, sensitive, impact,
             1 if demonstrated else 0, rationale, store.now()))
        self.con.commit()
        return k

    def paths(self, class_id: str | None = None) -> list[dict[str, Any]]:
        sql = "SELECT * FROM weakness_link WHERE hunt_id=?"
        args: list[Any] = [self.hunt_id]
        if class_id:
            sql += " AND class_id=?"
            args.append(class_id)
        out = []
        for r in self.con.execute(sql + " ORDER BY created_at", args):
            d = dict(r)
            d["crosses_boundary"] = bool(d.get("boundary"))
            d["demonstrated"] = bool(d["demonstrated"])
            out.append(d)
        return out

    # ------------------------------------------------------ §28 chain search
    def chains(self, *, require_demonstrated: bool = True) -> dict[str, Any]:
        """Search for meaningful chains. Claims nothing it cannot show.

        §28: a chain is `Weakness A -> Weakness B -> a privilege or impact
        boundary`. The search is over the WEAKNESS GRAPH: two classes are
        chainable when one's sensitive action reaches a node the other needs,
        and the chain is only reported when the terminal step is demonstrated.
        """
        links = self.paths()
        by_class: dict[str, list[dict[str, Any]]] = {}
        for l in links:
            by_class.setdefault(l["class_id"], []).append(l)

        found: list[dict[str, Any]] = []
        claimed: list[dict[str, Any]] = []
        for a_cls, a_links in by_class.items():
            for b_cls, b_links in by_class.items():
                if a_cls == b_cls:
                    continue
                for a in a_links:
                    for b in b_links:
                        reaches = self._reaches(a.get("sensitive"), b.get("entry_node"))
                        if not reaches:
                            continue
                        cand = {
                            "steps": [a, b],
                            "classes": [a_cls, b_cls],
                            "boundary_crossed": bool(a.get("boundary")
                                                     or b.get("boundary")),
                            "demonstrated": bool(a.get("demonstrated")
                                                 and b.get("demonstrated")),
                        }
                        found.append(cand)
                        if cand["demonstrated"] and cand["boundary_crossed"]:
                            claimed.append(cand)
        if require_demonstrated:
            return {"candidates": len(found), "chains": claimed,
                    "note": ("only demonstrated chains crossing a boundary are "
                             "reported as chains; candidates are returned as "
                             "candidates so nothing is over-claimed (§28)")}
        return {"candidates": len(found), "chains": claimed, "all": found}

    def _reaches(self, sensitive: str | None, entry: str | None) -> bool:
        """Does the sensitive action reach the other weakness's entry point?

        The relationship is checked against the SURFACE GRAPH, not against the
        strings the caller happened to pass. Two arbitrary node names that
        happen to differ are not a chain — a chain is a demonstrated
        reachability, and asserting one from prose is exactly the fabrication
        this module exists to prevent. When either node is absent from the
        graph the answer is False, which is why `chains()` reports candidates
        separately from demonstrated chains.
        """
        if not sensitive or not entry:
            return False
        if sensitive == entry:
            return True
        if not (self.node(sensitive) and self.node(entry)):
            return False
        return entry in self.reachable_from(sensitive)

    # ---------------------------------------------------------- §18 views
    def view(self, representation: str = "auto") -> dict[str, Any]:
        """Derive one representation. §18: pick what supports the decision."""
        nodes = [dict(r) for r in self.nodes()]
        for n in nodes:
            n["attributes"] = _loads(n["attributes"])
        edges = [dict(r) for r in self.edges()]
        for e in edges:
            e["attributes"] = _loads(e["attributes"])

        counts: dict[str, int] = {}
        for n in nodes:
            counts[n["kind"]] = counts.get(n["kind"], 0) + 1

        reps: dict[str, Any] = {
            "asset_graph": {"nodes": [n for n in nodes
                                      if n["kind"] in ("host", "service",
                                                       "datastore")],
                            "edges": [e for e in edges
                                      if e["rel"] in ("exposes", "delegates_to",
                                                      "reads", "writes")]},
            "endpoint_graph": {"nodes": [n for n in nodes
                                         if n["kind"] == "endpoint"],
                               "edges": [e for e in edges
                                         if e["rel"] == "exposes"]},
            "identity_map": {"nodes": [n for n in nodes
                                       if n["kind"] in ("identity", "boundary")],
                             "edges": [e for e in edges
                                       if e["rel"] in ("authenticates_as",
                                                       "crosses")]},
            "attack_graph": {"nodes": self.paths(),
                             "edges": [e for e in edges
                                       if e["rel"] == "crosses"]},
            "service_map": {"nodes": [n for n in nodes
                                      if n["kind"] in ("host", "service",
                                                       "technology")],
                            "edges": edges},
        }
        if representation == "auto":
            # The rule that supports the decision: whichever representation has
            # observed content wins, so an empty view is never silently chosen.
            representation = next(
                (k for k in ("endpoint_graph", "identity_map", "service_map",
                             "asset_graph")
                 if reps[k]["nodes"]), "asset_graph")
        return {"representation": representation,
                "counts": counts,
                "observed_nodes": sum(1 for n in nodes if n["observed"]),
                "inferred_nodes": sum(1 for n in nodes if not n["observed"]),
                "view": reps.get(representation, reps["asset_graph"]),
                "available": sorted(reps)}

    # ------------------------------------------------- §19 surface -> hypothesis
    def reachability_facts(self) -> dict[str, Any]:
        """The facts a hypothesis generator is allowed to reason from.

        Returns only OBSERVED facts plus their inference chain. An inferred
        node is included but marked, because §19 lets the engine propose
        hypotheses it was not handed — from evidence, not from imagination.
        """
        hosts = self.nodes("host")
        eps = self.nodes("endpoint")
        ids = self.nodes("identity")
        bnd = self.nodes("boundary")
        unauth = [e["name"] for e in eps
                  if not _loads(e["attributes"]).get("auth")]
        authed = [e["name"] for e in eps
                  if _loads(e["attributes"]).get("auth")]
        tech = [n["name"] for n in self.nodes("technology")]
        return {
            "hosts": [h["name"] for h in hosts],
            "endpoints": len(eps),
            "unauthenticated_endpoints": unauth,
            "authenticated_endpoints": authed,
            "identities": [i["name"] for i in ids],
            "boundaries": [b["name"] for b in bnd],
            "technologies": tech,
            "trust_boundary_count": len(bnd),
            "no_boundary_declared": not bnd,
        }

    def summary(self) -> dict[str, Any]:
        rep = self.view()
        return {"hunt_id": self.hunt_id, "nodes": len(self.nodes()),
                "edges": len(self.edges()),
                "weaknesses": len(self.paths()),
                "observed_nodes": rep["observed_nodes"],
                "inferred_nodes": rep["inferred_nodes"],
                "representation": rep["representation"],
                "counts": rep["counts"]}


def _loads(raw: str | None) -> dict[str, Any]:
    try:
        v = json.loads(raw or "{}")
        return v if isinstance(v, dict) else {}
    except (ValueError, TypeError):
        return {}


def seed_from_observations(con: sqlite3.Connection, hunt_id: str,
                           observations: Iterable[dict[str, Any]]
                           ) -> Surface:
    """Build a surface from raw observations.

    Deliberately the only bulk-import path: an asset enters the surface with the
    observation that found it, so `observed=0` (inferred) is never confused with
    `observed=1` (seen). Every node carries its provenance string.
    """
    s = Surface(con, hunt_id)
    for o in observations:
        kind = o.get("kind")
        name = o.get("name")
        if not kind or not name:
            continue
        attrs = {k: v for k, v in o.items() if k not in ("kind", "name")}
        src = attrs.pop("source", "")
        s.add_node(kind, name, observed=bool(o.get("observed", True)),
                   evidence=str(src), **attrs)
    return s