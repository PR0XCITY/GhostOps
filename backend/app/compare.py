"""Compare two Builder designs saved in slots A and B.

Saving a design runs the same static check as the Builder (terraform plan, OPA,
graph diff, Infracost; no MiniStack, nothing signed) and keeps a snapshot of the
result next to the architecture, so the comparison page loads instantly.

snapshot(check)      monthly cost, verdict preview, pillar scores, risk counts and
                     per-service cost from one static check
diff(a, b)           services only in A, only in B, and every setting (config field
                     or usage input) that differs between services with the same
                     name and type; defaults are filled in first, so "unset" and
                     "set to the default" are the same
highlights(a, b)     which design is cheaper (lower monthly cost; unknown if either
                     cost is unknown) and which has fewer risks: fewer blocking
                     findings (security CRITICAL/HIGH) first, then fewer findings
                     in total, then fewer penalty points; equal on all = tie
"""

from __future__ import annotations

from typing import Any

from app.certificate import BLOCKING, PENALTY, PILLARS, blocks
from app.generator import validate

SLOTS = ("A", "B")
COST_EPSILON = 0.005  # half a cent: below this the two costs are the same


def _service_costs(check: dict[str, Any]) -> list[dict[str, Any]]:
    """Monthly cost per service: the sum of its resources' priced rows (None if none priced)."""
    owner = {}
    for service in check.get("services", []):
        for address in service.get("resources", []):
            owner[address] = service["name"]
    totals: dict[str, float | None] = {s["name"]: None for s in check.get("services", [])}
    for row in check.get("cost_breakdown", []):
        name = owner.get(row["resource"].split("[")[0])
        if name is not None and row.get("monthly_usd") is not None:
            totals[name] = round((totals[name] or 0.0) + row["monthly_usd"], 2)
    return [{"name": s["name"], "type": s["type"], "monthly_usd": totals[s["name"]]}
            for s in check.get("services", [])]


def snapshot(check: dict[str, Any]) -> dict[str, Any]:
    flags = check["risk_flags"]
    return {
        "monthly_usd": check["cost_delta"]["monthly_usd"],
        "cost_note": check["cost_delta"].get("note"),
        "verdict": check["verdict_preview"],
        "pillars": {p: {"score": v["score"], "findings": v["findings"]} for p, v in check["pillars"].items()},
        "risk_count": len(flags),
        "blocking_count": sum(blocks(f) for f in flags),
        "penalty": sum(PENALTY.get(f["severity"], 0) for f in flags),
        "risk_flags": [{"rule": f["rule"], "severity": f["severity"], "resource": f["resource"],
                        "pillar": f.get("pillar", "security")} for f in flags],
        "resource_count": check["resource_count"],
        "services": _service_costs(check),
    }


def diff(a: dict[str, Any], b: dict[str, Any]) -> dict[str, Any]:
    """What differs between two architectures (both must be valid)."""
    sa = {s.slug: s for s in validate(a)}
    sb = {s.slug: s for s in validate(b)}
    same = [n for n in sa if n in sb and sa[n].type == sb[n].type]
    only_a = [{"name": n, "type": s.type} for n, s in sa.items() if n not in same]
    only_b = [{"name": n, "type": s.type} for n, s in sb.items() if n not in same]
    changed = []
    for name in same:
        x, y = sa[name], sb[name]
        for field in dict.fromkeys([*x.config, *y.config]):
            if x.config.get(field) != y.config.get(field):
                changed.append({"service": name, "type": x.type, "field": field,
                                "a": x.config.get(field), "b": y.config.get(field)})
        for field in dict.fromkeys([*x.usage, *y.usage]):
            if x.usage.get(field) != y.usage.get(field):
                changed.append({"service": name, "type": x.type, "field": f"usage.{field}",
                                "a": x.usage.get(field), "b": y.usage.get(field)})
    return {"only_in_a": only_a, "only_in_b": only_b, "changed_settings": changed,
            "identical": not (only_a or only_b or changed)}


def _risk_key(snap: dict[str, Any]) -> tuple[int, int, int]:
    return snap["blocking_count"], snap["risk_count"], snap["penalty"]


def highlights(a: dict[str, Any], b: dict[str, Any]) -> dict[str, Any]:
    ca, cb = a["monthly_usd"], b["monthly_usd"]
    if ca is None or cb is None:
        cheaper = {"slot": None, "difference_usd": None, "reason": "The monthly cost of one design is unknown."}
    elif abs(ca - cb) < COST_EPSILON:
        cheaper = {"slot": "tie", "difference_usd": 0.0, "reason": "Both designs cost the same per month."}
    else:
        slot, diff_usd = ("A", cb - ca) if ca < cb else ("B", ca - cb)
        cheaper = {"slot": slot, "difference_usd": round(diff_usd, 2),
                   "reason": f"Design {slot} costs ${diff_usd:.2f} less per month."}

    ka, kb = _risk_key(a), _risk_key(b)
    if ka == kb:
        fewer = {"slot": "tie", "reason": "Both designs have the same findings count and weight."}
    else:
        slot = "A" if ka < kb else "B"
        win, lose = (a, b) if slot == "A" else (b, a)
        if win["blocking_count"] != lose["blocking_count"]:
            why = f"{win['blocking_count']} blocking finding(s) against {lose['blocking_count']}"
        elif win["risk_count"] != lose["risk_count"]:
            why = f"{win['risk_count']} finding(s) against {lose['risk_count']}"
        else:
            why = f"lighter findings ({win['penalty']} penalty points against {lose['penalty']})"
        fewer = {"slot": slot, "reason": f"Design {slot} has fewer risks: {why}."}
    return {"cheaper": cheaper, "fewer_risks": fewer}


def comparison(saved: dict[str, dict[str, Any] | None]) -> dict[str, Any]:
    """The GET /comparisons body: both slots, plus diff and highlights when both are saved."""
    a, b = saved.get("A"), saved.get("B")
    both = a is not None and b is not None
    return {
        "A": a, "B": b,
        "diff": diff(a["architecture"], b["architecture"]) if both else None,
        "highlights": highlights(a["snapshot"], b["snapshot"]) if both else None,
        "pillars": list(PILLARS),
        "blocking_severities": sorted(BLOCKING),
    }
