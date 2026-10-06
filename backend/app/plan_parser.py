"""Normalize Terraform plan JSON into a flat list of resource changes.

Input is the output of `terraform show -json <planfile>` (format_version 1.x).
Output is one ResourceChange per managed resource instance in `resource_changes`.

Action mapping from Terraform's `change.actions` list:
  ["create"]            -> "create"
  ["update"]            -> "update"
  ["delete"]            -> "delete"
  ["no-op"]             -> "no-op"
  ["delete", "create"]  -> "replace"  (destroy then create)
  ["create", "delete"]  -> "replace"  (create_before_destroy)
Any other combination raises PlanParseError: for a safety gate, an action we do
not understand must fail loudly rather than be silently treated as harmless.

Data sources (mode "data") are skipped: reading data does not change
infrastructure. `before`/`after` are passed through as Terraform emits them,
including any sensitive values, so callers must not log them blindly.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

Action = Literal["create", "update", "delete", "replace", "no-op"]

_ACTION_MAP: dict[tuple[str, ...], Action] = {
    ("create",): "create",
    ("update",): "update",
    ("delete",): "delete",
    ("no-op",): "no-op",
    ("delete", "create"): "replace",
    ("create", "delete"): "replace",
}


class PlanParseError(ValueError):
    """The input is not a Terraform plan JSON this parser can trust."""


@dataclass(frozen=True)
class ResourceChange:
    address: str
    type: str
    action: Action
    before: dict[str, Any] | None
    after: dict[str, Any] | None
    name: str = ""
    provider_name: str = ""
    module_address: str | None = None
    # Attributes whose value is only known after apply (e.g. generated IDs).
    after_unknown: dict[str, Any] = field(default_factory=dict)
    # Terraform's original action list, kept for audit.
    raw_actions: tuple[str, ...] = ()
    # Set when the change targets a deposed object rather than the current one.
    deposed: str | None = None
    # Terraform's sensitivity masks: True, or a dict/list mirroring before/after.
    before_sensitive: Any = False
    after_sensitive: Any = False


def normalize_action(actions: list[str] | tuple[str, ...]) -> Action:
    key = tuple(actions)
    try:
        return _ACTION_MAP[key]
    except KeyError:
        raise PlanParseError(f"unsupported Terraform action combination: {list(key)}") from None


def parse_plan(plan: Any) -> list[ResourceChange]:
    """Normalize an already-decoded plan JSON document."""
    if not isinstance(plan, dict):
        raise PlanParseError(f"plan must be a JSON object, got {type(plan).__name__}")

    version = plan.get("format_version")
    if not isinstance(version, str):
        raise PlanParseError("missing format_version: not a `terraform show -json` plan")
    if version.split(".")[0] != "1":
        raise PlanParseError(f"unsupported plan format_version {version!r} (need 1.x)")

    raw_changes = plan.get("resource_changes", [])
    if not isinstance(raw_changes, list):
        raise PlanParseError("resource_changes must be a list")

    changes: list[ResourceChange] = []
    for i, rc in enumerate(raw_changes):
        if not isinstance(rc, dict):
            raise PlanParseError(f"resource_changes[{i}] must be an object")
        if rc.get("mode", "managed") != "managed":
            continue

        address = rc.get("address")
        rtype = rc.get("type")
        change = rc.get("change")
        if not isinstance(address, str) or not address:
            raise PlanParseError(f"resource_changes[{i}] has no address")
        if not isinstance(rtype, str) or not rtype:
            raise PlanParseError(f"{address}: missing type")
        if not isinstance(change, dict) or not isinstance(change.get("actions"), list):
            raise PlanParseError(f"{address}: missing change.actions")

        try:
            action = normalize_action(change["actions"])
        except PlanParseError as exc:
            raise PlanParseError(f"{address}: {exc}") from None

        before = change.get("before")
        after = change.get("after")
        for label, value in (("before", before), ("after", after)):
            if value is not None and not isinstance(value, dict):
                raise PlanParseError(f"{address}: change.{label} must be an object or null")

        after_unknown = change.get("after_unknown")
        changes.append(
            ResourceChange(
                address=address,
                type=rtype,
                action=action,
                before=before,
                after=after,
                name=rc.get("name", ""),
                provider_name=rc.get("provider_name", ""),
                module_address=rc.get("module_address"),
                after_unknown=after_unknown if isinstance(after_unknown, dict) else {},
                raw_actions=tuple(change["actions"]),
                deposed=rc.get("deposed"),
                before_sensitive=change.get("before_sensitive", False),
                after_sensitive=change.get("after_sensitive", False),
            )
        )
    return changes


def parse_plan_json(text: str | bytes) -> list[ResourceChange]:
    """Normalize plan JSON given as a string or bytes."""
    try:
        plan = json.loads(text)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise PlanParseError(f"invalid JSON: {exc}") from None
    return parse_plan(plan)


def load_plan(path: str | Path) -> list[ResourceChange]:
    """Normalize the plan JSON file at `path`."""
    return parse_plan_json(Path(path).read_bytes())
