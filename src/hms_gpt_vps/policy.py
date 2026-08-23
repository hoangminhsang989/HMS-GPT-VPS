"""Fail-closed policy primitives for HMS-GPT-VPS."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Decision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


@dataclass(frozen=True)
class PolicyRequest:
    capability: str
    project_id: str | None = None
    destructive: bool = False
    explicitly_approved: bool = False


def evaluate(request: PolicyRequest) -> Decision:
    """Evaluate the smallest Stage-0 policy surface.

    Unknown/empty capability and missing project scope are denied. Destructive
    actions require explicit approval before they can be considered allowed.
    """
    if not request.capability.strip():
        return Decision.DENY
    if not request.project_id or not request.project_id.strip():
        return Decision.DENY
    if request.destructive and not request.explicitly_approved:
        return Decision.REQUIRE_APPROVAL
    return Decision.ALLOW
