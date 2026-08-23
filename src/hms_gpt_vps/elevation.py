from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class ElevationDecision(str, Enum):
    NOT_REQUIRED = "not_required"
    REQUIRE_APPROVAL = "require_approval"
    APPROVED = "approved"
    DENIED = "denied"


@dataclass(frozen=True)
class ElevationRequest:
    reason: str
    explicitly_approved: bool = False
    explicitly_denied: bool = False


def evaluate_elevation(request: ElevationRequest) -> ElevationDecision:
    if not request.reason.strip():
        return ElevationDecision.NOT_REQUIRED
    if request.explicitly_denied:
        return ElevationDecision.DENIED
    if request.explicitly_approved:
        return ElevationDecision.APPROVED
    return ElevationDecision.REQUIRE_APPROVAL
