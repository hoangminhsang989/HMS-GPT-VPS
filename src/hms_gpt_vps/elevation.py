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

    def validate(self) -> None:
        if not isinstance(self.reason, str):
            raise ValueError("elevation reason must be a string")
        if not isinstance(self.explicitly_approved, bool):
            raise ValueError("elevation explicitly_approved must be boolean")
        if not isinstance(self.explicitly_denied, bool):
            raise ValueError("elevation explicitly_denied must be boolean")
        if self.explicitly_approved and self.explicitly_denied:
            raise ValueError("elevation request cannot be both approved and denied")


def evaluate_elevation(request: ElevationRequest) -> ElevationDecision:
    request.validate()
    if not request.reason.strip():
        return ElevationDecision.NOT_REQUIRED
    if request.explicitly_denied:
        return ElevationDecision.DENIED
    if request.explicitly_approved:
        return ElevationDecision.APPROVED
    return ElevationDecision.REQUIRE_APPROVAL
