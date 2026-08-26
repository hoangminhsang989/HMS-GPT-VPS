from __future__ import annotations

from .principal_pairing_service import (
    PrincipalPairingResult,
    PrincipalPairingService,
    TrustedIntegrationPrincipal,
)


class ProvisionStateBoundPrincipalPairingService(PrincipalPairingService):
    """Production pairing service that commits READY after durable binding.

    PrincipalPairingService owns the cryptographic exchange and durable
    PrincipalSessionBinding publication. Only after that call returns may the
    provisioning state advance from PAIRING_PENDING to READY. Retrying after a
    crash is safe because the base service first recovers/verifies an existing
    exact binding, then this wrapper finishes the idempotent READY CAS.
    """

    def pair(
        self,
        principal: TrustedIntegrationPrincipal,
        pairing_link: str,
    ) -> PrincipalPairingResult:
        result = super().pair(principal, pairing_link)
        self.readiness.commit_principal_binding_ready()
        return result
