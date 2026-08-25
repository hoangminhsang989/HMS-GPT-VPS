from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import uuid

from .bootstrap_retirement import (
    _path_chain_has_redirect,
    _require_answer_iso_authority,
    detach_answer_iso_by_id as detach_answer_iso,
    retire_bootstrap_guest_by_id as retire_bootstrap_guest,
)
from .install_artifacts import TextSecretStore, clear_install_secrets
from .powershell_direct import PowerShellDirectCredential
from .provision_state import ProvisionRecord, ProvisionState, ProvisionStateStore


class PostInstallStateError(RuntimeError):
    pass


@dataclass(frozen=True)
class PostInstallFinalizationConfig:
    instance_id: str
    vm_name: str
    bootstrap_username: str
    answer_iso: Path
    answer_iso_sha256: str
    runtime_dir: Path
    vm_id: str = ""

    def validate(self) -> None:
        if not isinstance(self.instance_id, str) or not self.instance_id.strip():
            raise ValueError("instance_id is required")
        if not isinstance(self.vm_name, str) or not self.vm_name.strip():
            raise ValueError("vm_name is required")
        if not isinstance(self.vm_id, str) or not self.vm_id.strip():
            raise ValueError("vm_id is required for post-install finalization")
        try:
            canonical_vm_id = str(uuid.UUID(self.vm_id)).lower()
        except (ValueError, AttributeError) as exc:
            raise ValueError("vm_id must be a valid GUID") from exc
        if self.vm_id != canonical_vm_id:
            raise ValueError("vm_id must use canonical lowercase GUID form")
        if not isinstance(self.bootstrap_username, str) or not self.bootstrap_username.strip():
            raise ValueError("bootstrap_username is required")
        if not isinstance(self.answer_iso_sha256, str) or len(self.answer_iso_sha256) != 64:
            raise ValueError("answer_iso_sha256 must contain 64 hex characters")
        try:
            int(self.answer_iso_sha256, 16)
        except ValueError as exc:
            raise ValueError("answer_iso_sha256 must be hexadecimal") from exc

        runtime = self.runtime_dir.expanduser().absolute()
        if _path_chain_has_redirect(runtime):
            raise ValueError(
                "managed runtime directory must not traverse a link or reparse point"
            )
        answer = _require_answer_iso_authority(self.answer_iso)
        try:
            answer.relative_to(runtime)
        except ValueError as exc:
            raise ValueError("answer ISO is outside the managed runtime directory") from exc


class PostInstallFinalizationRuntime:
    """Crash-safe host runtime for the credential retirement boundary.

    The bootstrap account retirement is deliberately two phase. The intent is
    durably persisted as BOOTSTRAP_RETIRING before the final PowerShell Direct
    call. If the process dies after the guest disables the account but before
    BOOTSTRAP_RETIRED is persisted, future automatic runs must not reuse that
    credential. They stop for an external retirement proof (future Agent control
    path) instead.

    Media detach and local secret cleanup are host-side idempotent operations and
    can be retried safely after crash because both have exact managed targets and
    postcondition checks. Credential retirement and answer-media detach are both
    bound to the persisted canonical Hyper-V VMId; VM name is only a secondary
    consistency check and never the sole mutation authority.
    """

    def __init__(
        self,
        config: PostInstallFinalizationConfig,
        state_path: Path,
        secret_store: TextSecretStore,
    ) -> None:
        config.validate()
        self.config = config
        self.store = ProvisionStateStore(state_path)
        self.secret_store = secret_store

    def current(self) -> ProvisionRecord:
        record = self.store.load()
        if record is None:
            raise PostInstallStateError("provision state does not exist")
        if record.instance_id != self.config.instance_id:
            raise PostInstallStateError("provision state belongs to another instance")
        return record

    def retire_bootstrap(self, credential: PowerShellDirectCredential) -> ProvisionRecord:
        current = self.current()
        if current.state is not ProvisionState.AGENT_HEALTHY:
            raise PostInstallStateError(
                "bootstrap retirement requires AGENT_HEALTHY checkpoint"
            )

        self.store.transition_checked(
            instance_id=self.config.instance_id,
            expected_state=ProvisionState.AGENT_HEALTHY,
            state=ProvisionState.BOOTSTRAP_RETIRING,
            reason="final_credentialed_guest_action",
        )
        try:
            result = retire_bootstrap_guest(
                self.config.vm_id,
                self.config.vm_name,
                credential,
                self.config.bootstrap_username,
            )
        except Exception:
            # Preserve the retirement-intent checkpoint. Automatic retry is
            # intentionally forbidden because the guest account may already be
            # disabled even when the host did not receive the response.
            self.store.transition(
                instance_id=self.config.instance_id,
                state=ProvisionState.BOOTSTRAP_RETIRING,
                reason="retirement_result_unknown_requires_external_proof",
                last_error="bootstrap retirement result unknown",
            )
            raise

        if result.get("retired") is not True:
            self.store.transition(
                instance_id=self.config.instance_id,
                state=ProvisionState.BOOTSTRAP_RETIRING,
                reason="retirement_postcondition_not_proven",
                last_error="bootstrap retirement postcondition not proven",
            )
            raise PostInstallStateError("bootstrap retirement postcondition failed")

        return self.store.transition_checked(
            instance_id=self.config.instance_id,
            expected_state=ProvisionState.BOOTSTRAP_RETIRING,
            state=ProvisionState.BOOTSTRAP_RETIRED,
            reason="bootstrap_retirement_verified",
        )

    def record_external_retirement_proof(self) -> ProvisionRecord:
        """Advance a crash-interrupted retirement only after trusted proof.

        Tranche 5 will supply this proof through the authenticated Agent control
        path. This method deliberately performs no PowerShell Direct login.
        """
        return self.store.transition_checked(
            instance_id=self.config.instance_id,
            expected_state=ProvisionState.BOOTSTRAP_RETIRING,
            state=ProvisionState.BOOTSTRAP_RETIRED,
            reason="external_agent_retirement_proof",
        )

    def detach_answer_media(self) -> ProvisionRecord:
        current = self.current()
        if current.state is not ProvisionState.BOOTSTRAP_RETIRED:
            raise PostInstallStateError(
                "answer-media detach requires BOOTSTRAP_RETIRED checkpoint"
            )
        result = detach_answer_iso(
            self.config.vm_id,
            self.config.vm_name,
            self.config.answer_iso,
        )
        if result.get("detached") is not True:
            raise PostInstallStateError("answer-media detach postcondition failed")
        return self.store.transition_checked(
            instance_id=self.config.instance_id,
            expected_state=ProvisionState.BOOTSTRAP_RETIRED,
            state=ProvisionState.ANSWER_MEDIA_DETACHED,
            reason="managed_answer_media_detached",
        )

    def clear_transient_install_secrets(self) -> ProvisionRecord:
        current = self.current()
        if current.state is not ProvisionState.ANSWER_MEDIA_DETACHED:
            raise PostInstallStateError(
                "install-secret cleanup requires ANSWER_MEDIA_DETACHED checkpoint"
            )

        clear_install_secrets(
            self.config.answer_iso,
            self.secret_store,
            expected_sha256=self.config.answer_iso_sha256,
            runtime_dir=self.config.runtime_dir,
        )
        answer_authority = _require_answer_iso_authority(self.config.answer_iso)
        if answer_authority.exists():
            raise PostInstallStateError("managed answer ISO still exists after cleanup")

        try:
            self.secret_store.load_text()
        except FileNotFoundError:
            pass
        else:
            raise PostInstallStateError("bootstrap secret store still contains data")

        return self.store.transition_checked(
            instance_id=self.config.instance_id,
            expected_state=ProvisionState.ANSWER_MEDIA_DETACHED,
            state=ProvisionState.INSTALL_SECRETS_CLEARED,
            reason="transient_install_secrets_cleared",
        )

    def apply(
        self,
        action: str,
        *,
        credential: PowerShellDirectCredential | None = None,
    ) -> ProvisionRecord:
        if action == "RETIRE_BOOTSTRAP_ACCOUNT":
            if credential is None:
                raise ValueError("bootstrap credential is required for retirement")
            return self.retire_bootstrap(credential)
        if action == "DETACH_ANSWER_MEDIA":
            return self.detach_answer_media()
        if action == "CLEAR_INSTALL_SECRETS":
            return self.clear_transient_install_secrets()
        raise NotImplementedError(f"post-install action is not supported: {action}")
