# R002C — Hyper-V Reconciliation Contract

## Scope

This document defines the Tranche-2 host-side reconciliation contract for the Windows-first HMS-GPT-VPS product.

The managed guest is a Windows Hyper-V Generation-2 VM. ChatGPT/HMS control targets the guest agent only. Hyper-V lifecycle and Windows host elevation remain local desktop authority.

## Reconcile rule

Every mutable step follows:

`observe -> decide -> mutate -> observe again -> verify postcondition -> advance durable state`

Durable provisioning state MUST NOT move to the next phase merely because a PowerShell command was requested or returned exit code 0.

If the postcondition is missing or identity changed, the step fails closed and remains retryable.

## PowerShell safety

Generated PowerShell never interpolates unescaped user-controlled strings directly into executable syntax. VM names, paths, switch names, NAT names and identifiers pass through the single-quoted literal encoder in `powershell.ps_literal`.

The legacy `hyperv_executor` surface delegates to the hardened reconciler so there is one execution path.

## Managed network

Default managed network:

- vSwitch: `HMS-GPT-VPS-Internal`
- switch type: `Internal`
- NAT: `HMS-GPT-VPS-NAT`
- subnet: `172.29.240.0/24`
- host/gateway: `172.29.240.1`
- reserved first guest: `172.29.240.10`

The reconciler creates no NAT static mappings and opens no inbound guest management port.

A same-name vSwitch of another type or a same-name NAT with another prefix is a configuration conflict. The tool must not silently rewrite unrelated host networking.

The internal NAT is selected instead of an External vSwitch to avoid placing the AI-controlled guest directly on the physical LAN.

## VM identity

The first successful VM creation returns Hyper-V `VMId` and persists it in the instance registry.

Subsequent reconciles use both the expected VM name and persisted `VMId`. A same-name VM with a different identity, or an expected VMId bound to another name, is an identity conflict.

The tool must not silently adopt or overwrite a different VM.

## VM configuration

Current managed baseline:

- Hyper-V Generation 2;
- static startup memory;
- explicit vCPU count;
- dynamic VHDX;
- automatic checkpoints disabled;
- Secure Boot enabled with the Microsoft Windows template;
- one managed adapter attached to the dedicated internal switch;
- no implicit host-folder sharing.

Static reconciliation requires the VM to be Off. The reconciler never auto-stops a running VM because stopping a workload is a separate operator-visible action.

## Windows install media

Only a validated `.iso` source is accepted. When a SHA-256 is configured it must match before use.

The ISO attach step:

1. verifies the VM exists and is Off;
2. creates or reconciles the VM DVD drive;
3. attaches the intended ISO;
4. sets the DVD device as the Generation-2 first boot device;
5. re-observes the DVD path before advancing durable state.

Starting Windows Setup is deliberately outside the Tranche-2 runtime. Tranche 3 must first produce the complete unattended-install artifact/bootstrap path so the product does not accidentally boot into an interactive unmanaged installation.

## Observation contract

`hyperv_observe` is read-only and reports at minimum:

- dedicated network postcondition;
- observed VMId;
- VM state;
- VM adapter/switch binding;
- intended ISO attachment;
- Hyper-V heartbeat status.

When a persisted VMId is supplied, observation itself fails on identity mismatch.

## Registry contract

The instance registry persists:

- HMS instance ID;
- VM name;
- backend type;
- phase;
- workspace path;
- stable VMId;
- managed switch name;
- reserved guest IPv4.

Once a non-null VMId is persisted for an HMS instance, replacing it with a different non-null VMId is rejected unless a future explicit recovery/adoption workflow is invoked with operator approval.

## Security invariants

1. No External vSwitch by default.
2. No inbound NAT mapping by default.
3. No automatic VM stop/reset to make reconciliation easier.
4. No silent adoption of a different VM identity.
5. No unescaped PowerShell literals.
6. No progress advancement before read-after-write verification.
7. No Windows Setup start until unattended-install artifacts are ready.
8. No host filesystem sharing is required for the managed workflow.
9. Host Administrator operations remain outside the guest/ChatGPT control plane.

## Tranche-2 exit criteria

The code-level Tranche-2 gate requires:

- internal vSwitch/NAT reconciler;
- identity-bound VM reconciler;
- ISO/DVD boot-order reconciler;
- read-only Hyper-V observer;
- persistent VMId metadata;
- postcondition-based provisioning transitions;
- regression tests for the security invariants above.

A real-Hyper-V Windows integration run is still required before declaring the runtime implementation production PASS. Linux GitHub Actions can validate deterministic Python logic and generated PowerShell shape, but cannot prove Hyper-V host behavior.
