# R002C — Windows Unattended Install Contract

## Scope

This document defines the Tranche-3 Windows guest installation foundation for HMS-GPT-VPS.

The physical Windows host remains outside ChatGPT/HMS guest-control authority. The Windows guest is a dedicated Hyper-V Generation-2 VM owned by the local HMS desktop provisioner.

## Media strategy

HMS-GPT-VPS does not modify or redistribute the operator's Windows product ISO.

The installation bundle contains two independent CD/DVD images:

1. **Windows product ISO** — supplied by the operator from a lawful Microsoft/licensed source and optionally pinned by SHA-256.
2. **Transient answer ISO** — generated locally by HMS-GPT-VPS and containing `Autounattend.xml` at the root.

The Windows product ISO is the first boot device. The answer ISO is a secondary removable-media source that Windows Setup can discover automatically.

The answer-media ISO is generated using the pure-Python `pycdlib` package, reopened and byte-verified before atomic publication.

## Windows 11 VM baseline

Before Windows Setup may start, the VM must satisfy the managed baseline:

- Hyper-V Generation 2;
- Secure Boot enabled with `MicrosoftWindows` template;
- virtual TPM enabled using a local VM key protector;
- at least the project-configured CPU/RAM/disk minimums;
- dedicated Internal Hyper-V network rather than an External vSwitch;
- no implicit host-drive sharing.

## Destructive disk gate

The full answer file intentionally uses `WillWipeDisk=true` for the guest installation target. Therefore it is never emitted without an explicit internal acknowledgement that the target is the dedicated blank guest disk created for this HMS VM.

Immediately before `Start-VM`, the host-side gate verifies:

1. VM exists and is Off;
2. VM has exactly one hard disk;
3. that hard disk path equals the provisioner's managed VHDX path;
4. the intended Windows product ISO is attached;
5. the intended answer ISO is attached;
6. Secure Boot is On;
7. virtual TPM is enabled.

Any mismatch blocks the install. The provisioner never auto-stops/reset a running VM to make this gate pass.

## GPT partition layout

Current MVP unattended layout on guest Disk 0:

- EFI System Partition: **300 MB**, FAT32;
- Microsoft Reserved Partition: **16 MB**;
- Windows primary partition: remaining disk space, NTFS, drive `C:`.

The MVP does not create a custom recovery-tools partition. Recovery-layout optimization can be added later after the first reproducible end-to-end VM pipeline is stable.

## Windows edition selection

The answer file selects the image using `/IMAGE/INDEX`.

The operator/tool must validate that the configured image index matches the intended Windows edition in the supplied ISO before a production release. HMS-GPT-VPS does not inject a Windows product key and does not bypass Windows licensing or activation.

## Temporary bootstrap account

PowerShell Direct requires a valid credential inside the guest. The unattended installation therefore creates a **temporary local Administrator bootstrap account** solely for post-install provisioning.

Rules:

- username is managed by the provisioner;
- password is generated at runtime using a cryptographically secure RNG;
- password is at least 20 characters; current default is 32;
- password fields are redacted from Python dataclass `repr()`;
- the password is never committed to Git;
- the password is never placed in normal audit/events;
- the password is never used as HMS pairing/session credential;
- AutoLogon is limited to one logon;
- after HMS Agent bootstrap succeeds, the temporary Administrator account must be disabled/removed and any AutoLogon residue removed.

## Secret artifact lifecycle

The generated full `Autounattend.xml` necessarily contains the temporary bootstrap password in plaintext because Windows Setup consumes it as installation configuration. Therefore both the XML content and generated answer ISO are classified as **transient secret artifacts**.

Lifecycle:

1. generate runtime bootstrap credential;
2. protect the resume copy with current-user Windows DPAPI;
3. generate full unattend XML in memory;
4. build `hms-answer.iso` in protected runtime storage;
5. record only non-secret metadata such as SHA-256, size and username;
6. verify answer ISO SHA-256 again before attaching/starting Setup;
7. use the DPAPI-protected credential for PowerShell Direct bootstrap;
8. after bootstrap/agent health is proven, detach the answer ISO;
9. delete the known answer ISO artifact;
10. clear the DPAPI secret store;
11. disable/remove the temporary bootstrap Administrator account.

No cleanup step may delete arbitrary paths; only exact managed artifact paths are eligible.

## DPAPI contract

Short-lived host-side bootstrap credential recovery uses Windows DPAPI in current-user scope with UI forbidden.

This prevents the provisioning state JSON/registry from carrying a reusable plaintext password. DPAPI native output buffers are released through `LocalFree` using pointer-sized `void*` handling for Windows x64 safety.

DPAPI is a Windows-only runtime dependency. Cross-platform CI verifies that non-Windows use fails explicitly; native encrypt/decrypt round-trip belongs in the Windows test lane.

## Install bundle reconciliation

Media reconciliation is fail-closed:

- attach the Windows ISO if absent;
- attach the answer ISO if absent;
- refuse to silently replace an unrelated/operator-owned DVD image;
- set Windows product ISO as first boot device;
- read back both attachments and boot order before durable state advances.

The provisioner uses a read-only install-bundle observer so application restart/resume does not depend on mutation results left in memory.

## Installation start

`START_UNATTENDED_INSTALL` is executed only after:

- Windows product ISO validation succeeds;
- answer ISO exists and matches the recorded SHA-256;
- install-bundle observer reports both media attached and correct boot order;
- Hyper-V observer reports Secure Boot + vTPM ready;
- destructive VHD target gate succeeds.

After `Start-VM`, the runtime observes that the VM entered `Running` state before durable state advances to OS installation.

## Network during Setup

The default Hyper-V network is an Internal vSwitch with host NAT. Hyper-V NAT does not provide DHCP by itself.

The initial unattended installation must not depend on inbound management ports. Static guest IPv4 configuration and outbound DNS/gateway setup are completed during guest bootstrap through PowerShell Direct or an equivalent local-only channel.

## Post-install bootstrap target

After Windows finishes installation and Hyper-V guest readiness is observed:

1. load the DPAPI-protected temporary bootstrap credential;
2. connect using PowerShell Direct;
3. ensure a guest user profile exists/PowerShell Direct is usable;
4. configure managed static guest IP, gateway and DNS;
5. create `C:\HMS-Workspace`;
6. apply NTFS ACLs;
7. install HMS Agent as a Windows Service with least privilege;
8. verify Agent health/capabilities;
9. remove temporary bootstrap privilege/credential artifacts;
10. detach/delete answer media and clear the DPAPI store.

## Security invariants

1. No product key or activation bypass is embedded.
2. No HMS pairing token is embedded in unattend media.
3. No reusable Agent credential is embedded in unattend media.
4. `WillWipeDisk` is allowed only for the dedicated managed guest disk.
5. VM identity remains pinned by Hyper-V VMId.
6. Secure Boot + vTPM are required before Windows 11 Setup starts.
7. Unknown DVD media is not silently replaced.
8. Answer media integrity is rechecked immediately before Setup.
9. Host drives are not shared to perform installation/bootstrap.
10. ChatGPT does not receive the temporary Administrator password.
11. ChatGPT does not receive Hyper-V host control.
12. Durable provisioning state advances only after observed postconditions.

## Verification status

The deterministic Python logic, XML generation, ISO generation/readback, script shape and security gates can run in normal GitHub CI.

A real Windows Hyper-V integration run is still mandatory before runtime PASS. That run must prove, at minimum:

- vTPM creation on the target Windows edition;
- Internal vSwitch/NAT reconciliation;
- exact VM/VHD identity checks;
- dual-DVD media attach and boot order;
- Windows Setup actually consumes the generated `Autounattend.xml`;
- reboot/install convergence;
- PowerShell Direct credential/bootstrap path;
- DPAPI native round trip;
- cleanup of answer media/bootstrap Administrator without affecting unrelated host/guest data.
