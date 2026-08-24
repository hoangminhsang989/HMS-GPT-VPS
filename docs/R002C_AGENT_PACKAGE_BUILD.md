# R002C Windows Agent package build

The production guest service artifact is `hms-agent.exe` built on a Windows x64 CI runner.

## Build authority

- Runtime dependencies stay separate from packaging dependencies.
- Packaging pins `PyInstaller==6.22.2` and `pyinstaller-hooks-contrib==2026.6`.
- The build uses the dedicated `scripts/hms_agent_entry.py` entrypoint and collects the HMS package submodules required by the lazily loaded Windows SCM path.
- The artifact remains a console-subsystem executable so `--version` can be used as a deterministic pre-install smoke check. A Windows service runs in Session 0, so this does not create an interactive desktop UI when SCM launches it.

## Required package evidence

CI may publish the Agent artifact only after all of the following pass:

1. Linux and Windows regression matrix on Python 3.11, 3.12 and 3.13.
2. The built executable runs `hms-agent.exe --version` successfully and reports the source package version.
3. The file is a Windows PE executable with AMD64 machine type `0x8664`.
4. `hms-agent.manifest.json` is canonical strict JSON containing schema version, filename, application version, byte size and SHA-256.
5. The just-written manifest is loaded back and the executable is re-verified against it.
6. PowerShell independently verifies manifest size and SHA-256 before the artifact is uploaded.

The manifest is non-secret. It is integrity metadata only and does not replace Authenticode signing or the later real-guest qualification gate.

## Not yet claimed by this gate

A successful package build does not prove that the executable can run as `NT AUTHORITY\\LocalService` with the `NT SERVICE\\HMSAgent` SID inside a managed Hyper-V guest. That remains a separate positive qualification gate covering SCM installation, native token proof, LocalMachine DPAPI credential access, loopback health, outbound HTTPS transport, command execution and restart/reconnect behavior.
