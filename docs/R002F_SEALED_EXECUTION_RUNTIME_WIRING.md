# R002F sealed execution runtime wiring

Status: `STAGED_NOT_EXECUTED`.

This tranche wires the reviewed sealed project-tree substrate into the R002F preflight and one-shot coordinator without rewriting the existing coordinator.

## Authority split

Production qualification now separates:

- `repo_evidence_root`: mutable Git checkout used only by read-only preflight evidence;
- `execution_root`: complete reviewed project tree, exact manifest + protected read-only ACL;
- `python-runtime`: complete Python runtime closure, exact manifest + protected read-only ACL;
- `git-runtime`: complete Git runtime closure used only by preflight.

The live one-shot coordinator receives `execution_root` as its existing `repo_root`, so all imports and all child qualification scripts resolve from the sealed project tree.

## Runtime manifests

`SealedRuntimeManifest` supports `python-runtime` and `git-runtime`. It binds:

- exact file and directory namespace;
- exact path/casing;
- size and SHA-256 for every file;
- one canonical entrypoint;
- no reparse/symlink tree entries;
- exact manifest SHA-256 supplied externally.

The Git closure may not contain `powershell.exe`, `pwsh.exe`, `cmd.exe`, or `python.exe`; the bounded PATH therefore cannot shadow the OS/Python hosts with an approved Git package.

## OS process authority

ACL verification no longer resolves PowerShell through caller `PATH`. Runtime authority resolves Windows System32 through the OS and launches the absolute `System32\\WindowsPowerShell\\v1.0\\powershell.exe` host with a bounded environment.

Preflight child environment uses only:

`<sealed Git entrypoint directory>;<OS WindowsPowerShell\\v1.0>;<OS System32>`

Live one-shot child environment uses only:

`<OS WindowsPowerShell\\v1.0>;<OS System32>`

`SystemRoot`, `windir`, and `COMSPEC` are reconstructed from the OS System32 authority. Inherited `PYTHON*` and `GIT_*` controls are removed. Preflight reintroduces bounded Git controls that disable system/global configuration, fsmonitor, untracked cache, replacement objects, and optional locks.

## Sealed preflight

`preflight_r002f_sealed_one_shot_production_qualification.py` must run with the sealed Python interpreter under `-I -B` from the sealed project tree.

It:

1. proves project/Python/Git complete trees and exact read-only ACLs;
2. verifies its actual `sys.executable` equals the sealed Python entrypoint;
3. temporarily replaces the process environment with the bounded preflight environment;
4. runs the existing zero-manual component preflight against `repo_evidence_root`;
5. requires the observed checkout HEAD to equal the reviewed commit bound by the sealed project manifest;
6. discards the component's mutable checkout script path and `--repo-root`;
7. emits a replacement command that invokes the sealed one-shot script with sealed Python.

Bootstrap username/password must be absent during preflight.

## Sealed one-shot

`run_r002f_sealed_one_shot_production_qualification.py` validates project + Python closure, verifies `sys.executable`, and invokes the existing coordinator with:

- `repo_root=execution_root`;
- absolute sealed Python;
- PATH limited to OS WindowsPowerShell\\v1.0 + System32;
- a validator that re-proves project/Python authority at each existing coordinator checkpoint.

After the existing `06-one-shot-manifest.json`, it creates `07-sealed-execution-binding.json` binding that result to the reviewed commit and sealed project/Python manifest digests.

## Remaining external gate

This staged code does **not** self-prove the pre-import root of trust. An OS-trusted external preparation/launcher must still create/seal the project and toolchain roots and verify the externally approved manifest digests before sealed Python starts.

Therefore no Windows/Hyper-V execution is authorized yet and all higher-level ChatGPT/OAuth/full-flow/pairing proof flags remain unchanged until separate real proof exists.
