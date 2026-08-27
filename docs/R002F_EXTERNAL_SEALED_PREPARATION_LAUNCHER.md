# R002F external sealed preparation launcher remediation

Status: `STAGED_NOT_EXECUTED`.

The direct stage-0 candidate at commit `aacb9942154892a76481ab88c7ebb7f229bc583e` failed fresh committed-byte review. Two material boundaries were found before any Windows execution:

1. two closure booleans were not type-exactly checked, and the stage-0 proof did not independently bind all schema/root/no-execution fields from the sealed preflight proof;
2. raw `PreflightArgs` admitted `--flag=value` and argparse long-option-abbreviation forms that could bypass exact-string reserved-option filtering.

This descendant does not rewrite that commit. It introduces a smaller external launcher that is the only approved entry into that stage-0 child. The first launcher candidate at `5628d5bf42751c725d22b55d6787d2e98ec61c67` was also rejected during fresh committed-byte review because it had not independently sanitized host PowerShell search paths before cmdlet use and optional values could still begin with option syntax. This V2 closes both boundaries forward-only.

## Child authority

The launcher contains the reviewed stage-0 SHA-256 as a constant:

`3b14890a51b7d51aaac0105d1f3149a85c2c0e9b10208f25b4cc8f61130c787f`

It opens that exact direct-child file with `FileShare.Read`, verifies the hash before launch, keeps the handle alive across the child process, and verifies the same bytes after return.

The launcher exposes explicit optional preflight parameters only. There is no raw `ValueFromRemainingArguments` / `PreflightArgs` channel, and every optional forwarded value is rejected if it begins with an option prefix. Caller text therefore cannot replace fixed execution-root/manifest/runtime/proof/reviewed-commit authority by duplicate, equals-form, argparse abbreviation, or option-shaped value smuggling.

Before any child pinning or JSON cmdlet use, V2 derives System32 from `[Environment]::SystemDirectory`, replaces `PATH`, `PSModulePath`, `SystemRoot`, `windir`, `COMSPEC`, and `PATHEXT`, removes inherited `PYTHON*` / `GIT_*` controls, and uses .NET `File.GetAttributes` for reparse checks. Host search-path state is therefore not accepted as launcher execution authority.

## Independent post-child gate

After stage-0 returns with only exit 0 or 2, the launcher independently opens and pins both produced proofs. It requires the sealed preflight proof to bind:

- schema v1 and exact qualification;
- exact boolean ready/exit result;
- reviewed commit;
- repo-evidence root;
- execution/Python/Git roots;
- OS System32;
- all three externally supplied manifest SHA-256 values;
- exact boolean true for project/Python/Git closure proof;
- exact boolean false for `execution_started`, `hyperv_mutated`, `bridge_started`, and `tunnel_started`.

It then requires the stage-0 proof to bind the same reviewed commit, exact reviewed child SHA-256 before/after, actual preflight-proof SHA-256, exact external-pin boundary flags, and the same four false no-execution/no-mutation flags.

Only then can a create-only `R002F_EXTERNAL_SEALED_PREPARATION_LAUNCHER` proof be written.

## External root of trust

This launcher still cannot self-prove that its own expected SHA came from outside the process. The OS/deployment authority **must pin the launcher SHA-256 before process creation**, hold the exact opened launcher file against write/delete for the process lifetime, and invoke absolute OS Windows PowerShell.

Therefore the launcher proof deliberately keeps:

`external_launcher_preexecution_pin_self_proven=false`

No Hyper-V/HMSBridge/tunnel execution is authorized by this tranche. Real Windows execution remains a later gate.
