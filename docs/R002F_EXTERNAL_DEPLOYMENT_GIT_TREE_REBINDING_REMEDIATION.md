# R002F External Deployment Git-Tree Rebinding Remediation

Status: `STAGED_NOT_EXECUTED`.

This descendant supersedes the initial external deployment bundle preparation
candidate at commit `239405cbfff2891283af21d7ce080b521ed99851` for production
qualification use.

## Fresh review blocker

The initial preparation gate pinned and parsed the project manifest, required
its `reviewed_commit` text to equal the requested commit, and verified the
project source tree against the manifest. That was not sufficient to prove that
the manifest's internal `path -> Git blob SHA-1` mapping actually came from the
reviewed Git commit.

A syntactically valid manifest could therefore self-assert the correct commit
text while carrying a different blob mapping, and a source tree matching that
mapping would have passed the preparation gate. `repo_evidence_root` was placed
into the bundle but was not used by the preparation gate to independently
re-derive the reviewed Git tree.

The prior preparation verdict is therefore superseded for production use by
this remediation.

## Remediation authority

Bundle preparation now additionally requires:

- `--reviewed-git-executable <absolute-path>`
- `--reviewed-git-executable-sha256 <externally-approved-64-lowercase-hex>`

The Git digest is an external deployment/review authority. It is not discovered
or promoted from the local machine.

Before project source verification or bundle publication, preparation now:

1. pins/parses the exact canonical project manifest bytes;
2. requires the manifest's reviewed commit to equal the requested commit;
3. requires `repo_evidence_root` to be an exact clean checkout of that commit
   using the existing reviewed checkout authority;
4. pins the exact externally-approved Git executable;
5. runs absolute-path `git ls-tree -r -z --full-tree <reviewed-commit>` with
   Git-control environment sanitization and replacement objects disabled;
6. accepts only regular Git blob modes `100644` and `100755`;
7. rejects symlink/gitlink modes, unsupported object types, invalid/unsafe
   Windows paths, control characters, duplicate/case-colliding paths and
   malformed tree output;
8. revalidates the reviewed clean checkout after tree collection;
9. requires the exact manifest `path -> git_blob_sha1` mapping to equal the
   independently derived reviewed Git tree;
10. only then verifies concrete project source bytes against that same in-memory
    manifest and continues Python/Git runtime closure verification and bundle
    publication.

The Git-tree rebind uses the same in-memory manifest object and canonical bytes
that are later hashed into the bundle. No manifest re-read occurs between the
Git-tree comparison and source-tree verification, so replacement of the
manifest path cannot switch the mapping used for bundle publication.

## Fail-closed boundary

Preparation now fails before bundle publication if:

- reviewed Git executable path/hash authority is invalid;
- reviewed checkout HEAD/clean/index authority fails;
- Git tree collection fails;
- Git tree output is malformed, over-broad, non-regular, unsafe or
  case-colliding;
- project manifest commit text differs;
- project manifest blob mapping differs from the exact reviewed commit tree;
- project source differs from the now-rebound manifest;
- any prior launcher/stage-0/runtime/create-only gate fails.

Bootstrap secret environment variables remain forbidden during preparation.
No secret value is logged or added to the bundle.

## Updated invocation

The existing preparation CLI now additionally requires the exact reviewed Git
binary authority:

```powershell
python scripts/prepare_r002f_external_deployment_bundle.py `
  --reviewed-commit <40-lowercase-hex> `
  --repo-evidence-root <exact-clean-reviewed-checkout> `
  --reviewed-git-executable <absolute-git.exe> `
  --reviewed-git-executable-sha256 <externally-approved-sha256> `
  <remaining existing preparation arguments>
```

After successful create-only bundle publication, the bundle SHA-256 still must
be recorded/pinned through the external deployment procedure before the
existing renderer/OS-trusted launcher command is used.

## Proof boundary

This remediation is still preparation-only and `STAGED_NOT_EXECUTED`.
It does not start the launcher, Hyper-V, HMSBridge, HMSAgent or the tunnel and
does not prove any live production or ChatGPT/OAuth fact.

The following remain false until separate real execution evidence exists:

- `hyperv_guest_proven`
- `live_managed_guest_tls_proven`
- `authenticated_agent_transport_proven`
- `openai_control_plane_origin_proven`
- `full_bridge_command_flow_proven`
- `bootstrap_retired`
- `pairing_ready`
- `chatgpt_ui_origin_proven`
- ChatGPT OAuth/private-key-jwt proof flags.
