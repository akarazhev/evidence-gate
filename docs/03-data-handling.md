# 3. Data handling

Read this before first use. It defines the only channel through which code leaves
the perimeter, and the controls on it.

---

## The one channel

In manual mode there is exactly one path out: **the review packet an engineer
builds and submits.** No webhook, no scheduled job, no repository event, no agent
with credentials.

That single channel is what makes this mode auditable. Everything below exists to
keep it single.

## What a packet contains

| Included | Not included |
|---|---|
| Scanner finding metadata (rule, message, severity) | Whole files, unless the window covers them |
| A window of source around the flagged lines (default ±40) | Any file matching `policy/excluded-paths.yml` |
| Small snippets at each dataflow step (±12 lines) | Repository history, branches, remotes |
| Relative file paths and line numbers | Environment variables, credentials, tokens |
| Instructions and the procedure reference | Build artifacts, dependency trees, SBOM contents |

Inspect any packet directly. It is plain JSON:

```bash
python3 -m json.tool findings/packets/F-abc123.json | less
```

## Enforcement, not guidance

`scripts/check_scope.py` runs **before any file content is read**. The ordering is
the control. A finding touching an excluded path is refused with exit code 2 and
no source is opened:

```
REFUSED: finding touches an excluded path.
  path:    .env
  pattern: **/.env
  reason:  Runtime secrets
This finding must be reviewed without agent assistance.
```

The check is dependency-free by design. It parses the policy file itself rather
than importing a YAML library, so a missing package cannot silently disable it.

It also covers every file in the scanner's dataflow trace, not just the flagged
location. A taint path passing through an excluded module refuses the whole
packet.

The agent is separately instructed in `CLAUDE.md` to stop if a flow enters an
excluded path and to record it in `blocked_by_scope`. That instruction is a
second layer. It is not the control; the packet builder is. Never rely on an
instruction where you can rely on a refusal.

## Widening context safely

When the agent asks for an additional file, do not paste it. Scope-check first:

```bash
python3 scripts/check_scope.py src/middleware/auth.py && sed -n '1,120p' src/middleware/auth.py
```

The `&&` matters: the file is only printed if the check passes.

Prefer narrow context anyway. A whole repository in context degrades reasoning
about a specific finding as well as widening exposure. Narrow is both safer and
better.

## Residency and retention are different questions

**Retention** — how long a provider stores prompts and responses, and whether
they train on them. Addressable through account tier and contractual terms. See
`docs/02-setup.md`.

**Residency** — where processing physically occurs. Not addressable by any
setting on a hosted service.

If your requirement is residency, this workflow does not satisfy it on restricted
code, and no amount of retention configuration changes that. Use the fully local
configuration below.

## Fully local configuration

When any external processing is unacceptable:

```
Semgrep CE ──┐
             ├──► ai-deep-sast (local model, fast scan) ──► SARIF ──► DefectDojo
Trivy/Grype ─┤
Syft (SBOM) ─┘
```

The packet builder, scope check, verdict schema, promotion policy, metrics and
golden set in this repository all work unchanged against a locally hosted model.
Only the model endpoint changes. What you lose is reasoning depth; what you keep
is the entire discipline, which is most of the value.

A hybrid is also viable: local model for the broad pass, hosted model only for
findings above a severity threshold in modules outside the restricted list. The
restricted list is `excluded-paths.yml`, already enforced.

## Committing artifacts

`.gitignore` excludes `findings/packets/` because packets contain source
excerpts.

Verdicts, challenges, and `triage-log.csv` **are** committed. They are the audit
trail, and an audit trail nobody can find is not one. If your verdicts quote
sensitive source in the `reasoning` field, either redact before committing or
move `findings/` to a private store and keep only aggregate metrics in the public
repository.

## Pre-flight checklist

Before the first real review:

- [ ] Agent authenticated with an organizational account, verified not personal
- [ ] `excluded-paths.yml` reflects this project, every entry owned and explained
- [ ] `make check-scope` output reviewed by whoever owns the restrictions
- [ ] One packet inspected by hand, end to end
- [ ] A deliberate refusal tested: point the builder at an excluded path and
      confirm exit code 2
- [ ] Workstation transcript caching considered against your requirements
- [ ] Residency requirement confirmed as not applicable, or the local path chosen
