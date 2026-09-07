# 2. Setup

Use this workflow from an organizational account approved for source-code review.
Do not use a personal account for restricted repositories.

## Tooling

Required:

- Python 3.9+
- Semgrep, at a pinned version (see below)

Optional:

- Syft for SBOM generation
- Trivy or Grype for dependency scanning
- DefectDojo or another findings store

Install the required scanner:

```bash
make install SEMGREP_VERSION=1.2.3
```

### Pin the scanner version

Semgrep's fingerprints feed finding identity: the packet builder prefers
`partialFingerprints` over file content when deriving a finding id. An upgrade
can change those fingerprints, which re-keys every finding, which orphans its
verdicts and resurrects everything previously dismissed.

So the version is pinned, and `make install` refuses without one:

    make install SEMGREP_VERSION=1.2.3

Record the version in use here, before the first scan:

**Scanner version:** `<fill in>`

Treat an upgrade the way you would an identity-scheme change: archive
`findings/` and re-triage. `record_verdict.py` refuses to mix identity schemes
in one log, but it cannot detect a scanner upgrade for you. That one is on the
engineer, which is why the version is written down rather than inferred.

## Account checks

Before the first review, confirm:

- The agentic coding tool is authenticated under commercial terms.
- Prompt and response retention settings match the repository's data policy.
- Training on submitted content is disabled where the provider supports it.
- The reviewer understands that processing residency is separate from retention.

If residency is mandatory, use the local-model workflow described in
`docs/03-data-handling.md`.

## Repository setup

Review and edit these files for the target repository:

- `CLAUDE.md`
- `policy/excluded-paths.yml`
- `policy/severity-policy.yml`

Then run:

```bash
make check-scope
```

The exclusion list is not advisory. Packet generation refuses excluded paths.
