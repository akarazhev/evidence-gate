# 2. Setup

Use this workflow from an organizational account approved for source-code review.
Do not use a personal account for restricted repositories.

## Tooling

Required:

- Python 3.9+
- Semgrep

Optional:

- Syft for SBOM generation
- Trivy or Grype for dependency scanning
- DefectDojo or another findings store

Install the required scanner:

```bash
make install
```

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
