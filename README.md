# appsec-review

Human-driven security review workflow using an agentic coding tool as an analysis
assistant, with deterministic scanning as the detection layer.

**Mode: manual.** The engineer initiates every analysis. Nothing runs unattended,
nothing is triggered by repository events, and no agent holds repository write
access or CI credentials.

---

## What this is

A repeatable procedure, not a pipeline. It gives you:

- A deterministic scan producing SARIF (Semgrep, plus SCA and SBOM).
- A structured triage procedure where an agent explains and classifies a finding.
- A separate adversarial validation pass that tries to refute the verdict.
- A normalized verdict record that flows back into the same findings store as
  everything else.
- Metrics that tell you whether this is working before you commit to automating it.

## What this is not

- Not a CI integration. See `docs/07-graduation.md` for the criteria to move there.
- Not a guarantee of coverage. Nothing is reviewed unless a human asks for it.
- Not a replacement for the deterministic scanners. It sits on top of them.

## Why manual first

The agent never processes untrusted repository content (issue bodies, PR
descriptions, comments from external contributors), so the prompt-injection and
credential-exposure surface that affects event-triggered CI agents does not apply
here. The only channel out of the perimeter is what the engineer explicitly puts
in context, which is auditable and enforced by `scripts/check_scope.py`.

## Quick start

```bash
# 0. Read these first
#    docs/02-setup.md         - authentication, which account, what to verify
#    docs/03-data-handling.md - what leaves the perimeter and what must not

make install          # install deterministic tooling
make scan             # semgrep -> findings/raw.sarif
make triage N=0       # build a review packet for finding #0
```

`make triage` writes a self-contained packet to `findings/packets/`. You open the
agent, load `prompts/triage-finding.md` together with the packet, and get back a
verdict. Then:

```bash
make validate ID=<finding-id>   # build the adversarial challenge packet
make record ID=<finding-id>     # merge verdict + challenge into SARIF and the log
make metrics                    # how the program is actually performing
```

## Layout

| Path | Contents |
|---|---|
| `CLAUDE.md` | Project context the agent reads at session start |
| `docs/` | Procedures, data-handling rules, metrics, graduation criteria |
| `prompts/` | The five review procedures, one file each |
| `policy/` | Excluded paths and severity policy. Both are enforced by scripts |
| `scripts/` | Scan, scope check, packet builder, verdict recorder, metrics |
| `goldenset/` | Regression cases used to qualify any tool or model change |
| `templates/` | Verdict schema, triage log, threat model template |
| `findings/` | Local working directory. Git-ignored |

## Prerequisites

- Python 3.9+
- Semgrep (`pip install semgrep`)
- Optional: Trivy or Grype, Syft, DefectDojo instance
- An agentic coding tool authenticated under commercial terms (see `docs/02-setup.md`)

## License

Choose one before publishing. The prompts and docs here are original; the skill
packs referenced in `docs/02-setup.md` carry their own licenses (MIT, Apache 2.0,
CC-BY-SA) and are not vendored into this repository.
