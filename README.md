# appsec-review

Human-driven security review workflow using an agentic coding tool as an analysis
assistant, with deterministic scanning as the detection layer.

**Mode: manual.** The engineer initiates every analysis. Nothing runs unattended,
nothing is triggered by repository events, and no agent holds repository write
access or CI credentials.

---

## What this is

A repeatable procedure, not a pipeline. It gives you:

- A deterministic scan producing SARIF (Semgrep). SCA and SBOM tools are
  optional and are run separately; `make scan` does not invoke them.
- A structured triage procedure where an agent explains and classifies a finding.
- A separate adversarial validation pass that tries to refute the verdict.
- A normalized verdict record in `findings/reviewed.sarif`, ready to import
  into a findings store. The DefectDojo importer is a placeholder; see Status.
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

make install SEMGREP_VERSION=1.2.3  # install deterministic tooling
make scan             # semgrep -> findings/raw.sarif
make triage N=0       # build a review packet for finding #0
```

`make triage` writes a self-contained packet to `findings/packets/`. You open the
agent, load `prompts/triage-finding.md` together with the packet, and get back a
verdict. Then:

```bash
make validate ID=F-abc123   # build the adversarial challenge packet
make record ID=F-abc123 AGENT=<triage model> VALIDATOR=<validation model> MINUTES=12
make decide ID=F-abc123 DECISION=accepted BY=appsec-oncall
make metrics                # how the programme is actually performing
```

`make record` refuses when `AGENT` and `VALIDATOR` name the same model. That is
the independence mechanism, not a preference — a second pass on the same model
inherits the same blind spots.

## Status

Working: scan, triage queue, packet builder, scope enforcement, verdict
recording, human decisions, metrics, tests.

**Not implemented.** These are placeholders and will tell you so when run:

- `goldenset/run_goldenset.py` — no regression cases are configured. Until they
  are, the graduation criterion that depends on them cannot be met; see
  `docs/07-graduation.md`.
- `scripts/import_defectdojo.py` — no DefectDojo credentials or import settings.
  Reviewed findings are in `findings/reviewed.sarif` and can be imported by hand.

## Tests

```bash
make test
```

Standard library only, no network, no scanner required. If it needs a
`pip install` to run, that is a bug.

## The triage queue

`make list` shows every finding. On a real repository that is hundreds, so it
filters:

```bash
make list LEVEL=error UNREVIEWED=1
make list RULE=injection LIMIT=20
make triage ID=F-abc123
```

Filters work on what the SARIF carries — scanner `level`, rule id, path. They
deliberately do not filter on policy severity or priority class: those are
assigned by the agent during triage and do not exist yet at listing time.

Indices shift when filters change, so use `ID=` for anything you want to
reproduce or put in a ticket.

## Layout

| Path | Contents |
|---|---|
| `CLAUDE.md` | Project context the agent reads at session start |
| `docs/` | Procedures, data handling, design decisions, controls, graduation |
| `prompts/` | The five review procedures, one file each |
| `policy/` | Excluded paths and severity policy. Both are enforced by scripts |
| `scripts/` | Scan, scope check, packet builder, verdict recorder, metrics |
| `rules/` | Local Semgrep rules. Empty by default; `make scan` refuses without them |
| `goldenset/` | Intended for regression cases. Placeholder, see Status |
| `templates/` | Verdict and challenge schemas, threat-model template |
| `findings/` | Local working directory. Git-ignored |

Documentation, in reading order:

| File | Read it when |
|---|---|
| `docs/02-setup.md` | Before the first run: accounts, retention, scanner pin |
| `docs/03-data-handling.md` | Before the first run: what leaves the perimeter |
| `docs/04-procedures.md` | Choosing which of the four procedures fits |
| `docs/05-design-decisions.md` | Changing a control, to see what you would undo |
| `docs/06-controls.md` | Auditing: what each control refuses and what proves it |
| `docs/07-graduation.md` | Deciding whether to keep going or automate |

The series starts at 02; there is no 01.

## Prerequisites

- Python 3.9+
- Semgrep at the version recorded in `docs/02-setup.md`
- Optional: Trivy or Grype, Syft, DefectDojo instance
- An agentic coding tool authenticated under commercial terms (see `docs/02-setup.md`)

## Known limitations

- Breaking audit-log change: `recorded_at` now follows `reviewed_at` in the
  CSV header. Writer-stamped UTC recording time controls revision ordering,
  decision supersession and `--since`; the model's `reviewed_at` is retained
  as self-reported history. Recorders refuse older headers. Archive the old
  `findings/` directory or retriage before recording with the new contract.
- Breaking challenge-schema change: every challenge must carry the exact
  16-hex `verdict_digest` from its challenge packet. Old challenges without
  the field are refused; a challenge for another revision is refused before
  writing. Rebuild the packet and rerun validation whenever the verdict changes.
- `findings/reviewed.sarif` accumulates and is never pruned. Over a long
  programme it grows without bound; rotate it yourself if that becomes a
  problem.
- `make check-template` fails in this repository on purpose: `CLAUDE.md` here is
  the template you copy and fill in per project. The check proves only that no
  template placeholders remain; it does not judge whether the replacement text
  meaningfully describes the project.
- A scanner upgrade can change finding ids. See `docs/02-setup.md`.

## License

Not yet chosen. The prompts, docs and scripts here are original work; nothing is
vendored from another project. Pick a license before anyone else depends on
this.
