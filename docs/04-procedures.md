# 4. Procedures

Four scenarios. Each names its trigger, its cost, and what it produces. Run the
one that matches the situation; do not run the expensive one by default.

---

## Scenario 1 — Triage a scanner finding

**Trigger:** a scanner alert nobody has assessed.
**Cost:** 5–15 minutes.
**Frequency:** the bulk of the work. Most of the programme's value is here.

```bash
make scan REPO=../myapp
make list
make triage N=7                    # -> findings/packets/F-abc123.json
```

Open the agent. Load `prompts/triage-finding.md` and the packet. Save the JSON
response to `findings/verdicts/F-abc123.json`.

```bash
make validate ID=F-abc123          # builds the challenge packet
```

**New session. Different model.** Load `prompts/adversarial-validate.md` and the
challenge packet. Save to `findings/challenges/F-abc123.json`.

```bash
make record ID=F-abc123 MINUTES=12
```

Record the minutes honestly. Without them the programme has no primary success
metric and `metrics.py` cannot compute the number that justifies its existence.

**Why the second session matters.** Continuing in the same conversation gets you
agreement, not validation. The model has already committed to a position and will
mostly defend it. Independence is the mechanism; a second pass without it is
theatre.

---

## Scenario 2 — Deep audit of a module

**Trigger:** a release that materially changes a security-relevant component. Not
a schedule.
**Cost:** hours.
**Frequency:** rarely. Reserve it for genuine changes to the threat model.

Scope to **one module**. Never the whole repository: audit quality falls off a
cliff as scope grows, and a report covering everything gets read by nobody.

Load `prompts/module-audit.md` with the module path. The procedure runs recon,
then hunts by attack class, then adversarially reviews its own candidates before
reporting. Phase 3 is not optional; without it you receive the raw hunt output
and inherit the triage burden the exercise was meant to remove.

Findings come back as an array. Record each one:

```bash
for f in findings/verdicts/audit-*.json; do
  python3 scripts/record_verdict.py --verdict "$f"
done
```

The summary artifact matters as much as the findings. "Attack classes cleared,
and what was checked to clear them" is the part that tells you what you know.

---

## Scenario 3 — Threat model at design review

**Trigger:** a new feature or an architecture change, before the code is written
or while it is still cheap to change.
**Cost:** 30–60 minutes.
**Output:** a committed artifact, not a chat log.

Load `prompts/threat-model.md` with the design description, diagram, or prototype.
Commit the result to `docs/threat-models/<component>.md` using the template.

If the system contains a model, a retrieval pipeline, or an agent with tools, the
prompt adds the categories classical STRIDE does not cover: prompt injection
including the indirect variety, context and memory poisoning, unsafe tool use,
training and data supply chain, output handling into interpreters, and excessive
agency. Treat every tool the agent can call as a trust boundary and every
retrieval source as untrusted input.

Re-run when the architecture changes. Not per commit.

---

## Scenario 4 — Variant analysis after a confirmed finding

**Trigger:** a finding reaches `confirmed`, or an incident closes.
**Cost:** 20–40 minutes.
**Value:** the highest ratio in the set, and the most frequently skipped.

Load `prompts/variant-analysis.md` with the confirmed verdict. The procedure
abstracts the root cause, derives search patterns, searches the repository
including scripts and tooling, triages each hit, and proposes a structural fix.

The deliverable that matters is the **detection rule**. A variant analysis that
ends without one has fixed today's instances and left tomorrow's free to appear.
Add the rule to your Semgrep configuration and the class stops being able to
return silently.

Teams that skip this fix the single reported site and meet the same bug six
months later in a different file.

---

## When not to use the agent

- **Findings in excluded paths.** The builder refuses them. Review by hand.
- **Findings you already understand.** If you can classify it in thirty seconds,
  do. The overhead is not free.
- **Anything requiring runtime proof.** Memory-safety and race classes are parked
  in `awaiting_proof`. Static reasoning cannot close them regardless of how
  convincing it sounds, and treating a confident static argument as proof for
  these classes is precisely the failure this workflow is built to prevent.
- **Broad "find all the bugs" requests.** Unscoped requests produce unscoped
  output. Every procedure here is deliberately narrow.
