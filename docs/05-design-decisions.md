# 5. Design decisions

Why the controls are shaped the way they are. Each entry records a decision that
still constrains the code, so that a future change knows what it would be
undoing. Decisions that turned out to be wrong are listed with what replaced
them, because the reasoning is the useful part.

The rule underneath all of them: **a control refuses; it does not warn.** A
warning printed to a terminal at 18:00 on a Friday is not a control.

---

## Model self-reports are not authoritative

The engineer supplies the triage and validation model identifiers on the command
line. `record_verdict.py` compares those, and a match is a refusal that writes
nothing at all.

The model also states its own identity in the verdict JSON. That value is kept,
under `agent_self_reported`, and controls nothing: a model asked what it is gives
an unreliable answer, and independence is the mechanism the whole two-pass design
rests on.

The same reasoning later forced a second decision. Revision ordering originally
used `reviewed_at`, which the model writes into its own verdict — so the writer
and the metrics could disagree about which revision was current. Ordering now
uses `recorded_at`, stamped by the recorder at write time. `reviewed_at` is
retained as history and decides nothing.

## Identity survives edits elsewhere in the file

A finding id is derived from the scanner's fingerprint when SARIF carries one,
and otherwise from the normalised text of the flagged region plus how many
identical regions precede it.

It deliberately does **not** include the line number. The previous scheme did,
so any edit above a finding re-keyed it: its verdicts were orphaned and every
dismissed finding came back on the next scan.

It deliberately **does** change when the flagged code changes. Changed code
deserves a fresh review.

The scheme is recorded per row as `id_scheme`, and the recorder refuses to mix
schemes in one log. A scanner upgrade can change fingerprints and therefore ids;
nothing can detect that automatically, which is why `docs/02-setup.md` asks for
the version in writing.

## A challenge refutes one revision, not a finding

Challenges bind to a `verdict_digest`, not to the finding id, because every
revision of a finding shares the id. Without the tighter binding an upheld
challenge for a true positive could be replayed to authorise superseding it with
a false positive — the opposite claim.

## Two row types, two merge rules

A verdict row **replaces** the verdict wholesale, empty fields included:
re-triaging without a challenge must not inherit the previous run's
`challenge_result`, or the log asserts a second pass that never ran.

A human-decision row **patches** the decision onto whichever verdict stands. A
verdict recorded after a decision invalidates it — the human accepted a different
state than the one now standing, and treating that as ground truth would
manufacture agreement.

## The human decision carries no schema, deliberately

The contracts in `templates/` are output contracts for a model, because model
output needs validating before it enters the findings store. A human decision is
typed at a terminal and is validated by argparse and an enum instead.

Do not add a schema for it out of symmetry. The distinction between "a model
asserted this" and "a person decided this" is what makes the accuracy metric mean
anything.

## Rates are withheld when their denominator is undefined

`metrics.py` reports counts as facts and derived shares only when there is
something to divide by. With nothing decided, coverage and accuracy print as *not
computed* rather than as a confident number.

The dismissal rate was once called the false-positive rate. It measures what the
pipeline did, not whether the pipeline was right; those are different quantities
and only the second answers whether the programme is worth continuing.

## Offline by default, network on purpose

`scan.sh` reads rules from a local `rules/` directory and refuses when it is
empty. Telemetry and the version check are disabled unconditionally.

Reaching the Semgrep registry is still supported through an explicit
`SEMGREP_CONFIG`, and prints a banner naming the egress before it happens. The
claim in `docs/03-data-handling.md` that there is one channel out of the
perimeter has to be true out of the box, not after configuration.

## Validate to the depth the consumer relies on

Every control bypass found during hardening had one shape: the check was
shallower than the use. A container was checked where the result mattered; a path
name where the opened file mattered; a parsed value where the supplied flag
mattered; a container type where the field the sort keys on mattered.

So a validator owes exactly what its consumer depends on. `check_log_compatible`
checks what `collapse()` reads — id, recording time, scheme, row type,
completeness, and the numeric fields the aggregates consume — because anything
less produces confident metrics from data the reader had to guess at.

## Refusals are strict on purpose

One malformed row blocks further recording until a human fixes it. One
unreadable existing SARIF blocks the merge. An empty policy is treated as a
disabled control rather than as permission.

The alternative in each case is to keep appending to a file we have already
stopped understanding.
