# 1. Getting started

From an empty checkout to the first real review. Roughly two person-days, none of
it programming.

The order matters. Step 0 can end the exercise, and it is the cheapest step to
run, so it goes first.

---

## Step 0 — Confirm two different models are available

**One hour. Do this before anything else.**

`make record` refuses when `AGENT` and `VALIDATOR` name the same model, and
findings of medium severity or higher never leave `blocked_needs_challenge`
without a challenge. With one model the pilot stalls on its first real finding,
and no configuration changes that — it is the design.

**Verify:** open two sessions on genuinely different models, hand each one a JSON
packet, and get JSON back from both.

If you cannot, stop here. This is an organisational decision, not a technical
one, and everything downstream depends on it.

## Step 1 — Choose the pilot service

**Fifteen minutes.**

One service, not the whole organisation. Pick the smallest one whose security
actually matters. Clone this repository next to it; you will run every command
from here with `REPO=../target`.

## Step 2 — Pin the scanner version

**Thirty minutes.**

```bash
make install SEMGREP_VERSION=1.107.0    # substitute the current stable release
```

Record the version in `docs/02-setup.md`, where it says
`**Scanner version:** <fill in>`.

**Verify:** `semgrep --version` matches what you wrote down.

Scanner fingerprints feed finding identity. An upgrade can re-key every finding,
orphaning its verdicts and resurrecting everything previously dismissed. Nothing
detects that for you, which is why the version is written down rather than
inferred.

## Step 3 — Build the rule set

**About a day. AppSec engineer.**

`rules/` ships empty and `make scan` refuses without it. That is deliberate:
somebody else's rule set is worse than none, because it produces findings nobody
can act on.

Reconnaissance first, to see what a stock pack would say:

```bash
SEMGREP_CONFIG=p/security-audit make scan REPO=../target
make list
```

Then curate. Keep what is relevant to this service's languages and frameworks;
drop the noise now rather than later. Noise is more expensive than a missed rule,
because it destroys trust in the queue and the queue is the whole workflow.

**Verify:** `make scan REPO=../target` succeeds without `SEMGREP_CONFIG`, and
`make list` returns a number a person could work through.

## Step 4 — Fill in CLAUDE.md

**Half a day. Needs whoever owns the service architecture.**

Eight placeholders remain in the shipped template. `make check-template` prints
the current list with line numbers, which is the authoritative version; they
cover:

- attacker-controlled entry points
- authenticated but untrusted input
- trusted input
- security-critical modules requiring extra scrutiny
- one accepted pattern, with its date, reason and ticket

Write entry points concretely — `app/routes/api.py:handle_upload`, not "HTTP
handlers". Whether the word `traced` in a verdict means anything depends on this
file being specific.

**Verify:** `make check-template` exits 0. Then have a person read the result.
The check proves only that no placeholders remain; it cannot judge whether the
replacement text describes your system.

## Step 5 — Review the exclusion policy

**Thirty minutes.**

Ten defaults ship in `policy/excluded-paths.yml`: dotenv files, key material,
`secrets/`, `.git/`, and the packet directory. Add what is specific to this
service — config directories holding credentials, fixtures containing real data,
vendored trees.

Every entry needs an `owner` and a `reason`. The parser refuses without them.

**Verify:**

```bash
make check-scope                       # does the list say what you expect?
python3 scripts/check_scope.py .env    # a deliberate refusal: expect exit 2
```

## Step 6 — Set the pilot thresholds

**Thirty minutes. Programme owner.**

`docs/07-graduation.md` carries `<coverage threshold>` and
`<accuracy threshold>` under "Pilot exit criteria". Fill both in **before** the
pilot starts.

Choosing them once the numbers arrive is not measurement; it is fitting the
criteria to the result.

## Step 7 — Take one finding end to end

**One hour.**

```bash
make scan REPO=../target
make list LEVEL=error
make triage ID=F-abc123

python3 -m json.tool findings/packets/F-abc123.json | less   # read it yourself
```

Hand the packet and `prompts/triage-finding.md` to model A. Save the response to
`findings/verdicts/F-abc123.json`.

```bash
make validate ID=F-abc123
```

**A fresh session on model B.** Hand it the challenge packet and
`prompts/adversarial-validate.md`. Save to `findings/challenges/F-abc123.json`.

```bash
make record ID=F-abc123 AGENT=<model A> VALIDATOR=<model B> MINUTES=12
make decide ID=F-abc123 DECISION=accepted BY=appsec-oncall
make metrics
```

Also test a refusal on purpose: point the packet builder at an excluded path and
confirm it exits 2 without writing a packet.

**Verify:** `make metrics` reports one finding carrying a human decision.

## Step 8 — Run the pilot

Record minutes honestly, every time. Without them metric 1 cannot be computed,
and metric 1 is the number that justifies the programme's existence.

Aim for twenty to thirty decided findings before drawing conclusions. Below
that, agent accuracy is a number without a meaning.

---

## What usually goes wrong

In descending order of likelihood:

**The second model never materialises.** Which is why Step 0 is first and costs
an hour rather than a week.

**The rule set produces hundreds of findings** and the queue becomes
unworkable. The fix is tighter rules, not more patience. `make list
UNREVIEWED=1 LEVEL=error` narrows the queue, but it does not fix a rule set that
was never curated.

**Minutes stop being recorded** after the first week, and the pilot ends without
its primary number. Nothing in the tooling can compel this; it is a discipline
that has to be agreed before starting.
