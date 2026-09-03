# Local Semgrep rules

`scan.sh` reads rules from this directory by default. It is empty on purpose:
a rule set is specific to the languages and frameworks of the repository under
review, and shipping someone else's is worse than shipping none.

Populate it with `.yaml` rule files before the first scan.

To use the Semgrep registry instead, opt in explicitly:

    SEMGREP_CONFIG=p/security-audit make scan REPO=../myapp

That reaches the network, which is a second channel out of the perimeter.
`docs/03-data-handling.md` explains what that means and when it is acceptable.
