# Task 1 report: test infrastructure

## What changed

- Added the `tests` package bootstrap so standalone modules in `scripts/` are imported the same way as at runtime.
- Added shared fixture and temporary-tree helpers, including policy exclusion and scan-noise loaders.
- Added the independent basic policy fixture exercising comments, quoted values, a trailing-slash directory pattern, and both policy sections.
- Added four harness self-tests.
- Added the `make test` target and help entry using only the Python standard library.

## Verification commands and outputs

`make test`

```text
test_fixture_exclusions_load (tests.test_harness.TestHarness.test_fixture_exclusions_load) ... ok
test_fixture_policy_is_present (tests.test_harness.TestHarness.test_fixture_policy_is_present) ... ok
test_scripts_are_importable (tests.test_harness.TestHarness.test_scripts_are_importable) ... ok
test_temp_tree_materialises_files (tests.test_harness.TestHarness.test_temp_tree_materialises_files) ... ok

----------------------------------------------------------------------
Ran 4 tests in 0.003s

OK
```

`git diff HEAD^ HEAD --check` completed with no output (no whitespace errors).

## Files changed

- `Makefile`
- `tests/__init__.py`
- `tests/helpers.py`
- `tests/fixtures/policy-basic.yml`
- `tests/test_harness.py`
- `.superpowers/sdd/2026-09-01-appsec-review-hardening/task-1-report.md`

## Self-review

The committed implementation matches the task brief: the required public helper interfaces are present, `scripts/` is inserted on `sys.path`, the fixture is independent of the live policy, temporary trees clean up after the context exits, and the Make target supplies `-t .` for package discovery. The diff passed `git diff --check`, and the post-commit test run passed all four tests.

## TDD RED/GREEN evidence

This task creates test infrastructure and a Makefile/configuration entry rather than production behavior. TDD RED/GREEN is therefore not applicable to a production feature; the required harness verification is the four-test green run recorded above.

## Concerns

None. No dependencies were installed and no network access was used.

## Commit

`test: add stdlib test harness and policy fixture`
