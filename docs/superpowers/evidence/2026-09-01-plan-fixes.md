# Plan Fixes

## Task 3 file list

- Before: Task 3 listed only `tests/test_check_scope.py` under `Files`.
- After: The list also names the required red-test evidence file and the plan-fixes evidence file.
- Why: The execution brief requires both artifacts in this task commit. This is an unambiguous, local completeness correction and does not change the task intent or behavior.

## Task 5 file list

- Before: Task 5 listed only `tests/test_record_verdict.py` under `Files`.
- After: The list also names the required red-test evidence file and the plan-fixes evidence file.
- Why: The execution brief requires both artifacts in this task commit. This is an unambiguous, local completeness correction and does not change the task intent or behavior.

## Task 8 file list and RED expectation

- Before: Task 8 listed only `scripts/record_verdict.py` and `tests/test_record_verdict.py` under `Files`, despite requiring the Task 5 red-test evidence backfill and this plan-fixes entry. Its RED expectation named only `build_result`, although alphabetical `unittest` execution can encounter another missing helper first.
- After: The file list includes both evidence artifacts, and the RED expectation permits the required missing-helper `AttributeError` regardless of which helper executes first.
- Why: These are unambiguous local completeness and test-runner-order corrections. They preserve Task 8's accumulation behavior, refusal semantics, scope, and interfaces.

## Task 9 file list

- Before: Task 9 listed only `scripts/record_verdict.py` and `tests/test_record_verdict.py` under `Files`.
- After: The list also names the required red-test evidence file and the plan-fixes evidence file.
- Why: The execution brief requires both artifacts in this task commit. This is an unambiguous, local completeness correction and does not change the task intent, validation boundary, refusal behavior, partial-write guarantees, scope, or egress.

## Task 9 top-level object guard

- Before: Task 9's fallback-validator tests and prescribed body did not cover a
  non-object top-level instance. `_fallback_validate([], {"type": "object",
  "properties": {}}, "fixture")` therefore leaked `AttributeError` at
  `instance.items()` instead of raising `ValidationError`.
- After: The task adds a focused regression and an upfront `dict` guard that
  raises `ValidationError` before accessing object members.
- Why: This is an unambiguous local validation-boundary correction. It preserves
  the fallback's refusal behavior, scope, partial-write guarantees, and egress.

## Task 10 file list

- Before: Task 10 listed only `scripts/check_scope.py` and
  `policy/excluded-paths.yml` under `Files`.
- After: The list also names the required red-test evidence file and the
  plan-fixes evidence file.
- Why: The execution brief requires both artifacts in this task commit. This is
  an unambiguous, local completeness correction and does not change the task
  intent, platform-independent matching behavior, scope, independence,
  partial-write guarantees, or egress.

## Task 11 file list

- Before: Task 11 listed only `scripts/build_packet.py` and
  `tests/test_build_packet.py` under `Files`.
- After: The list also names the required red-test evidence file and the
  plan-fixes evidence file.
- Why: The execution brief requires the Task 3 green-commit backfill, Task 11
  RED evidence, and this plan-fixes entry in the task commit. This is an
  unambiguous, local completeness correction and does not change the task
  intent, identity behavior, scope ordering, independence, partial-write
  guarantees, or egress.

## Task 12 file list

- Before: Task 12 listed only `scripts/record_verdict.py`, `Makefile`, and
  `tests/test_record_verdict.py` under `Files`.
- After: The list also names the required red-test evidence file and the
  plan-fixes evidence file.
- Why: The execution brief requires the Task 11 green-commit backfill, Task 12
  RED evidence, and this plan-fixes entry in the task commit. This is an
  unambiguous, local completeness correction and does not change the task
  intent, independence behavior, refusal ordering, partial-write guarantees,
  scope, or egress.

## Task 1 temp-tree lifecycle warning found during Task 12

- Before: Task 1's `temp_tree` docstring explained fixture materialisation but
  did not say that `TemporaryDirectory` deletes the tree when the context exits.
- After: The docstring requires file-absence assertions to run inside the
  context and explains that captured values may still be asserted outside it.
- Why: An `assertFalse(path.exists())` after context teardown passes whether or
  not the code under test created the path, making a no-partial-write control
  vacuous. The warning is a local, unambiguous documentation correction to the
  existing test helper and prevents recurrence of the confirmed Task 12 test
  defect without changing production behavior.

## Task 4 fixture path discovered during Task 11

- Before: Task 4's SARIF fixture used `secrets/prod.env`, and its scope-ordering
  test asserted that path. The path was excluded only by the independent
  fixture policy.
- After: The fixture uses `config/server.pem` with rule
  `generic.secrets.private-key-detected` and message `Private key material`;
  the ordering test asserts the new path and explains the live-policy boundary.
- Why: Task 11's manual listing command uses the live policy, not the fixture
  policy. The `.pem` path is excluded under both, preserving fixture
  independence while making the manual scope-control verification meaningful.
