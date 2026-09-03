# appsec-review Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Закрыть разрыв между тем, что документация репозитория утверждает, и тем, что код обеспечивает, и довести проект до состояния, пригодного для пилота на реальном репозитории.

**Architecture:** Семь слоёв, строго по порядку. Слой 0 создаёт тестовую инфраструктуру и фиксирует текущее поведение — часть его тестов намеренно красные, они ведут правки слоя 1. Слои 1–3 чинят корректность, независимость и egress. Слои 4–5 добавляют очередь триажа и запись решения человека. Слой 6 приводит документацию в соответствие с уже работающим кодом.

**Tech Stack:** Python 3.9+, только стандартная библиотека. `unittest` для тестов. `jsonschema` остаётся опциональной зависимостью. POSIX sh для `scan.sh`. GNU make.

**Spec:** `docs/superpowers/specs/2026-09-01-appsec-review-hardening-design.md`

## Global Constraints

- **Язык артефактов:** весь код, комментарии, docstring-и, сообщения об ошибках, README и содержимое `docs/` — на английском. Настоящий план и спека — на русском.
- **Никаких новых зависимостей.** `make test` обязан работать на голом Python 3.9+ без единого `pip install`. `jsonschema` остаётся опциональной.
- **Никакой сети в тестах.** Ни один тест не обращается к сети и не требует установленного `semgrep`.
- **Python 3.9 floor.** `from __future__ import annotations` уже стоит во всех скриптах — сохранять при правках; синтаксис `X | None` в аннотациях допустим только благодаря ему.
- **Аудит-трейл append-only.** `findings/triage-log.csv` никогда не переписывается и не редактируется задним числом. Актуальное состояние отражает `findings/reviewed.sarif`.
- **Контроль — это отказ, а не предупреждение.** Любая проверка, названная контролем, завершается ненулевым кодом возврата и не пишет частичный результат.
- **Стиль коммитов:** `<type>: <imperative summary>` на английском, типы `test`, `fix`, `feat`, `docs`, `refactor`.

---

## File Structure

**Создаются:**

| Путь | Ответственность |
|---|---|
| `tests/__init__.py` | Делает `tests` пакетом и кладёт `scripts/` в `sys.path` |
| `tests/helpers.py` | Общие помощники: фикстуры, временные деревья файлов |
| `tests/fixtures/policy-basic.yml` | Политика исключений для тестов, независимая от боевой |
| `tests/fixtures/sample.sarif` | SARIF с несколькими находками, включая `codeFlows` |
| `tests/test_check_scope.py` | Парсинг политики и матчинг путей |
| `tests/test_build_packet.py` | Идентичность находок, порядок scope-check, фильтры очереди |
| `tests/test_record_verdict.py` | Консистентность, продвижение, SARIF, валидатор |
| `tests/test_metrics.py` | Агрегация лога |
| `tests/test_scan_sh.py` | Путь отказа `scan.sh` без semgrep |
| `tests/test_human_decision.py` | Запись решения человека |
| `scripts/record_human_decision.py` | Запись решения человека, ground truth программы |
| `rules/README.md` | Как заполнить локальный набор правил |
| `templates/threat-model.md` | Шаблон, на который уже ссылаются README и `docs/04` |

**Модифицируются:**

| Путь | Что меняется |
|---|---|
| `scripts/check_scope.py` | Регистронезависимый матчинг (§1.4) |
| `scripts/build_packet.py` | Параметр `exclusions`, стабильный `finding_id`, фильтры `--list`, адресация по id |
| `scripts/record_verdict.py` | Честный rationale, накопление SARIF, валидатор, независимость, миграция лога, `--supersede` |
| `scripts/metrics.py` | Схлопывание по `finding_id`, переименование величины, блок точности |
| `scripts/scan.sh` | Офлайн по умолчанию, `--metrics=off` |
| `policy/excluded-paths.yml` | Паттерн `**/.envrc` |
| `templates/verdict.schema.json`, `templates/challenge.schema.json` | Описания полей `agent` |
| `Makefile` | Цели `test`, `check-template`, переменные `AGENT`, `VALIDATOR`, `ID`, фильтры |
| `README.md`, `docs/03-data-handling.md`, `docs/04-procedures.md`, `docs/07-graduation.md`, `CLAUDE.md` | Слой 6 |

---

# Слой 0 — тестовая инфраструктура

Слой 0 покрывает только существующий код. Тесты на новую функциональность слоёв 4 и 5 пишутся внутри этих слоёв.

Часть тестов здесь **намеренно красная**: они написаны против желаемого поведения и станут зелёными в слое 1. Не использовать `unittest.expectedFailure` — после правки такой тест даёт unexpected success и требует переделки. Сохраняйте вывод упавшего прогона: он является доказательством, что дефект реален.

### Task 1: Тестовая инфраструктура

**Files:**
- Create: `tests/__init__.py`
- Create: `tests/helpers.py`
- Create: `tests/fixtures/policy-basic.yml`
- Create: `tests/test_harness.py`
- Modify: `Makefile`

**Interfaces:**
- Consumes: ничего.
- Produces: `tests.helpers.REPO_ROOT: Path`, `tests.helpers.FIXTURES: Path`, `tests.helpers.fixture_exclusions(name: str) -> list[dict]`, `tests.helpers.temp_tree(files: dict[str, str]) -> ContextManager[Path]`. Все последующие задачи импортируют отсюда.

- [ ] **Step 1: Создать пакет тестов с bootstrap путей**

`scripts/` не является пакетом, а `build_packet.py` импортирует `check_scope` как модуль верхнего уровня. Тесты обязаны воспроизвести это, иначе импорты разойдутся.

`tests/__init__.py`:

```python
"""Test package for appsec-review.

`scripts/` is a directory of standalone tools, not an importable package:
`build_packet.py` reaches `check_scope` by putting its own directory on
sys.path. Tests must reproduce that layout or the imports diverge from what
the tools actually do at runtime.
"""

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
_SCRIPTS = str(REPO_ROOT / "scripts")
if _SCRIPTS not in sys.path:
    sys.path.insert(0, _SCRIPTS)
```

- [ ] **Step 2: Написать помощники**

`tests/helpers.py`:

```python
"""Shared test helpers.

Fixtures live under tests/fixtures/ rather than reusing policy/ from the
repository root. A test suite that reads the live policy file breaks every
time the policy is edited, and a suite that breaks on unrelated edits stops
being run.
"""

from __future__ import annotations

import contextlib
import tempfile
from pathlib import Path

from tests import REPO_ROOT

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def fixture_exclusions(name: str = "policy-basic.yml") -> list[dict]:
    """Load the exclusion rules from a fixture policy file."""
    import check_scope

    exclusions, _ = check_scope.load_policy(FIXTURES / name)
    return exclusions


def fixture_scan_noise(name: str = "policy-basic.yml") -> list[str]:
    import check_scope

    _, scan_noise = check_scope.load_policy(FIXTURES / name)
    return scan_noise


@contextlib.contextmanager
def temp_tree(files: dict[str, str]):
    """Materialise a throwaway file tree and yield its root.

    Keys are repository-relative paths, values are file contents. Parent
    directories are created automatically.

    The tree is deleted when the block exits. Assert the ABSENCE of a file
    inside the block, never after it: `assertFalse(p.exists())` on the outside
    passes whether or not the code under test wrote the file, which turns a
    no-partial-write control into a test that cannot fail. Capturing a value
    inside and asserting on it outside is fine.
    """
    with tempfile.TemporaryDirectory() as raw:
        root = Path(raw)
        for rel, content in files.items():
            target = root / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
        yield root


__all__ = ["REPO_ROOT", "FIXTURES", "fixture_exclusions", "fixture_scan_noise", "temp_tree"]
```

- [ ] **Step 3: Создать фикстуру политики**

Фикстура намеренно упражняет комментарии, значения в кавычках, паттерн-директорию с завершающим слэшем и обе секции.

`tests/fixtures/policy-basic.yml`:

```yaml
# Fixture policy. Deliberately small and independent of policy/excluded-paths.yml
# so that editing the real policy cannot break the test suite.
exclusions:
  - pattern: "**/.env"
    owner: appsec
    reason: Runtime secrets
  - pattern: "**/*.pem"
    owner: appsec
    reason: Certificate or key material
  - pattern: "secrets/"          # trailing slash means the whole directory
    owner: appsec
    reason: Secret material

scan_noise:
  - "node_modules/"
  - "dist/"
```

- [ ] **Step 4: Написать проверку самой инфраструктуры**

`tests/test_harness.py`:

```python
"""Proves the harness itself works before anything depends on it."""

import unittest
from pathlib import Path

from tests.helpers import FIXTURES, fixture_exclusions, temp_tree


class TestHarness(unittest.TestCase):
    def test_scripts_are_importable(self):
        import check_scope

        self.assertTrue(hasattr(check_scope, "check_path"))

    def test_fixture_policy_is_present(self):
        self.assertTrue((FIXTURES / "policy-basic.yml").exists())

    def test_fixture_exclusions_load(self):
        self.assertEqual(len(fixture_exclusions()), 3)

    def test_temp_tree_materialises_files(self):
        with temp_tree({"a/b.py": "print(1)\n"}) as root:
            self.assertEqual((root / "a" / "b.py").read_text(), "print(1)\n")
        self.assertFalse(Path(root).exists())


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 5: Добавить цель `make test`**

В `Makefile` дописать `test` в список `.PHONY` и добавить цель. `-t .` задаёт корень репозитория как top-level directory, иначе `tests` не импортируется как пакет.

```make
test:
	@python3 -m unittest discover -s tests -t . -v
```

Также добавить строку в блок `help`:

```make
	@echo "  make test                 run the test suite (stdlib only)"
```

- [ ] **Step 6: Прогнать**

Run: `make test`
Expected: 4 теста, все PASS.

- [ ] **Step 7: Коммит**

```bash
git add tests Makefile
git commit -m "test: add stdlib test harness and policy fixture"
```

---

### Task 2: Тесты парсера политики

**Files:**
- Create: `tests/test_check_scope.py`

**Interfaces:**
- Consumes: `tests.helpers.FIXTURES`, `check_scope.load_policy`, `check_scope._parse_policy`.
- Produces: класс `TestParsePolicy`; следующая задача дописывает в этот же файл класс `TestMatches`.

- [ ] **Step 1: Написать тесты**

`_parse_policy` написан вручную специально, чтобы отсутствие PyYAML не отключало контроль молча. Значит он и есть предмет проверки.

`tests/test_check_scope.py`:

```python
"""Tests for the scope control.

check_scope is the only component in this repository whose refusal is a
security control rather than a convenience, so it is tested first and hardest.
"""

import unittest

import check_scope
from tests.helpers import FIXTURES


class TestParsePolicy(unittest.TestCase):
    def setUp(self):
        self.exclusions, self.scan_noise = check_scope.load_policy(
            FIXTURES / "policy-basic.yml"
        )

    def test_reads_every_exclusion(self):
        patterns = [rule["pattern"] for rule in self.exclusions]
        self.assertEqual(patterns, ["**/.env", "**/*.pem", "secrets/"])

    def test_keeps_owner_and_reason(self):
        first = self.exclusions[0]
        self.assertEqual(first["owner"], "appsec")
        self.assertEqual(first["reason"], "Runtime secrets")

    def test_strips_trailing_comment(self):
        third = self.exclusions[2]
        self.assertEqual(third["pattern"], "secrets/")

    def test_reads_scan_noise_as_bare_strings(self):
        self.assertEqual(self.scan_noise, ["node_modules/", "dist/"])

    def test_missing_policy_refuses_rather_than_defaulting(self):
        with self.assertRaises(FileNotFoundError):
            check_scope.load_policy(FIXTURES / "does-not-exist.yml")

    def test_rules_without_a_pattern_are_dropped(self):
        exclusions, _ = check_scope._parse_policy(
            "exclusions:\n"
            "  - owner: appsec\n"
            "    reason: no pattern key\n"
            '  - pattern: "**/id_rsa"\n'
            "    owner: appsec\n"
        )
        self.assertEqual([r["pattern"] for r in exclusions], ["**/id_rsa"])


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Прогнать**

Run: `make test`
Expected: все PASS. Если `test_strips_trailing_comment` падает — парсер не срезает комментарии, и это находка; зафиксируйте вывод и остановитесь.

- [ ] **Step 3: Коммит**

```bash
git add tests/test_check_scope.py
git commit -m "test: cover the hand-rolled policy parser"
```

---

### Task 3: Тесты матчинга путей, включая красные

**Files:**
- Modify: `tests/test_check_scope.py`
- Create: `docs/superpowers/evidence/2026-09-01-red-tests.md`
- Create: `docs/superpowers/evidence/2026-09-01-plan-fixes.md`

**Interfaces:**
- Consumes: `check_scope._matches`, `check_scope.check_path`, `check_scope.ScopeViolation`.
- Produces: класс `TestMatches`. Два его теста красные до Task 10.

- [ ] **Step 1: Дописать класс матчинга**

Добавить в `tests/test_check_scope.py` перед блоком `if __name__`:

```python
class TestMatches(unittest.TestCase):
    def setUp(self):
        self.exclusions = check_scope.load_policy(FIXTURES / "policy-basic.yml")[0]

    def assertRefused(self, path):
        with self.assertRaises(check_scope.ScopeViolation):
            check_scope.check_path(path, self.exclusions)

    def assertAllowed(self, path):
        check_scope.check_path(path, self.exclusions)

    def test_dotfile_at_root(self):
        self.assertRefused(".env")

    def test_dotfile_nested(self):
        self.assertRefused("services/api/.env")

    def test_dot_slash_prefix_is_stripped_not_lstripped(self):
        # lstrip("./") would eat the leading dot and turn ".env" into "env",
        # defeating every dotfile exclusion in the policy.
        self.assertRefused("./.env")

    def test_extension_glob_at_root_and_at_depth(self):
        self.assertRefused("server.pem")
        self.assertRefused("certs/intermediate/server.pem")

    def test_directory_pattern_covers_contents(self):
        self.assertRefused("secrets/token.txt")
        self.assertRefused("app/secrets/token.txt")

    def test_windows_separators_are_normalised(self):
        self.assertRefused("services\\api\\.env")

    def test_similar_names_are_not_refused(self):
        self.assertAllowed("src/environment.py")
        self.assertAllowed("docs/env-setup.md")
        self.assertAllowed("src/secretsmanager.py")

    # --- Red until Task 10 -------------------------------------------------
    # macOS APFS and Windows NTFS are case-insensitive by default, so `.ENV`
    # and `.env` name the same file with the same contents. fnmatch.fnmatch
    # delegates to os.path.normcase, which is the identity on POSIX, so the
    # glob is case-sensitive there and the second spelling walks straight past
    # the exclusion.

    def test_uppercase_dotfile_is_refused(self):
        self.assertRefused(".ENV")

    def test_mixed_case_extension_is_refused(self):
        self.assertRefused("certs/Server.PEM")
```

- [ ] **Step 2: Прогнать и зафиксировать красные**

Run: `make test`
Expected: FAIL ровно в двух тестах — `test_uppercase_dotfile_is_refused` и `test_mixed_case_extension_is_refused`, оба с `ScopeViolation not raised`. Сохраните вывод: он является доказательством дефекта §1.4.

Если падает что-то ещё — остановитесь и сообщите: спека построена на неверном чтении кода.

- [ ] **Step 3: Коммит**

```bash
git add tests/test_check_scope.py
git commit -m "test: cover path matching; two cases red pending case-folding fix"
```

---

### Task 4: Параметр `exclusions` и проверка порядка scope-check

**Files:**
- Modify: `scripts/build_packet.py:116-130`
- Create: `tests/test_build_packet.py`
- Create: `tests/fixtures/sample.sarif`

**Interfaces:**
- Consumes: `tests.helpers.temp_tree`, `tests.helpers.FIXTURES`.
- Produces: `build_packet.build_triage_packet(result, repo, window, exclusions=None)` — новый четвёртый параметр. Задачи 11, 15 и 16 опираются на него.

- [ ] **Step 1: Добавить параметр**

Сейчас `build_triage_packet` зовёт `load_policy()` без аргументов и жёстко привязан к боевой политике. В `scripts/build_packet.py` заменить сигнатуру и начало тела:

```python
def build_triage_packet(
    result: dict, repo: Path, window: int, exclusions: list[dict] | None = None
) -> dict:
    fid = finding_id(result["rule_id"], result["file"], result["start_line"])

    # Scope check before any file content is read. This ordering is the point.
    if exclusions is None:
        exclusions, _ = load_policy()
```

Остальное тело не трогать.

- [ ] **Step 2: Создать фикстуру SARIF**

`tests/fixtures/sample.sarif`:

```json
{
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "semgrep",
          "rules": [
            {
              "id": "python.lang.security.audit.exec-detected",
              "shortDescription": { "text": "exec detected" },
              "fullDescription": { "text": "Detected the use of exec" }
            },
            {
              "id": "python.django.security.injection.sql",
              "shortDescription": { "text": "SQL injection" }
            }
          ]
        }
      },
      "results": [
        {
          "ruleId": "python.lang.security.audit.exec-detected",
          "level": "error",
          "message": { "text": "Detected the use of exec" },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": { "uri": "app/handler.py" },
                "region": { "startLine": 5, "endLine": 5 }
              }
            }
          ]
        },
        {
          "ruleId": "python.django.security.injection.sql",
          "level": "warning",
          "message": { "text": "SQL injection" },
          "partialFingerprints": { "semgrep.fingerprint": "abc123def456" },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": { "uri": "app/db.py" },
                "region": { "startLine": 2, "endLine": 2 }
              }
            }
          ],
          "codeFlows": [
            {
              "threadFlows": [
                {
                  "locations": [
                    {
                      "location": {
                        "physicalLocation": {
                          "artifactLocation": { "uri": "app/routes.py" },
                          "region": { "startLine": 3 }
                        },
                        "message": { "text": "source: request parameter" }
                      }
                    }
                  ]
                }
              ]
            }
          ]
        },
        {
          "ruleId": "generic.secrets.private-key-detected",
          "level": "note",
          "message": { "text": "Private key material" },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": { "uri": "config/server.pem" },
                "region": { "startLine": 1, "endLine": 1 }
              }
            }
          ]
        }
      ]
    }
  ]
}
```

- [ ] **Step 3: Написать тесты**

`tests/test_build_packet.py`:

```python
"""Tests for packet construction.

The ordering test is the important one: docs/03-data-handling.md claims the
scope check runs before any file content is read, and that claim is what makes
the data-handling story true.
"""

import unittest
from pathlib import Path

import build_packet
import check_scope
from tests.helpers import FIXTURES, fixture_exclusions, temp_tree

SARIF = FIXTURES / "sample.sarif"


class TestLoadSarif(unittest.TestCase):
    def setUp(self):
        self.results = build_packet.load_sarif_results(SARIF)

    def test_reads_every_result(self):
        self.assertEqual(len(self.results), 3)

    def test_prefers_full_description_over_message(self):
        self.assertEqual(self.results[0]["rule_description"], "Detected the use of exec")

    def test_falls_back_to_short_description(self):
        self.assertEqual(self.results[1]["rule_description"], "SQL injection")

    def test_extracts_code_flows(self):
        steps = self.results[1]["code_flows"][0]["steps"]
        self.assertEqual(steps[0]["file"], "app/routes.py")
        self.assertEqual(steps[0]["line"], 3)

    def test_result_without_flows_has_empty_list(self):
        self.assertEqual(self.results[0]["code_flows"], [])


class TestScopeCheckOrdering(unittest.TestCase):
    """The scope check must refuse before the file is opened."""

    def test_excluded_path_refuses_even_when_file_is_absent(self):
        results = build_packet.load_sarif_results(SARIF)
        excluded = results[2]
        # Excluded by **/*.pem under BOTH the fixture policy and the live one.
        # The manual check in Task 11 Step 8 runs against the live policy, so a
        # fixture path excluded only by the fixture would look in-scope there.
        self.assertEqual(excluded["file"], "config/server.pem")

        # Empty tree: the file does not exist. If the builder read first and
        # checked second, this would raise FileNotFoundError instead.
        with temp_tree({}) as repo:
            with self.assertRaises(check_scope.ScopeViolation):
                build_packet.build_triage_packet(
                    excluded, repo, 40, fixture_exclusions()
                )


class TestReadContext(unittest.TestCase):
    def setUp(self):
        self.text = "\n".join(f"line{i}" for i in range(1, 11)) + "\n"

    def test_window_clamps_at_start_of_file(self):
        with temp_tree({"a.py": self.text}) as root:
            out = build_packet.read_context(root / "a.py", 1, 1, 3)
        self.assertTrue(out.splitlines()[0].endswith("| line1"))
        self.assertEqual(len(out.splitlines()), 4)

    def test_window_clamps_at_end_of_file(self):
        with temp_tree({"a.py": self.text}) as root:
            out = build_packet.read_context(root / "a.py", 10, 10, 3)
        self.assertTrue(out.splitlines()[-1].endswith("| line10"))

    def test_window_wider_than_file_returns_whole_file(self):
        with temp_tree({"a.py": self.text}) as root:
            out = build_packet.read_context(root / "a.py", 5, 5, 500)
        self.assertEqual(len(out.splitlines()), 10)

    def test_missing_file_returns_none(self):
        self.assertIsNone(build_packet.read_context(Path("/nope/absent.py"), 1, 1, 3))


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 4: Прогнать**

Run: `make test`
Expected: всё PASS, кроме двух известных красных из Task 3.

- [ ] **Step 5: Коммит**

```bash
git add scripts/build_packet.py tests/test_build_packet.py tests/fixtures/sample.sarif
git commit -m "test: prove scope check precedes file reads; inject exclusions for testability"
```

---

### Task 5: Тесты консистентности и продвижения, включая красные

**Files:**
- Create: `tests/test_record_verdict.py`
- Update: `docs/superpowers/evidence/2026-09-01-red-tests.md`
- Update: `docs/superpowers/evidence/2026-09-01-plan-fixes.md`

**Interfaces:**
- Consumes: `record_verdict.check_consistency`, `record_verdict.decide_state`.
- Produces: `tests.test_record_verdict.make_verdict(**overrides) -> dict` — фабрика валидного вердикта, используется задачами 8, 9, 12, 13, 17.

- [ ] **Step 1: Написать тесты**

`tests/test_record_verdict.py`:

```python
"""Tests for verdict validation and promotion.

decide_state decides what enters the audit trail, and the rationale it returns
is written verbatim into SARIF. A rationale that overstates what was verified
is a defect of the same kind this whole workflow exists to catch.
"""

import unittest

import record_verdict


def make_verdict(**overrides) -> dict:
    """A minimal verdict that passes schema and consistency checks."""
    verdict = {
        "finding_id": "F-000000000001",
        "rule_id": "python.lang.security.audit.exec-detected",
        "verdict": "true_positive",
        "confidence": "medium",
        "evidence_level": "partial",
        "severity": "medium",
        "reasoning": "Read the sink and its immediate callers; path not fully resolved.",
        "reviewer": {"agent": "model-a", "reviewed_at": "2026-09-01T10:00:00+00:00"},
        "location": {"file": "app/handler.py", "start_line": 4, "end_line": 4},
    }
    verdict.update(overrides)
    return verdict


def make_challenge(result: str = "upheld", **overrides) -> dict:
    challenge = {
        "finding_id": "F-000000000001",
        "challenge_result": result,
        "refutation_attempts": [
            {"claim": "input is attacker controlled", "result": "held"}
        ],
        "reasoning": "Re-derived the flow independently; the claim survived.",
        "validator": {"agent": "model-b", "validated_at": "2026-09-01T12:00:00+00:00"},
    }
    challenge.update(overrides)
    return challenge


class TestCheckConsistency(unittest.TestCase):
    def test_clean_verdict_has_no_problems(self):
        self.assertEqual(record_verdict.check_consistency(make_verdict()), [])

    def test_high_confidence_requires_traced(self):
        problems = record_verdict.check_consistency(
            make_verdict(confidence="high", evidence_level="partial")
        )
        self.assertEqual(len(problems), 1)
        self.assertIn("evidence_level=traced", problems[0])

    def test_pattern_cannot_be_true_positive(self):
        problems = record_verdict.check_consistency(
            make_verdict(evidence_level="pattern", verdict="true_positive")
        )
        self.assertEqual(len(problems), 1)
        self.assertIn("pattern", problems[0])

    def test_traced_requires_data_flow(self):
        problems = record_verdict.check_consistency(
            make_verdict(evidence_level="traced")
        )
        self.assertEqual(len(problems), 1)
        self.assertIn("data_flow", problems[0])

    def test_traced_with_data_flow_is_clean(self):
        problems = record_verdict.check_consistency(
            make_verdict(
                evidence_level="traced",
                data_flow=[{"file": "app/handler.py", "description": "sink"}],
            )
        )
        self.assertEqual(problems, [])

    def test_memory_safety_cwe_requires_runtime_proof(self):
        problems = record_verdict.check_consistency(make_verdict(cwe=["CWE-416"]))
        self.assertEqual(len(problems), 1)
        self.assertIn("CWE-416", problems[0])

    def test_blocked_by_scope_forces_needs_human(self):
        problems = record_verdict.check_consistency(
            make_verdict(blocked_by_scope=["policy/secrets/"], verdict="true_positive")
        )
        self.assertEqual(len(problems), 1)
        self.assertIn("needs_human", problems[0])


class TestDecideState(unittest.TestCase):
    def test_medium_without_challenge_is_blocked(self):
        state, _ = record_verdict.decide_state(make_verdict(severity="medium"), None)
        self.assertEqual(state, "blocked_needs_challenge")

    def test_refuted_challenge_goes_to_human(self):
        state, rationale = record_verdict.decide_state(
            make_verdict(), make_challenge("refuted")
        )
        self.assertEqual(state, "human_review")
        self.assertIn("refuted", rationale)

    def test_inconclusive_challenge_goes_to_human(self):
        state, _ = record_verdict.decide_state(
            make_verdict(), make_challenge("inconclusive")
        )
        self.assertEqual(state, "human_review")

    def test_runtime_proof_parks_the_finding(self):
        state, _ = record_verdict.decide_state(
            make_verdict(requires_runtime_proof=True), make_challenge()
        )
        self.assertEqual(state, "awaiting_proof")

    def test_pattern_evidence_never_confirms(self):
        state, _ = record_verdict.decide_state(
            make_verdict(verdict="false_positive", evidence_level="pattern"),
            make_challenge(),
        )
        self.assertEqual(state, "dismissed")

    def test_needs_human_verdict_goes_to_human(self):
        state, _ = record_verdict.decide_state(
            make_verdict(verdict="needs_human"), make_challenge()
        )
        self.assertEqual(state, "human_review")

    def test_challenged_true_positive_is_confirmed(self):
        self.assertEqual(
            record_verdict.decide_state(
                make_verdict(evidence_level="partial"), make_challenge("upheld")
            ),
            ("confirmed", "true positive upheld under adversarial validation"),
        )

    # --- Red until Task 7 --------------------------------------------------
    # Policy exempts low and info from adversarial validation, so reaching
    # `confirmed` without a challenge is correct. Claiming the finding was
    # "upheld under adversarial validation" when no second pass ran is not:
    # that sentence is written verbatim into reviewed.sarif and the triage log.

    def test_unchallenged_low_says_so_plainly(self):
        self.assertEqual(
            record_verdict.decide_state(
                make_verdict(severity="low", evidence_level="partial"), None
            ),
            (
                "confirmed",
                "true positive; severity=low does not require adversarial "
                "validation under policy",
            ),
        )

    def test_unchallenged_info_dismissal_says_so_plainly(self):
        self.assertEqual(
            record_verdict.decide_state(
                make_verdict(
                    severity="info", verdict="false_positive", evidence_level="partial"
                ),
                None,
            ),
            (
                "dismissed",
                "false positive; severity=info does not require adversarial "
                "validation under policy",
            ),
        )


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Прогнать и зафиксировать красные**

Run: `make test`
Expected: FAIL ровно в `test_unchallenged_low_says_so_plainly` и `test_unchallenged_info_dismissal_says_so_plainly`. Первый покажет фактическое `'true positive upheld under adversarial validation'` — это и есть ложное утверждение §1.1. Сохраните вывод.

Всего красных на этот момент: 4 (два из Task 3, два отсюда).

- [ ] **Step 3: Коммит**

```bash
git add tests/test_record_verdict.py
git commit -m "test: cover consistency rules and promotion matrix; two cases red"
```

---

### Task 6: Тесты метрик

**Files:**
- Create: `tests/test_metrics.py`
- Modify: `tests/helpers.py`

**Interfaces:**
- Consumes: `metrics.load_rows`, `metrics.compute`, `metrics.render`.
- Produces: `tests.helpers.write_log(path: Path, rows: list[dict]) -> None` — пишет CSV по актуальному `record_verdict.LOG_FIELDS`. Задачи 13 и 19 расширяют список колонок; помощник переживает это без правок.

- [ ] **Step 1: Добавить помощник записи лога**

Помощник читает `LOG_FIELDS` из модуля, а не дублирует список. Колонки будут добавляться в задачах 13 и 19, и захардкоженный заголовок сломал бы тесты на ровном месте.

Дописать в `tests/helpers.py` перед `__all__`:

```python
def write_log(path, rows: list[dict]) -> None:
    """Write a triage log using whatever columns record_verdict declares today.

    Reading LOG_FIELDS from the module rather than hardcoding it here means
    later tasks can add columns without breaking every metrics test.
    """
    import csv

    import record_verdict

    with Path(path).open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=record_verdict.LOG_FIELDS)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k, "") for k in record_verdict.LOG_FIELDS})
```

И добавить `"write_log"` в `__all__`.

- [ ] **Step 2: Написать тесты**

`tests/test_metrics.py`:

```python
"""Tests for programme metrics.

Metric 4 (disagreement rate) is the one that tells you whether the second pass
is doing any work, so its edge cases matter more than the headline numbers.
"""

import unittest

import metrics
from tests.helpers import temp_tree, write_log


def row(**overrides) -> dict:
    base = {
        "reviewed_at": "2026-09-01T10:00:00+00:00",
        "finding_id": "F-000000000001",
        "severity": "medium",
        "evidence_level": "traced",
        "confidence": "high",
        "initial_verdict": "true_positive",
        "challenge_result": "upheld",
        "final_state": "confirmed",
        "minutes_spent": "10",
        "requires_runtime_proof": "False",
        "agent": "model-a",
        "validator": "model-b",
    }
    base.update(overrides)
    return base


class TestCompute(unittest.TestCase):
    def compute(self, rows):
        with temp_tree({"placeholder": ""}) as root:
            log = root / "triage-log.csv"
            write_log(log, rows)
            return metrics.compute(metrics.load_rows(log, None))

    def test_empty_log(self):
        self.assertEqual(metrics.compute([]), {"total": 0})

    def test_missing_log_is_not_an_error(self):
        self.assertEqual(metrics.load_rows(metrics.LOG_PATH.parent / "absent.csv", None), [])

    def test_counts_states(self):
        m = self.compute([row(), row(finding_id="F-2", final_state="dismissed")])
        self.assertEqual(m["total"], 2)
        self.assertEqual(m["decided"], 2)
        self.assertEqual(m["undecided"], 0)

    def test_rate_excludes_undecided_findings(self):
        # Parked findings are not evidence of precision, so they must stay out
        # of the denominator.
        m = self.compute(
            [
                row(),
                row(finding_id="F-2", final_state="dismissed"),
                row(finding_id="F-3", final_state="human_review", challenge_result=""),
            ]
        )
        self.assertEqual(m["decided"], 2)
        self.assertEqual(m["undecided"], 1)
        self.assertEqual(m["false_positive_rate_pct"], 50.0)

    def test_disagreement_rate_over_challenged_only(self):
        m = self.compute(
            [
                row(),
                row(finding_id="F-2", challenge_result="refuted", final_state="human_review"),
            ]
        )
        self.assertEqual(m["disagreement_rate_pct"], 50.0)

    def test_same_model_validations_are_counted(self):
        m = self.compute([row(validator="model-a")])
        self.assertEqual(m["same_model_validations"], 1)

    def test_timings(self):
        m = self.compute([row(minutes_spent="10"), row(finding_id="F-2", minutes_spent="20")])
        self.assertEqual(m["median_minutes"], 15.0)
        self.assertEqual(m["timed_findings"], 2)

    def test_unparseable_timing_is_skipped_not_fatal(self):
        m = self.compute([row(minutes_spent=""), row(finding_id="F-2", minutes_spent="8")])
        self.assertEqual(m["timed_findings"], 1)

    def test_since_filter(self):
        with temp_tree({"placeholder": ""}) as root:
            log = root / "triage-log.csv"
            write_log(
                log,
                [
                    row(reviewed_at="2026-07-01T10:00:00+00:00"),
                    row(finding_id="F-2", reviewed_at="2026-09-01T10:00:00+00:00"),
                ],
            )
            kept = metrics.load_rows(log, "2026-08-01")
        self.assertEqual([r["finding_id"] for r in kept], ["F-2"])


class TestRender(unittest.TestCase):
    def test_empty_render_tells_you_what_to_do(self):
        self.assertIn("No reviews recorded yet", metrics.render({"total": 0}))

    def test_zero_disagreement_raises_the_alarm(self):
        m = metrics.compute(
            [
                dict(row(), final_state="confirmed"),
                dict(row(), finding_id="F-2", final_state="confirmed"),
            ]
        )
        self.assertIn("rubber-stamping", metrics.render(m))


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 3: Прогнать**

Run: `make test`
Expected: PASS, кроме четырёх известных красных.

- [ ] **Step 4: Коммит**

```bash
git add tests/test_metrics.py tests/helpers.py
git commit -m "test: cover metric aggregation and its warning paths"
```

**Слой 0 завершён.** Итог: 4 красных теста, каждый соответствует дефекту из спеки. Если красных больше или меньше — остановитесь и сообщите до начала слоя 1.

---

# Слой 1 — корректность контролей

### Task 7: Честный rationale в `decide_state`

**Files:**
- Modify: `scripts/record_verdict.py:152-189`

**Interfaces:**
- Consumes: тесты из Task 5.
- Produces: `record_verdict._unchallenged_note(verdict_label: str, severity: str) -> str`.

- [ ] **Step 1: Подтвердить красноту**

Run: `python3 -m unittest tests.test_record_verdict.TestDecideState -v`
Expected: FAIL в двух тестах `*_says_so_plainly`.

- [ ] **Step 2: Добавить хелпер формулировки**

Вставить в `scripts/record_verdict.py` непосредственно перед `def decide_state`:

```python
def _unchallenged_note(verdict_label: str, severity: str) -> str:
    """Rationale for a finding that policy exempts from adversarial validation.

    Deliberately distinct from the challenged wording. Only critical, high and
    medium require a challenge; reporting a low finding as "upheld under
    adversarial validation" would write a false statement into reviewed.sarif
    and the triage log, where it outlives everyone who remembers the context.
    """
    return (
        f"{verdict_label}; severity={severity} does not require adversarial "
        "validation under policy"
    )
```

- [ ] **Step 3: Развести ветки продвижения**

Заменить обе терминальные ветки в `decide_state`:

```python
    if v == "true_positive":
        if verdict.get("requires_runtime_proof"):
            return (
                "awaiting_proof",
                "static reasoning cannot confirm this class; a runtime harness must reproduce it",
            )
        if verdict.get("evidence_level") == "pattern":
            return ("human_review", "pattern-level evidence is insufficient to confirm")
        if challenge_result == "upheld":
            return ("confirmed", "true positive upheld under adversarial validation")
        return ("confirmed", _unchallenged_note("true positive", severity))

    if v == "false_positive":
        if challenge_result == "upheld":
            return ("dismissed", "false positive upheld")
        if not needs_challenge:
            return ("dismissed", _unchallenged_note("false positive", severity))
        return ("human_review", "dismissal not independently validated")
```

- [ ] **Step 4: Прогнать**

Run: `make test`
Expected: красных осталось 2 (только из Task 3).

- [ ] **Step 5: Коммит**

```bash
git add scripts/record_verdict.py
git commit -m "fix: stop claiming adversarial validation that never ran"
```

---

### Task 8: Накопление SARIF вместо перезаписи

**Files:**
- Modify: `scripts/record_verdict.py:202-269`, `:272-372`
- Modify: `tests/test_record_verdict.py`
- Modify: `docs/superpowers/evidence/2026-09-01-red-tests.md`
- Modify: `docs/superpowers/evidence/2026-09-01-plan-fixes.md`

**Interfaces:**
- Consumes: `make_verdict`, `make_challenge` из Task 5.
- Produces: `record_verdict.build_result(verdict, challenge, state, rationale) -> dict`, `record_verdict.sarif_document(results: list[dict]) -> dict`, `record_verdict.load_existing_results(path: Path) -> list[dict]`, `record_verdict.merge_result(existing: list[dict], result: dict) -> list[dict]`. Задача 18 вызывает `load_existing_results` и `sarif_document`.

- [ ] **Step 1: Написать падающие тесты**

Дописать в `tests/test_record_verdict.py` перед блоком `if __name__`:

```python
class TestSarifAccumulation(unittest.TestCase):
    """docs/04 loops record_verdict over many verdicts; each call must keep
    the previous ones. A single-result write silently discards the batch."""

    def result_for(self, fid, state="confirmed"):
        return record_verdict.build_result(
            make_verdict(finding_id=fid), None, state, "rationale text"
        )

    def test_second_finding_does_not_evict_the_first(self):
        merged = record_verdict.merge_result([], self.result_for("F-1"))
        merged = record_verdict.merge_result(merged, self.result_for("F-2"))
        ids = [r["properties"]["finding_id"] for r in merged]
        self.assertEqual(ids, ["F-1", "F-2"])

    def test_rerecording_replaces_rather_than_duplicates(self):
        merged = record_verdict.merge_result([], self.result_for("F-1", "confirmed"))
        merged = record_verdict.merge_result(merged, self.result_for("F-1", "dismissed"))
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0]["properties"]["state"], "dismissed")

    def test_order_is_deterministic(self):
        merged = record_verdict.merge_result([], self.result_for("F-9"))
        merged = record_verdict.merge_result(merged, self.result_for("F-1"))
        ids = [r["properties"]["finding_id"] for r in merged]
        self.assertEqual(ids, sorted(ids))

    def test_absent_file_yields_empty_list(self):
        with temp_tree({}) as root:
            self.assertEqual(
                record_verdict.load_existing_results(root / "reviewed.sarif"), []
            )

    def test_unparseable_file_refuses_rather_than_overwriting(self):
        with temp_tree({"reviewed.sarif": "{ this is not json"}) as root:
            with self.assertRaises(record_verdict.ValidationError):
                record_verdict.load_existing_results(root / "reviewed.sarif")

    # Two CLI-level tests for this task live in Task 12's
    # TestIndependenceControl instead: --fresh, and the refusal on malformed
    # existing SARIF. Both need --log so they do not write into the real
    # findings/ directory, and --log only exists from Task 12 onward.

    def test_round_trip_through_document(self):
        doc = record_verdict.sarif_document([self.result_for("F-1")])
        with temp_tree({}) as root:
            path = root / "reviewed.sarif"
            path.write_text(json.dumps(doc), encoding="utf-8")
            self.assertEqual(len(record_verdict.load_existing_results(path)), 1)
```

Добавить в шапку файла `import json` и `from tests.helpers import temp_tree`.

- [ ] **Step 2: Прогнать, убедиться что падает**

Run: `python3 -m unittest tests.test_record_verdict.TestSarifAccumulation -v`
Expected: FAIL with `AttributeError` for the required new helper API. Test
ordering may expose a missing helper other than `build_result` first.

- [ ] **Step 3: Разделить построение результата и документа**

В `scripts/record_verdict.py` переименовать `to_sarif` в `build_result`, оставив тело до `return {` без изменений, и завершить его возвратом одного результата:

```python
def build_result(verdict: dict, challenge: dict | None, state: str, rationale: str) -> dict:
    """Build one SARIF result for a reviewed finding.

    Dismissed findings carry a SARIF suppression, which is how a findings store
    learns not to re-raise them on the next scan.
    """
```

Тело оставить как есть до формирования `result`, затем:

```python
    if state == "dismissed":
        result["suppressions"] = [
            {
                "kind": "external",
                "justification": f"Dismissed after adversarial validation. {rationale}",
            }
        ]

    return result
```

- [ ] **Step 4: Добавить документ, чтение и слияние**

Дописать следом:

```python
def sarif_document(results: list[dict]) -> dict:
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "appsec-review",
                        "informationUri": "https://example.org/appsec-review",
                        "version": "1.0.0",
                    }
                },
                "results": results,
            }
        ],
    }


def load_existing_results(path: Path) -> list[dict]:
    """Read previously recorded results so a new one joins them.

    A file we cannot parse is a refusal, not a licence to overwrite: the
    reviewed SARIF is the audit trail's current-state view, and silently
    discarding it would lose every earlier verdict.
    """
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        raise ValidationError(
            f"Cannot read {path}: {exc}. Refusing to overwrite a file that "
            "cannot be parsed. Move it aside, or pass --fresh to start over."
        ) from exc
    runs = data.get("runs") or []
    if not runs:
        return []
    return runs[0].get("results", [])


def merge_result(existing: list[dict], result: dict) -> list[dict]:
    """Replace the result with the same finding_id, or append it."""
    fid = result["properties"]["finding_id"]
    merged = [
        r for r in existing if r.get("properties", {}).get("finding_id") != fid
    ]
    merged.append(result)
    merged.sort(key=lambda r: r.get("properties", {}).get("finding_id", ""))
    return merged
```

- [ ] **Step 5: Подключить в `main`, разбирая SARIF до любой записи**

Добавить флаг рядом с остальными аргументами:

```python
    parser.add_argument("--fresh", action="store_true",
                        help="Discard the existing reviewed SARIF instead of adding to it")
```

**Порядок здесь и есть предмет задачи.** Разбор существующего SARIF обязан идти до `append_log`. Лог append-only: строка, записанная перед отказом, не может быть отозвана, и два артефакта расходятся навсегда. Вставить непосредственно **перед** вызовом `append_log(`:

```python
    # Parse the existing SARIF before writing anything. The triage log is
    # append-only, so a row written ahead of a SARIF failure could never be
    # withdrawn and the two artefacts would disagree permanently.
    try:
        existing = [] if args.fresh else load_existing_results(args.sarif_out)
    except ValidationError as exc:
        print(f"SARIF ERROR: {exc}", file=sys.stderr)
        return 1
```

И заменить прежний блок записи SARIF на слияние и запись, без повторного чтения:

```python
    results = merge_result(existing, build_result(verdict, challenge, state, rationale))
    args.sarif_out.parent.mkdir(parents=True, exist_ok=True)
    args.sarif_out.write_text(json.dumps(sarif_document(results), indent=2), encoding="utf-8")
```

- [ ] **Step 6: Прогнать**

Run: `make test`
Expected: PASS, кроме двух красных из Task 3.

- [ ] **Step 7: Коммит**

```bash
git add scripts/record_verdict.py tests/test_record_verdict.py
git commit -m "fix: accumulate reviewed SARIF instead of overwriting per finding"
```

---

### Task 9: Укрепление резервного валидатора

**Files:**
- Modify: `scripts/record_verdict.py:71-113`
- Modify: `tests/test_record_verdict.py`
- Modify: `docs/superpowers/evidence/2026-09-01-red-tests.md`
- Modify: `docs/superpowers/evidence/2026-09-01-plan-fixes.md`

**Interfaces:**
- Consumes: `record_verdict._fallback_validate`, `record_verdict.ValidationError`.
- Produces: `record_verdict._JSON_TYPES: dict[str, type | tuple]`, `record_verdict._type_ok(value, expected) -> bool`.

- [ ] **Step 1: Написать падающие тесты**

Дописать в `tests/test_record_verdict.py`:

```python
class TestFallbackValidator(unittest.TestCase):
    """The fallback exists so a missing jsonschema degrades the check rather
    than removing it. It degraded further than advertised."""

    SCHEMA = {
        "required": ["name"],
        "additionalProperties": False,
        "properties": {
            "name": {"type": "string", "minLength": 2},
            "count": {"type": "integer"},
            "mode": {"type": "string", "enum": ["a", "b"]},
            "steps": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["file"],
                    "properties": {"file": {"type": "string"}},
                },
            },
            "tags": {"type": "array", "items": {"type": "string"}},
        },
    }

    def validate(self, instance):
        record_verdict._fallback_validate(instance, self.SCHEMA, "fixture")

    def test_missing_required_field(self):
        with self.assertRaises(record_verdict.ValidationError):
            self.validate({})

    def test_unknown_field_when_additional_properties_false(self):
        with self.assertRaises(record_verdict.ValidationError):
            self.validate({"name": "ok", "surprise": 1})

    def test_enum_is_enforced(self):
        with self.assertRaises(record_verdict.ValidationError):
            self.validate({"name": "ok", "mode": "c"})

    def test_min_length_is_enforced(self):
        with self.assertRaises(record_verdict.ValidationError):
            self.validate({"name": "x"})

    def test_valid_instance_passes(self):
        self.validate({"name": "ok", "count": 3, "mode": "a", "tags": ["x"]})

    # --- Gaps closed by this task -----------------------------------------

    def test_boolean_is_not_an_integer(self):
        # bool subclasses int in Python, so isinstance(True, int) is True and
        # `"count": True` slipped through as a valid integer.
        with self.assertRaises(record_verdict.ValidationError):
            self.validate({"name": "ok", "count": True})

    def test_array_items_are_validated(self):
        with self.assertRaises(record_verdict.ValidationError):
            self.validate({"name": "ok", "steps": [{"line": 3}]})

    def test_scalar_array_items_are_type_checked(self):
        with self.assertRaises(record_verdict.ValidationError):
            self.validate({"name": "ok", "tags": [1]})

    def test_unknown_schema_type_is_reported_not_crashed(self):
        with self.assertRaises(record_verdict.ValidationError):
            record_verdict._fallback_validate(
                {"x": 1}, {"properties": {"x": {"type": "int64"}}}, "fixture"
            )

    def test_top_level_non_object_is_reported_not_crashed(self):
        with self.assertRaises(record_verdict.ValidationError):
            record_verdict._fallback_validate(
                [], {"type": "object", "properties": {}}, "fixture"
            )


class TestSchemaDriftGuard(unittest.TestCase):
    """check_consistency compensates for the two conditional rules the
    fallback validator cannot express. If the schema grows a third, this test
    fails and forces someone to decide whether to mirror it."""

    def test_schema_has_exactly_the_conditionals_we_mirror(self):
        schema = json.loads(
            (record_verdict.SCHEMA_DIR / "verdict.schema.json").read_text(encoding="utf-8")
        )
        self.assertEqual(len(schema["allOf"]), 2)

    def test_high_confidence_conditional_is_mirrored(self):
        self.assertTrue(
            record_verdict.check_consistency(
                make_verdict(confidence="high", evidence_level="partial")
            )
        )

    def test_pattern_verdict_conditional_is_mirrored(self):
        self.assertTrue(
            record_verdict.check_consistency(
                make_verdict(evidence_level="pattern", verdict="true_positive")
            )
        )
```

- [ ] **Step 2: Прогнать**

Run: `python3 -m unittest tests.test_record_verdict.TestFallbackValidator -v`
Expected: FAIL в `test_boolean_is_not_an_integer`, `test_array_items_are_validated`, `test_scalar_array_items_are_type_checked`, `test_unknown_schema_type_is_reported_not_crashed`, `test_top_level_non_object_is_reported_not_crashed`.

- [ ] **Step 3: Вынести таблицу типов и проверку**

В `scripts/record_verdict.py` добавить перед `_fallback_validate`:

```python
_JSON_TYPES = {
    "string": str,
    "integer": int,
    "number": (int, float),
    "boolean": bool,
    "array": list,
    "object": dict,
    "null": type(None),
}


def _type_ok(value, expected) -> bool:
    """JSON-schema type check with Python's bool/int overlap accounted for."""
    names = expected if isinstance(expected, list) else [expected]
    for name_ in names:
        if name_ not in _JSON_TYPES:
            raise ValidationError(f"schema uses unknown type {name_!r}")
        # bool is a subclass of int, so True would satisfy "integer" and
        # "number" without this guard.
        if name_ in ("integer", "number") and isinstance(value, bool):
            continue
        if isinstance(value, _JSON_TYPES[name_]):
            return True
    return False
```

- [ ] **Step 4: Переписать тело валидатора**

Заменить `_fallback_validate` целиком:

```python
def _fallback_validate(instance: dict, schema: dict, name: str) -> None:
    """Minimal validator covering required keys, enums, types and array items.

    Not a full draft-07 implementation: `allOf`, `oneOf`, `$ref` and pattern
    matching are out of scope. The two conditional rules the verdict schema
    relies on are enforced separately by check_consistency, and a test guards
    against the schema growing a third.
    """
    if not isinstance(instance, dict):
        raise ValidationError(f"{name}: expected an object")

    for key in schema.get("required", []):
        if key not in instance:
            raise ValidationError(f"{name}: missing required field {key!r}")

    props = schema.get("properties", {})
    for key, value in instance.items():
        spec = props.get(key)
        if not spec:
            if schema.get("additionalProperties") is False:
                raise ValidationError(f"{name}: unexpected field {key!r}")
            continue

        if "enum" in spec and value not in spec["enum"]:
            raise ValidationError(f"{name}: {key}={value!r} not in {spec['enum']}")

        if "type" in spec and not _type_ok(value, spec["type"]):
            raise ValidationError(
                f"{name}: {key} should be {spec['type']}, got {type(value).__name__}"
            )

        if spec.get("minLength") and isinstance(value, str):
            if len(value) < spec["minLength"]:
                raise ValidationError(
                    f"{name}: {key} shorter than {spec['minLength']} chars"
                )

        if isinstance(value, dict) and spec.get("properties"):
            _fallback_validate(value, spec, f"{name}.{key}")

        if isinstance(value, list) and isinstance(spec.get("items"), dict):
            item_spec = spec["items"]
            for index, item in enumerate(value):
                label = f"{name}.{key}[{index}]"
                if item_spec.get("properties") or item_spec.get("required"):
                    if not isinstance(item, dict):
                        raise ValidationError(f"{label}: expected an object")
                    _fallback_validate(item, item_spec, label)
                elif "type" in item_spec and not _type_ok(item, item_spec["type"]):
                    raise ValidationError(
                        f"{label}: should be {item_spec['type']}, "
                        f"got {type(item).__name__}"
                    )
```

- [ ] **Step 5: Прогнать**

Run: `make test`
Expected: PASS, кроме двух красных из Task 3.

- [ ] **Step 6: Коммит**

```bash
git add scripts/record_verdict.py tests/test_record_verdict.py
git commit -m "fix: close type and array gaps in the fallback validator"
```

---

### Task 10: Регистронезависимый матчинг путей

**Files:**
- Modify: `scripts/check_scope.py:93-125`
- Modify: `policy/excluded-paths.yml`
- Modify: `docs/superpowers/evidence/2026-09-01-red-tests.md`
- Modify: `docs/superpowers/evidence/2026-09-01-plan-fixes.md`

**Interfaces:**
- Consumes: красные тесты из Task 3.
- Produces: поведение `_matches` не зависит от ОС.

- [ ] **Step 1: Подтвердить красноту**

Run: `python3 -m unittest tests.test_check_scope.TestMatches -v`
Expected: FAIL в `test_uppercase_dotfile_is_refused` и `test_mixed_case_extension_is_refused`.

- [ ] **Step 2: Свернуть регистр**

В `scripts/check_scope.py` заменить начало `_matches` и три вызова `fnmatch.fnmatch`:

```python
def _matches(path: str, pattern: str) -> bool:
    """gitignore-flavoured glob matching.

    A trailing slash means "this directory and everything under it". A pattern
    without a slash matches at any depth, mirroring gitignore behaviour, so
    `**/.env` and `.env` both catch a nested file.

    Matching is case-insensitive and platform-independent. macOS APFS and
    Windows NTFS are case-insensitive by default, so `.ENV` names the same file
    as `.env`; a case-sensitive glob would let the second spelling walk past
    every dotfile exclusion. fnmatch.fnmatch is not an option here because it
    defers to os.path.normcase, which makes the answer depend on the operating
    system the reviewer happens to be using.
    """
    # Strip a leading "./" as a prefix, not as a character set. lstrip("./")
    # would eat the leading dot of a dotfile and turn ".env" into "env",
    # silently defeating every dotfile exclusion in the policy.
    norm = path.replace("\\", "/")
    while norm.startswith("./"):
        norm = norm[2:]
    norm = norm.lstrip("/").lower()
    pattern = pattern.lower()

    if pattern.endswith("/"):
        prefix = pattern.rstrip("/")
        cleaned = prefix.replace("**/", "")
        return (
            norm.startswith(prefix + "/")
            or f"/{cleaned}/" in f"/{norm}"
            or norm.startswith(cleaned + "/")
        )

    if fnmatch.fnmatchcase(norm, pattern):
        return True
    # `**/x` should also match a top-level `x`
    if pattern.startswith("**/") and fnmatch.fnmatchcase(norm, pattern[3:]):
        return True
    # A bare pattern matches at any depth
    if "/" not in pattern and fnmatch.fnmatchcase(Path(norm).name, pattern):
        return True
    return False
```

- [ ] **Step 3: Закрыть пробел в политике**

В `policy/excluded-paths.yml` после блока `**/.env.*` добавить:

```yaml
  - pattern: "**/.envrc"
    owner: appsec
    reason: direnv environment, commonly holds secrets
```

- [ ] **Step 4: Прогнать**

Run: `make test`
Expected: **все зелёные.** Красных больше нет.

- [ ] **Step 5: Проверить боевую политику вручную**

Run: `python3 scripts/check_scope.py .ENV ; echo "exit=$?"`
Expected: `REFUSED`, `exit=2`.

Run: `python3 scripts/check_scope.py src/environment.py ; echo "exit=$?"`
Expected: `OK: 1 path(s) within scope`, `exit=0`.

- [ ] **Step 6: Коммит**

```bash
git add scripts/check_scope.py policy/excluded-paths.yml
git commit -m "fix: match exclusions case-insensitively and cover .envrc"
```

---

### Task 11: Стабильная идентичность находки

**Files:**
- Modify: `scripts/build_packet.py:32-35`, `:116-180`, `:200-280`
- Modify: `tests/test_build_packet.py`
- Modify: `docs/superpowers/evidence/2026-09-01-red-tests.md`
- Modify: `docs/superpowers/evidence/2026-09-01-plan-fixes.md`

**Interfaces:**
- Consumes: `check_scope.check_path`, `check_scope.ScopeViolation`.
- Produces: `build_packet.ID_SCHEME: str = "content-v1"`, `build_packet.compute_finding_id(result: dict, repo: Path, exclusions: list[dict] | None = None) -> str`, `build_packet.normalize_snippet(text: str) -> str`, `build_packet.scanner_fingerprint(result: dict) -> str | None`, `build_packet.occurrence_index(file_text: str, start_line: int, end_line: int, target: str) -> int`. Задачи 13, 15, 16 и 18 опираются на `ID_SCHEME` и `compute_finding_id`.

- [ ] **Step 1: Написать падающие тесты**

Дописать в `tests/test_build_packet.py` перед блоком `if __name__`:

```python
FILE_BEFORE = "import os\n\n\ndef run(cmd):\n    exec(cmd)\n"
FILE_AFTER = "import os\nimport sys\n\n\ndef run(cmd):\n    exec(cmd)\n"


def result_at(path="app/handler.py", start=5, end=5, **extra):
    base = {
        "rule_id": "python.lang.security.audit.exec-detected",
        "file": path,
        "start_line": start,
        "end_line": end,
    }
    base.update(extra)
    return base


class TestFindingIdentity(unittest.TestCase):
    """The old id hashed the line number, so any edit above a finding gave it a
    new identity: its verdicts were orphaned and dismissed findings came back."""

    def test_line_shift_preserves_identity(self):
        with temp_tree({"app/handler.py": FILE_BEFORE}) as repo:
            before = build_packet.compute_finding_id(
                result_at(start=5, end=5), repo, fixture_exclusions()
            )
        with temp_tree({"app/handler.py": FILE_AFTER}) as repo:
            after = build_packet.compute_finding_id(
                result_at(start=6, end=6), repo, fixture_exclusions()
            )
        self.assertEqual(before, after)

    def test_changing_the_fragment_changes_identity(self):
        with temp_tree({"app/handler.py": FILE_BEFORE}) as repo:
            original = build_packet.compute_finding_id(
                result_at(start=5, end=5), repo, fixture_exclusions()
            )
        edited = FILE_BEFORE.replace("exec(cmd)", "exec(shlex.quote(cmd))")
        with temp_tree({"app/handler.py": edited}) as repo:
            changed = build_packet.compute_finding_id(
                result_at(start=5, end=5), repo, fixture_exclusions()
            )
        self.assertNotEqual(original, changed)

    def test_identical_fragments_get_distinct_identities(self):
        text = "a = 1\nexec(cmd)\nb = 2\nexec(cmd)\n"
        with temp_tree({"app/handler.py": text}) as repo:
            first = build_packet.compute_finding_id(
                result_at(start=2, end=2), repo, fixture_exclusions()
            )
            second = build_packet.compute_finding_id(
                result_at(start=4, end=4), repo, fixture_exclusions()
            )
        self.assertNotEqual(first, second)

    def test_indentation_change_preserves_identity(self):
        with temp_tree({"app/handler.py": FILE_BEFORE}) as repo:
            original = build_packet.compute_finding_id(
                result_at(start=5, end=5), repo, fixture_exclusions()
            )
        reindented = FILE_BEFORE.replace("    exec(cmd)", "        exec(cmd)")
        with temp_tree({"app/handler.py": reindented}) as repo:
            same = build_packet.compute_finding_id(
                result_at(start=5, end=5), repo, fixture_exclusions()
            )
        self.assertEqual(original, same)

    def test_scanner_fingerprint_wins_and_needs_no_file(self):
        result = result_at(partialFingerprints={"semgrep.fingerprint": "abc123"})
        with temp_tree({}) as repo:
            fid = build_packet.compute_finding_id(result, repo, fixture_exclusions())
        self.assertTrue(fid.startswith("F-"))

    def test_fingerprint_key_choice_is_deterministic(self):
        a = build_packet.scanner_fingerprint(
            {"partialFingerprints": {"zeta": "1", "alpha": "2"}}
        )
        b = build_packet.scanner_fingerprint(
            {"partialFingerprints": {"alpha": "2", "zeta": "1"}}
        )
        self.assertEqual(a, b)

    def test_preferred_fingerprint_key_wins_over_alphabetical(self):
        fp = build_packet.scanner_fingerprint(
            {"partialFingerprints": {"aaa": "x", "primaryLocationLineHash": "y"}}
        )
        self.assertIn("primaryLocationLineHash", fp)

    def test_excluded_path_refuses_before_reading(self):
        with temp_tree({}) as repo:
            with self.assertRaises(check_scope.ScopeViolation):
                build_packet.compute_finding_id(
                    result_at(path="secrets/prod.env", start=1, end=1),
                    repo,
                    fixture_exclusions(),
                )

    def test_excluded_path_refuses_even_with_a_fingerprint(self):
        # The fingerprint path needs no file, so nothing would be leaked. It is
        # still refused: an id for a finding that can never become a packet is
        # a loose end, and the listing promises (no id) for excluded paths.
        with temp_tree({}) as repo:
            with self.assertRaises(check_scope.ScopeViolation):
                build_packet.compute_finding_id(
                    result_at(
                        path="secrets/prod.env",
                        start=1,
                        end=1,
                        partialFingerprints={"semgrep.fingerprint": "deadbeef"},
                    ),
                    repo,
                    fixture_exclusions(),
                )

    def test_empty_region_is_reported_clearly(self):
        with temp_tree({"app/handler.py": "\n\n\n"}) as repo:
            with self.assertRaises(ValueError):
                build_packet.compute_finding_id(
                    result_at(start=1, end=2), repo, fixture_exclusions()
                )

    def test_packet_records_the_identity_scheme(self):
        results = build_packet.load_sarif_results(SARIF)
        with temp_tree({"app/handler.py": FILE_BEFORE, "app/db.py": "q = f'{x}'\n"}) as repo:
            packet = build_packet.build_triage_packet(
                results[0], repo, 40, fixture_exclusions()
            )
        self.assertEqual(packet["id_scheme"], build_packet.ID_SCHEME)
```

- [ ] **Step 2: Прогнать**

Run: `python3 -m unittest tests.test_build_packet.TestFindingIdentity -v`
Expected: FAIL с `AttributeError: module 'build_packet' has no attribute 'compute_finding_id'`.

- [ ] **Step 3: Заменить генератор идентичности**

В `scripts/build_packet.py` заменить `finding_id` целиком:

```python
ID_SCHEME = "content-v1"

# Keys we trust first when a scanner emits several. Order is significance, not
# preference for its own sake: these are the ones scanners document as stable.
FINGERPRINT_PREFERENCE = ("primaryLocationLineHash", "semgrep.fingerprint")


def _digest(material: str) -> str:
    return f"F-{hashlib.sha256(material.encode()).hexdigest()[:12]}"


def scanner_fingerprint(result: dict) -> str | None:
    """The scanner's own stable identifier for this finding, when it emits one.

    SARIF 2.1.0 defines fingerprints and partialFingerprints for exactly this
    purpose, so preferring them means inheriting the scanner's notion of
    identity rather than inventing a competing one. Key selection is
    deterministic: a preferred key if present, otherwise the first in sorted
    order, so two runs over the same result always agree.
    """
    for container in ("fingerprints", "partialFingerprints"):
        prints = result.get(container)
        if not isinstance(prints, dict) or not prints:
            continue
        for key in FINGERPRINT_PREFERENCE:
            if key in prints:
                return f"{container}:{key}:{prints[key]}"
        key = sorted(prints)[0]
        return f"{container}:{key}:{prints[key]}"
    return None


def normalize_snippet(text: str) -> str:
    """Drop indentation and blank lines so reformatting does not reset identity."""
    stripped = (line.strip() for line in text.splitlines())
    return "\n".join(line for line in stripped if line)


def occurrence_index(file_text: str, start_line: int, end_line: int, target: str) -> int:
    """How many identical normalized snippets appear before this one.

    Without it, two identical fragments in one file would collapse into a
    single id. Stable under line shifts: inserting lines above moves the
    finding and its earlier duplicates by the same amount, so the count holds.
    """
    lines = file_text.splitlines()
    span = max(1, end_line - start_line + 1)
    count = 0
    for i in range(0, max(0, start_line - 1)):
        if normalize_snippet("\n".join(lines[i:i + span])) == target:
            count += 1
    return count


def compute_finding_id(
    result: dict, repo: Path, exclusions: list[dict] | None = None
) -> str:
    """Identity that survives edits elsewhere in the file.

    Guarantee: inserting or deleting lines above the finding does not change
    the id, so verdicts and SARIF suppressions survive ordinary refactoring.

    Non-guarantee, and deliberately so: editing the flagged fragment itself
    changes the id. Changed code deserves a fresh review.

    Known limitation: identity combines the fragment with how many identical
    fragments precede it, so reordering identical fragments within one file
    swaps their ids.

    Raises ScopeViolation for an excluded path, before either identity path
    runs. The content path would otherwise read a file the policy forbids, and
    the fingerprint path — which needs no file — would hand back an id for a
    finding that can never be turned into a packet. One rule for both keeps the
    control uniform and the listing honest.
    """
    rule_id = result["rule_id"]
    path = result["file"]

    check_path(path, exclusions)

    fingerprint = scanner_fingerprint(result)
    if fingerprint:
        return _digest(f"{rule_id}:{path}:{fingerprint}")

    target_file = repo / path
    if not target_file.exists():
        raise FileNotFoundError(
            f"Source file not found: {target_file}. Run the scan from the "
            "repository root."
        )

    text = target_file.read_text(encoding="utf-8", errors="replace")
    start, end = result["start_line"], result["end_line"]
    snippet = normalize_snippet("\n".join(text.splitlines()[start - 1:end]))
    if not snippet:
        raise ValueError(
            f"Cannot derive an identity for {path}:{start}-{end}: the flagged "
            "region is empty or whitespace only."
        )
    index = occurrence_index(text, start, end, snippet)
    return _digest(f"{rule_id}:{path}:{snippet}:{index}")
```

- [ ] **Step 4: Донести фингерпринты до потребителя**

`load_sarif_results` собирает собственный словарь и до сих пор отбрасывал оба
поля с фингерпринтами, поэтому предпочтительный источник идентичности не мог
сработать ни разу на реальном входе. Добавить в словарь, который собирает
`load_sarif_results` (`scripts/build_packet.py:59-75`), два ключа перед
`"code_flows"`:

```python
                    # Verbatim SARIF spelling: these are passed straight to
                    # scanner_fingerprint, and renaming them here would add a
                    # mapping layer whose only job is to be kept in sync.
                    "fingerprints": result.get("fingerprints") or {},
                    "partialFingerprints": result.get("partialFingerprints") or {},
```

И дописать в `TestFindingIdentity` два теста, закрывающих именно этот разрыв:

```python
    def test_fingerprints_survive_sarif_parsing(self):
        results = build_packet.load_sarif_results(SARIF)
        self.assertEqual(
            results[1]["partialFingerprints"],
            {"semgrep.fingerprint": "abc123def456"},
        )

    def test_real_sarif_input_uses_the_scanner_fingerprint(self):
        # An empty repository: the content path would raise FileNotFoundError,
        # so a returned id proves the fingerprint path actually ran on input
        # that came through load_sarif_results rather than a hand-built dict.
        results = build_packet.load_sarif_results(SARIF)
        with temp_tree({}) as repo:
            fid = build_packet.compute_finding_id(
                results[1], repo, fixture_exclusions()
            )
        self.assertTrue(fid.startswith("F-"))
```

- [ ] **Step 5: Переставить порядок в `build_triage_packet`**

Идентичность теперь читает файл, поэтому scope-check обязан идти раньше её вычисления. Заменить начало функции:

```python
def build_triage_packet(
    result: dict, repo: Path, window: int, exclusions: list[dict] | None = None
) -> dict:
    # Scope check before any file content is read, identity included. This
    # ordering is the point: compute_finding_id opens the source file.
    if exclusions is None:
        exclusions, _ = load_policy()
    candidates = [result["file"]] + [
        step["file"] for flow in result["code_flows"] for step in flow["steps"]
    ]
    for path in candidates:
        if path:
            check_path(path, exclusions)

    fid = compute_finding_id(result, repo, exclusions)
```

Удалить прежнюю строку `fid = finding_id(...)` из начала функции.

В возвращаемом словаре добавить поле сразу после `finding_id`:

```python
        "id_scheme": ID_SCHEME,
```

- [ ] **Step 6: Поправить список находок**

В `main` список больше не может считать id для исключённых путей — это означало бы чтение запрещённого файла. Заменить блок `if args.list or args.index is None:`:

```python
    if args.list or args.index is None:
        exclusions, _ = load_policy()
        print(f"{len(results)} finding(s):\n")
        for i, r in enumerate(results):
            try:
                fid = compute_finding_id(r, args.repo, exclusions)
            except (ScopeViolation, FileNotFoundError, ValueError):
                # Out of scope, absent, or unidentifiable. Never read a file the
                # policy excludes just to print a label for it.
                fid = None
            flag = "" if _in_scope(r["file"], exclusions) else "  [OUT OF SCOPE]"
            label = fid or "(no id)"
            print(f"  [{i:>3}] {label}  {r['level']:<8} {r['file']}:{r['start_line']}{flag}")
            print(f"        {r['rule_id']}")
        print("\nBuild a packet with: make triage N=<index>")
        return 0
```

И расширить `_in_scope`:

```python
def _in_scope(path: str, exclusions: list[dict] | None = None) -> bool:
    try:
        check_path(path, exclusions)
        return True
    except ScopeViolation:
        return False
```

- [ ] **Step 7: Прогнать**

Run: `make test`
Expected: всё зелёное.

- [ ] **Step 8: Проверить вручную**

Run: `python3 scripts/build_packet.py --sarif tests/fixtures/sample.sarif --list`
Expected: три находки, по одной на каждый путь идентичности. `app/db.py` несёт фингерпринт и получает id, не читая файла. `app/handler.py` идёт по содержимому, файла в рабочем каталоге нет, поэтому `(no id)`. `config/server.pem` помечена `[OUT OF SCOPE]` и тоже без id.

Эта проверка идёт против **живой** `policy/excluded-paths.yml`, а не против фикстуры, поэтому исключённый путь в фикстурном SARIF обязан подпадать под обе политики. Фикстура намеренно независима от живой политики (слой 0), и единственное место, где границы пересекаются, — вот эта ручная проверка.

- [ ] **Step 9: Коммит**

```bash
git add scripts/build_packet.py tests/test_build_packet.py
git commit -m "fix: derive finding identity from content so it survives line shifts"
```

**Слой 1 завершён.**

---

# Слой 2 — контракт независимости

### Task 12: Идентификаторы моделей от человека и отказ при совпадении

**Files:**
- Modify: `scripts/record_verdict.py:272-330`
- Modify: `Makefile`
- Modify: `tests/test_record_verdict.py`
- Modify: `docs/superpowers/evidence/2026-09-01-red-tests.md`
- Modify: `docs/superpowers/evidence/2026-09-01-plan-fixes.md`

**Interfaces:**
- Consumes: `record_verdict.main`.
- Produces: обязательный `--agent`, условно обязательный `--validator`. Задача 13 добавляет колонки самоотчёта.

- [ ] **Step 1: Написать падающий тест**

Тест вызывает `main` через `subprocess`, потому что предмет проверки — код возврата и отсутствие записи. Дописать в `tests/test_record_verdict.py`:

```python
class TestIndependenceControl(unittest.TestCase):
    """docs/04 calls independence the mechanism. A warning is not a mechanism."""

    def run_recorder(self, args, cwd):
        return subprocess.run(
            [sys.executable, str(REPO_ROOT / "scripts" / "record_verdict.py"), *args],
            capture_output=True,
            text=True,
            cwd=str(cwd),
        )

    def setup_files(self, root):
        verdict = make_verdict(severity="low", evidence_level="partial")
        challenge = make_challenge("upheld")
        (root / "verdict.json").write_text(json.dumps(verdict), encoding="utf-8")
        (root / "challenge.json").write_text(json.dumps(challenge), encoding="utf-8")

    def test_same_model_is_refused_and_writes_nothing(self):
        with temp_tree({"placeholder": ""}) as root:
            self.setup_files(root)
            log = root / "triage-log.csv"
            sarif = root / "reviewed.sarif"
            proc = self.run_recorder(
                [
                    "--verdict", str(root / "verdict.json"),
                    "--challenge", str(root / "challenge.json"),
                    "--agent", "model-a",
                    "--validator", "model-a",
                    "--sarif-out", str(sarif),
                    "--log", str(log),
                ],
                root,
            )
            # Absence is asserted INSIDE the block. temp_tree deletes the whole
            # tree on exit, so exists() afterwards is False no matter what the
            # process did, and the assertion could never fail.
            self.assertFalse(log.exists(), "a refused run must not write the log")
            self.assertFalse(sarif.exists(), "a refused run must not write SARIF")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("REFUSED", proc.stderr)

    def test_missing_agent_is_refused(self):
        with temp_tree({"placeholder": ""}) as root:
            self.setup_files(root)
            proc = self.run_recorder(["--verdict", str(root / "verdict.json")], root)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("--agent", proc.stderr)

    def test_challenge_without_validator_is_refused(self):
        with temp_tree({"placeholder": ""}) as root:
            self.setup_files(root)
            proc = self.run_recorder(
                [
                    "--verdict", str(root / "verdict.json"),
                    "--challenge", str(root / "challenge.json"),
                    "--agent", "model-a",
                ],
                root,
            )
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("--validator", proc.stderr)

    def test_fresh_discards_the_existing_sarif(self):
        # Deferred from Task 8: --fresh is only observable through the CLI, and
        # the recorder's argument set settles in this task.
        with temp_tree({"placeholder": ""}) as root:
            self.setup_files(root)
            sarif = root / "reviewed.sarif"
            stale = record_verdict.build_result(
                make_verdict(finding_id="F-stale"), None, "confirmed", "old"
            )
            sarif.write_text(
                json.dumps(record_verdict.sarif_document([stale])), encoding="utf-8"
            )
            proc = self.run_recorder(
                [
                    "--verdict", str(root / "verdict.json"),
                    "--agent", "model-a",
                    "--sarif-out", str(sarif),
                    "--log", str(root / "triage-log.csv"),
                    "--fresh",
                ],
                root,
            )
            ids = [
                r["properties"]["finding_id"]
                for r in record_verdict.load_existing_results(sarif)
            ]
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertNotIn("F-stale", ids)

    def test_single_model_run_without_challenge_is_accepted(self):
        # severity=low needs no challenge, so one model is legitimate here.
        with temp_tree({"placeholder": ""}) as root:
            self.setup_files(root)
            proc = self.run_recorder(
                [
                    "--verdict", str(root / "verdict.json"),
                    "--agent", "model-a",
                    "--sarif-out", str(root / "reviewed.sarif"),
                    "--log", str(root / "triage-log.csv"),
                ],
                root,
            )
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_malformed_sarif_refuses_before_touching_the_log(self):
        # Deferred from Task 8 alongside the --fresh test. Regression for the
        # ordering requirement: the log is append-only, so a row written ahead
        # of a SARIF failure could never be withdrawn.
        with temp_tree({"placeholder": ""}) as root:
            self.setup_files(root)
            log = root / "triage-log.csv"
            sarif = root / "reviewed.sarif"
            sarif.write_text("{ not json", encoding="utf-8")
            proc = self.run_recorder(
                [
                    "--verdict", str(root / "verdict.json"),
                    "--agent", "model-a",
                    "--sarif-out", str(sarif),
                    "--log", str(log),
                ],
                root,
            )
            # Inside the block: see the note in test_same_model_is_refused.
            self.assertFalse(log.exists(), "a refused run must not create the log")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("SARIF ERROR", proc.stderr)

    def test_distinct_models_are_accepted(self):
        with temp_tree({"placeholder": ""}) as root:
            self.setup_files(root)
            proc = self.run_recorder(
                [
                    "--verdict", str(root / "verdict.json"),
                    "--challenge", str(root / "challenge.json"),
                    "--agent", "model-a",
                    "--validator", "model-b",
                    "--sarif-out", str(root / "reviewed.sarif"),
                    "--log", str(root / "triage-log.csv"),
                ],
                root,
            )
        self.assertEqual(proc.returncode, 0, proc.stderr)
```

Добавить в шапку файла: `import subprocess`, `import sys`, `from tests import REPO_ROOT`.

- [ ] **Step 2: Прогнать**

Run: `python3 -m unittest tests.test_record_verdict.TestIndependenceControl -v`
Expected: FAIL — `--agent` и `--log` пока не существуют.

- [ ] **Step 3: Добавить аргументы**

В `main` рядом с остальными:

```python
    parser.add_argument("--agent", required=True,
                        help="Model identifier for the triage pass, supplied by the engineer")
    parser.add_argument("--validator",
                        help="Model identifier for the validation pass; required with --challenge")
    parser.add_argument("--log", type=Path, default=LOG_PATH,
                        help="Triage log to append to")
```

- [ ] **Step 4: Поставить контроль до любых записей**

Сразу после `args = parser.parse_args()`:

```python
    if args.challenge and not args.validator:
        parser.error("--validator is required when --challenge is given")

    if args.validator and args.agent == args.validator:
        print("REFUSED: triage and validation ran on the same model.\n", file=sys.stderr)
        print(f"  agent:     {args.agent}", file=sys.stderr)
        print(f"  validator: {args.validator}\n", file=sys.stderr)
        print(
            "Independence is the mechanism, not a preference. A second pass on the\n"
            "same model inherits the same blind spots and produces agreement rather\n"
            "than validation. Nothing was written.",
            file=sys.stderr,
        )
        return 2
```

- [ ] **Step 5: Заменить прежнее предупреждение сверкой самоотчёта**

Удалить блок, сравнивающий `verdict["reviewer"]["agent"]` с `challenge["validator"]["agent"]`, и поставить на его место:

```python
    # The model fills reviewer.agent in its own output, and models are
    # unreliable about their own identity. The engineer's value is authoritative;
    # a mismatch is worth surfacing but is not grounds to refuse.
    self_reported = verdict.get("reviewer", {}).get("agent", "")
    if self_reported and self_reported != args.agent:
        print(
            f"WARNING: verdict self-reports agent {self_reported!r}, engineer "
            f"supplied {args.agent!r}.\n",
            file=sys.stderr,
        )
    if challenge:
        validator_self = challenge.get("validator", {}).get("agent", "")
        if validator_self and validator_self != args.validator:
            print(
                f"WARNING: challenge self-reports validator {validator_self!r}, "
                f"engineer supplied {args.validator!r}.\n",
                file=sys.stderr,
            )
        if challenge.get("challenge_result") == "upheld" and not challenge.get(
            "refutation_attempts"
        ):
            print("WARNING: 'upheld' with no recorded refutation attempts is "
                  "agreement, not validation.\n", file=sys.stderr)
```

Заменить в `append_log` и в вызове использование `LOG_PATH` на `args.log`: сделать `append_log(row, path)` с параметром и передавать `args.log`.

```python
def append_log(row: dict, path: Path = LOG_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    exists = path.exists()
    with path.open("a", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=LOG_FIELDS)
        if not exists:
            writer.writeheader()
        writer.writerow({k: row.get(k, "") for k in LOG_FIELDS})
```

И в конце `main` заменить печать пути на `args.log`.

- [ ] **Step 6: Обновить Makefile**

```make
record:
	@test -n "$(ID)" || (echo "Set ID=<finding-id>" && exit 1)
	@test -n "$(AGENT)" || (echo "Set AGENT=<model that ran triage>" && exit 1)
	@python3 scripts/record_verdict.py \
		--verdict findings/verdicts/$(ID).json \
		--agent "$(AGENT)" \
		$(if $(VALIDATOR),--validator "$(VALIDATOR)",) \
		$(if $(wildcard findings/challenges/$(ID).json),--challenge findings/challenges/$(ID).json,) \
		$(if $(MINUTES),--minutes $(MINUTES),)
```

И в блоке `help` заменить строку записи:

```make
	@echo "  make record ID=F-abc AGENT=<model> VALIDATOR=<model> MINUTES=12"
```

- [ ] **Step 7: Прогнать**

Run: `make test`
Expected: всё зелёное.

- [ ] **Step 8: Коммит**

```bash
git add scripts/record_verdict.py tests/test_record_verdict.py Makefile
git commit -m "feat: refuse same-model validation instead of warning about it"
```

---

### Task 13: Рост лога и проверка совместимости

**Files:**
- Modify: `scripts/record_verdict.py:33-51`, `:192-200`, `:326-352`
- Modify: `tests/test_record_verdict.py`
- Modify: `docs/superpowers/evidence/2026-09-01-red-tests.md`
- Modify: `docs/superpowers/evidence/2026-09-01-plan-fixes.md`

**Interfaces:**
- Consumes: `build_packet.ID_SCHEME`.
- Produces: `record_verdict.check_log_compatible(path: Path, id_scheme: str) -> None`. Колонки `agent_self_reported`, `validator_self_reported`, `id_scheme`. Задачи 17 и 18 дополняют `LOG_FIELDS` тем же механизмом.

- [ ] **Step 1: Написать падающий тест**

```python
class TestLogCompatibility(unittest.TestCase):
    """csv.DictWriter appends happily under a stale header, misaligning every
    column. A silently corrupted audit trail is worse than a refusal."""

    def test_absent_log_is_fine(self):
        with temp_tree({}) as root:
            record_verdict.check_log_compatible(root / "triage-log.csv", "content-v1")

    def test_stale_header_is_refused(self):
        with temp_tree({"triage-log.csv": "reviewed_at,finding_id\n2026-01-01,F-1\n"}) as root:
            with self.assertRaises(record_verdict.ValidationError) as ctx:
                record_verdict.check_log_compatible(root / "triage-log.csv", "content-v1")
            self.assertIn("missing columns", str(ctx.exception))

    def test_current_header_is_accepted(self):
        with temp_tree({}) as root:
            log = root / "triage-log.csv"
            write_log(log, [])
            record_verdict.check_log_compatible(log, "content-v1")

    def test_foreign_id_scheme_is_refused(self):
        with temp_tree({}) as root:
            log = root / "triage-log.csv"
            write_log(log, [{"finding_id": "F-1", "id_scheme": "line-v0"}])
            with self.assertRaises(record_verdict.ValidationError) as ctx:
                record_verdict.check_log_compatible(log, "content-v1")
            self.assertIn("line-v0", str(ctx.exception))

    def test_log_carries_self_reported_columns(self):
        self.assertIn("agent_self_reported", record_verdict.LOG_FIELDS)
        self.assertIn("validator_self_reported", record_verdict.LOG_FIELDS)
        self.assertIn("id_scheme", record_verdict.LOG_FIELDS)

    def test_empty_log_file_still_gets_a_header(self):
        # A zero-byte file exists but is not yet a log: an interrupted write or
        # a stray touch leaves one behind. Appending without a header would put
        # a data row where csv.DictReader expects column names, and every
        # column would silently take its name from the first finding.
        with temp_tree({"triage-log.csv": ""}) as root:
            log = root / "triage-log.csv"
            record_verdict.check_log_compatible(log, "content-v1")
            record_verdict.append_log({"finding_id": "F-1"}, log)
            with log.open(encoding="utf-8", newline="") as fh:
                first_line = next(csv.reader(fh))
        self.assertEqual(first_line, record_verdict.LOG_FIELDS)
```

Добавить `import csv` и `from tests.helpers import write_log` в шапку.

- [ ] **Step 2: Прогнать**

Run: `python3 -m unittest tests.test_record_verdict.TestLogCompatibility -v`
Expected: FAIL — `check_log_compatible` отсутствует.

- [ ] **Step 3: Расширить набор колонок**

В `scripts/record_verdict.py` заменить `LOG_FIELDS`:

```python
LOG_FIELDS = [
    "reviewed_at", "finding_id", "id_scheme", "rule_id", "file", "line",
    "severity", "priority_class", "evidence_level", "confidence",
    "initial_verdict", "challenge_result", "final_state",
    "minutes_spent", "requires_runtime_proof",
    "agent", "validator",
    "agent_self_reported", "validator_self_reported",
    "notes",
]
```

И импортировать схему идентичности рядом с существующими импортами, по образцу `build_packet.py`:

```python
sys.path.insert(0, str(Path(__file__).resolve().parent))
from build_packet import ID_SCHEME  # noqa: E402
```

- [ ] **Step 4: Добавить проверку совместимости**

Сначала закрыть расхождение между двумя функциями. `append_log` решает, писать
ли заголовок, по факту существования файла, а `check_log_compatible` считает файл
без заголовка не требующим проверки. Пустой файл проваливается в щель между ними.
Заменить `append_log`:

```python
def append_log(row: dict, path: Path = LOG_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    # Key the header on content, not on existence. A file that exists but is
    # empty is not a log yet, and appending to it without a header would put a
    # data row in the header position, where csv.DictReader would read it as
    # the column names and corrupt every row that follows.
    has_header = path.exists() and path.stat().st_size > 0
    with path.open("a", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=LOG_FIELDS)
        if not has_header:
            writer.writeheader()
        writer.writerow({k: row.get(k, "") for k in LOG_FIELDS})
```

Затем добавить саму проверку:

```python
def check_log_compatible(path: Path, id_scheme: str) -> None:
    """Refuse to append to a log whose shape or identity scheme differs.

    Two separate hazards. A stale header means csv.DictWriter writes new rows
    under old column names and every field lands in the wrong place. A foreign
    id_scheme means the same finding carries a different id in older rows, so
    metrics would count one finding as two and nobody would notice.
    """
    if not path.exists():
        return

    with path.open(encoding="utf-8", newline="") as fh:
        reader = csv.reader(fh)
        header = next(reader, None)
        if header is None:
            # Empty file: nothing to compare against, and append_log will lay
            # down the header on the next write. The two functions have to
            # agree about what an empty file means, or a row lands where the
            # header belongs.
            return
        schemes = set()
        if "id_scheme" in header:
            column = header.index("id_scheme")
            for row in reader:
                if len(row) > column and row[column]:
                    schemes.add(row[column])

    if header != LOG_FIELDS:
        missing = [f for f in LOG_FIELDS if f not in header] or ["none"]
        extra = [f for f in header if f not in LOG_FIELDS] or ["none"]
        raise ValidationError(
            f"{path} has an incompatible header.\n"
            f"  missing columns: {', '.join(missing)}\n"
            f"  unexpected columns: {', '.join(extra)}\n"
            "Archive the existing findings/ directory, or migrate the log, "
            "before recording new verdicts."
        )

    foreign = sorted(s for s in schemes if s != id_scheme)
    if foreign:
        raise ValidationError(
            f"{path} contains rows written under identity scheme(s) "
            f"{', '.join(foreign)}, but this run uses {id_scheme}.\n"
            "The same finding carries a different id under each scheme, so the "
            "two cannot share a log. Archive findings/ and re-triage."
        )
```

- [ ] **Step 5: Вызвать проверку и заполнить колонки**

В `main`, сразу после проверки независимости:

```python
    try:
        check_log_compatible(args.log, ID_SCHEME)
    except ValidationError as exc:
        print(f"LOG ERROR: {exc}", file=sys.stderr)
        return 1
```

В словаре `append_log` заменить строки про агентов и добавить схему:

```python
            "id_scheme": ID_SCHEME,
            ...
            "agent": args.agent,
            "validator": args.validator or "",
            "agent_self_reported": verdict.get("reviewer", {}).get("agent", ""),
            "validator_self_reported": (challenge or {}).get("validator", {}).get("agent", ""),
```

И передать путь: `append_log({...}, args.log)`.

В `build_result` добавить в `properties`:

```python
            "id_scheme": ID_SCHEME,
```

- [ ] **Step 6: Обновить тест метрик под авторитетные колонки**

В `tests/test_metrics.py` тест `test_same_model_validations_are_counted` продолжает работать: `metrics.py` читает колонки `agent` и `validator`, которые теперь заполняются из CLI. Изменений не требуется — убедитесь прогоном.

- [ ] **Step 7: Прогнать**

Run: `make test`
Expected: всё зелёное.

- [ ] **Step 8: Коммит**

```bash
git add scripts/record_verdict.py tests/test_record_verdict.py
git commit -m "feat: record authoritative and self-reported model ids; guard log shape"
```

**Слой 2 завершён.**

---

# Слой 3 — egress

### Task 14: Офлайн-правила по умолчанию

**Files:**
- Modify: `scripts/scan.sh`
- Create: `rules/README.md`
- Create: `tests/test_scan_sh.py`
- Modify: `docs/03-data-handling.md`
- Modify: `docs/superpowers/evidence/2026-09-01-red-tests.md`
- Modify: `docs/superpowers/evidence/2026-09-01-plan-fixes.md`

**Interfaces:**
- Consumes: ничего.
- Produces: `SEMGREP_CONFIG` как единственный способ выйти в сеть.

- [ ] **Step 1: Написать падающий тест**

`tests/test_scan_sh.py`:

```python
"""Tests for the scanner entry point.

The refusal path must work without semgrep installed, which is why rule
resolution happens before semgrep is invoked.
"""

import subprocess
import unittest
from pathlib import Path

from tests import REPO_ROOT
from tests.helpers import temp_tree

SCAN = REPO_ROOT / "scripts" / "scan.sh"


class TestScanScript(unittest.TestCase):
    def run_scan(self, repo, env_config, bindir=None):
        # A stripped PATH is not a guarantee that semgrep is absent: package
        # managers do put it in /usr/bin. Tests that exercise the registry
        # branch must supply a stand-in on PATH, or they can reach the network.
        path = f"{bindir}:/usr/bin:/bin" if bindir else "/usr/bin:/bin"
        env = {"PATH": path, "SEMGREP_CONFIG": env_config}
        return subprocess.run(
            ["/bin/sh", str(SCAN), str(repo)],
            capture_output=True,
            text=True,
            cwd=str(repo),
            env=env,
        )

    def make_fake_semgrep(self, bindir: Path) -> Path:
        """Install a stand-in that records its arguments and exits 42.

        Returns the path it writes those arguments to. The distinctive exit
        code proves the stand-in is what ran, rather than a real semgrep found
        elsewhere on PATH or a silent failure that happens to look similar.
        """
        bindir.mkdir(parents=True, exist_ok=True)
        args_file = bindir / "args.txt"
        fake = bindir / "semgrep"
        fake.write_text(
            "#!/bin/sh\n"
            f'printf "%s\\n" "$@" > "{args_file}"\n'
            "exit 42\n",
            encoding="utf-8",
        )
        fake.chmod(0o755)
        return args_file

    def test_empty_rules_directory_refuses(self):
        with temp_tree({"rules/README.md": "placeholder\n"}) as root:
            proc = self.run_scan(root, str(root / "rules"))
        self.assertEqual(proc.returncode, 2)
        self.assertIn("REFUSED", proc.stderr)
        self.assertIn("SEMGREP_CONFIG", proc.stderr)

    def test_missing_rules_directory_refuses(self):
        with temp_tree({"placeholder": ""}) as root:
            proc = self.run_scan(root, str(root / "absent"))
        self.assertEqual(proc.returncode, 2)
        self.assertIn("REFUSED", proc.stderr)

    def test_refusal_leaves_no_state_behind(self):
        with temp_tree({"rules/README.md": "placeholder\n"}) as root:
            self.run_scan(root, str(root / "rules"))
            self.assertFalse((root / "findings").exists())

    def test_local_rules_pass_metrics_off_and_the_local_config(self):
        with temp_tree({"rules/x.yaml": "rules: []\n"}) as root:
            args_file = self.make_fake_semgrep(root / "bin")
            proc = self.run_scan(root, str(root / "rules"), bindir=root / "bin")
            recorded = args_file.read_text(encoding="utf-8").split("\n")
        self.assertEqual(proc.returncode, 42, "the stand-in must be what ran")
        self.assertIn("--metrics=off", recorded)
        self.assertIn(str(root / "rules"), recorded)
        self.assertNotIn("NETWORK", proc.stderr)

    def test_registry_config_announces_egress_and_still_disables_telemetry(self):
        with temp_tree({"placeholder": ""}) as root:
            args_file = self.make_fake_semgrep(root / "bin")
            proc = self.run_scan(root, "p/security-audit", bindir=root / "bin")
            recorded = args_file.read_text(encoding="utf-8").split("\n")
        self.assertEqual(proc.returncode, 42, "the stand-in must be what ran")
        self.assertIn("NETWORK", proc.stderr)
        self.assertIn("docs/03-data-handling.md", proc.stderr)
        self.assertIn("--metrics=off", recorded)
        self.assertIn("p/security-audit", recorded)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Прогнать**

Run: `python3 -m unittest tests.test_scan_sh -v`
Expected: FAIL — скрипт сейчас сразу зовёт semgrep с `--config auto`.

- [ ] **Step 3: Переписать `scan.sh`**

```sh
#!/usr/bin/env sh
set -eu

# Rules come from a local directory by default. docs/03-data-handling.md
# claims exactly one channel out of the perimeter — the review packet — and
# `--config auto` quietly opened a second one by fetching rules from the
# Semgrep registry and reporting telemetry. Going to the registry is still
# possible, but it is now a decision someone makes out loud.

repo="${1:-.}"
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
config="${SEMGREP_CONFIG:-$root/rules}"

# Resolution happens before semgrep is invoked so the refusal path works on a
# machine without semgrep, and so it can be tested there too. Nothing is
# created on disk until the configuration is known to be usable: a refusal
# that leaves state behind is not a clean refusal.
case "$config" in
  p/*|r/*|https://*)
    printf 'NETWORK: fetching rules from the Semgrep registry (%s).\n' "$config" >&2
    printf 'This is a second channel out of the perimeter.\n' >&2
    printf 'See docs/03-data-handling.md.\n\n' >&2
    ;;
  *)
    if [ ! -d "$config" ] || [ -z "$(ls -A "$config" 2>/dev/null | grep -v '^README.md$' || true)" ]; then
      printf 'REFUSED: no local rules in %s\n\n' "$config" >&2
      printf 'Add Semgrep rule files for this repository, or opt into the\n' >&2
      printf 'registry explicitly:\n\n' >&2
      printf '    SEMGREP_CONFIG=p/security-audit make scan REPO=%s\n\n' "$repo" >&2
      printf 'docs/03-data-handling.md explains why the default is offline.\n' >&2
      exit 2
    fi
    ;;
esac

mkdir -p findings

printf 'Rules:  %s\n' "$config"
printf 'Target: %s\n\n' "$repo"

semgrep scan --config "$config" --metrics=off --sarif \
  --output findings/raw.sarif "$repo"
```

- [ ] **Step 4: Создать каталог правил**

`rules/README.md`:

```markdown
# Local Semgrep rules

`scan.sh` reads rules from this directory by default. It is empty on purpose:
a rule set is specific to the languages and frameworks of the repository under
review, and shipping someone else's is worse than shipping none.

Populate it with `.yaml` rule files before the first scan.

To use the Semgrep registry instead, opt in explicitly:

    SEMGREP_CONFIG=p/security-audit make scan REPO=../myapp

That reaches the network, which is a second channel out of the perimeter.
`docs/03-data-handling.md` explains what that means and when it is acceptable.
```

- [ ] **Step 5: Задокументировать канал**

В `docs/03-data-handling.md`, сразу после раздела «The one channel», вставить:

```markdown
## The scanner is also a channel

`semgrep --config auto`, the previous default, fetched rules from the Semgrep
registry and reported telemetry on every run. That was a second path out of the
perimeter, undocumented and not covered by `check_scope.py`.

The default is now a local rule directory, `rules/`, and telemetry is disabled
unconditionally. `scan.sh` refuses to run against an empty `rules/` rather than
silently falling back to the network.

Reaching the registry is still supported and sometimes correct, but it is
explicit:

```bash
SEMGREP_CONFIG=p/security-audit make scan REPO=../myapp
```

That prints a banner naming the egress before it happens. What leaves the
perimeter on that path is the rule request itself, not your source; the source
still leaves only in a review packet.
```

- [ ] **Step 6: Прогнать**

Run: `make test`
Expected: всё зелёное.

- [ ] **Step 7: Коммит**

```bash
git add scripts/scan.sh rules tests/test_scan_sh.py docs/03-data-handling.md
git commit -m "fix: default the scanner to local rules and disable telemetry"
```

**Слой 3 завершён.**

---

# Слой 4 — очередь триажа

### Task 15: Фильтры списка находок

**Files:**
- Modify: `scripts/check_scope.py`
- Modify: `scripts/build_packet.py:200-280`
- Modify: `tests/test_build_packet.py`

**Interfaces:**
- Consumes: `build_packet.compute_finding_id`, `build_packet._in_scope`.
- Produces: `check_scope.matches(path: str, pattern: str) -> bool`; `build_packet.LEVEL_ORDER: dict[str, int]`, `build_packet.annotate(results, repo, exclusions) -> list[dict]`, `build_packet.apply_filters(items, levels=None, rule=None, path_glob=None, reviewed_ids=None, limit=None) -> list[dict]`, `build_packet.reviewed_finding_ids(verdict_dir: Path) -> set[str]`. Задача 16 адресует находки по id из этих же структур.

- [ ] **Step 1: Открыть матчер**

`apply_filters` нуждается в том же глоб-матчере, что и политика. Импортировать приватное имя было бы хрупко. В `scripts/check_scope.py` дописать после `_matches`:

```python
def matches(path: str, pattern: str) -> bool:
    """Public entry point for the policy's glob matcher.

    Exposed so the triage queue can filter paths with exactly the semantics the
    exclusion policy uses, rather than growing a second, subtly different one.
    """
    return _matches(path, pattern)
```

- [ ] **Step 2: Написать падающие тесты**

Дописать в `tests/test_build_packet.py`, добавив в шапку `import json`, `import subprocess`, `import sys` и `from tests import REPO_ROOT`:

```python
class TestTriageQueue(unittest.TestCase):
    def items(self):
        results = build_packet.load_sarif_results(SARIF)
        # Annotate without a repo so ids come back None; the filters under test
        # do not depend on identity except through reviewed_ids.
        with temp_tree({}) as repo:
            return build_packet.annotate(results, repo, fixture_exclusions())

    def test_level_filter(self):
        out = build_packet.apply_filters(self.items(), levels=["error"])
        self.assertEqual([i["level"] for i in out], ["error"])

    def test_level_filter_accepts_several(self):
        out = build_packet.apply_filters(self.items(), levels=["error", "note"])
        self.assertEqual(len(out), 2)

    def test_rule_substring_filter(self):
        out = build_packet.apply_filters(self.items(), rule="injection")
        self.assertEqual(len(out), 1)
        self.assertIn("injection", out[0]["rule_id"])

    def test_path_glob_filter(self):
        out = build_packet.apply_filters(self.items(), path_glob="app/*.py")
        self.assertEqual({i["file"] for i in out}, {"app/handler.py", "app/db.py"})

    def test_filters_combine(self):
        out = build_packet.apply_filters(
            self.items(), levels=["error", "warning"], path_glob="app/*.py", limit=1
        )
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["level"], "error")

    def test_sort_is_deterministic_and_severity_first(self):
        out = build_packet.apply_filters(self.items())
        self.assertEqual([i["level"] for i in out], ["error", "warning", "note"])

    def test_unreviewed_filter_hides_findings_with_verdicts(self):
        items = self.items()
        items[0]["finding_id"] = "F-aaaaaaaaaaaa"
        items[1]["finding_id"] = "F-bbbbbbbbbbbb"
        out = build_packet.apply_filters(items, reviewed_ids={"F-aaaaaaaaaaaa"})
        self.assertNotIn("F-aaaaaaaaaaaa", [i["finding_id"] for i in out])

    def test_reviewed_ids_are_read_from_verdict_filenames(self):
        with temp_tree(
            {"verdicts/F-aaaaaaaaaaaa.json": "{}", "verdicts/F-bbbbbbbbbbbb.json": "{}"}
        ) as root:
            found = build_packet.reviewed_finding_ids(root / "verdicts")
        self.assertEqual(found, {"F-aaaaaaaaaaaa", "F-bbbbbbbbbbbb"})

    def test_absent_verdict_directory_is_empty_not_an_error(self):
        with temp_tree({}) as root:
            self.assertEqual(build_packet.reviewed_finding_ids(root / "nope"), set())

    def test_json_output_is_machine_readable(self):
        proc = subprocess.run(
            [
                sys.executable,
                str(REPO_ROOT / "scripts" / "build_packet.py"),
                "--sarif", str(SARIF), "--list", "--json",
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(len(payload), 3)
        for item in payload:
            self.assertIn("finding_id", item)
            self.assertIn("in_scope", item)
            self.assertIn("level", item)
            self.assertIn("rule_id", item)
```

- [ ] **Step 3: Прогнать**

Run: `python3 -m unittest tests.test_build_packet.TestTriageQueue -v`
Expected: FAIL — `annotate` отсутствует.

- [ ] **Step 4: Реализовать очередь**

В `scripts/build_packet.py` добавить перед `def main`:

```python
# error first, because that is the order a reviewer wants to work in.
LEVEL_ORDER = {"error": 0, "warning": 1, "note": 2, "none": 3}


def annotate(results: list[dict], repo: Path, exclusions: list[dict]) -> list[dict]:
    """Attach identity and scope status to each result."""
    annotated = []
    for result in results:
        item = dict(result)
        try:
            item["finding_id"] = compute_finding_id(result, repo, exclusions)
        except (ScopeViolation, FileNotFoundError, ValueError):
            # Excluded, absent, or unidentifiable. Never read an excluded file
            # just to print a label for it.
            item["finding_id"] = None
        item["in_scope"] = _in_scope(result["file"], exclusions)
        annotated.append(item)
    return annotated


def reviewed_finding_ids(verdict_dir: Path) -> set[str]:
    """Ids that already have a verdict on disk, taken from filenames."""
    if not verdict_dir.exists():
        return set()
    return {path.stem for path in verdict_dir.glob("*.json")}


def apply_filters(
    items: list[dict],
    levels: list[str] | None = None,
    rule: str | None = None,
    path_glob: str | None = None,
    reviewed_ids: set[str] | None = None,
    limit: int | None = None,
) -> list[dict]:
    """Narrow the queue using what the SARIF actually carries.

    Filtering is on scanner `level`, rule id and path — never on policy
    severity or priority class. Those are assigned by the agent during triage
    and do not exist yet at listing time; mapping SARIF levels onto them here
    would manufacture a confidence nobody earned.
    """
    out = list(items)
    if levels:
        wanted = {level.strip().lower() for level in levels if level.strip()}
        out = [i for i in out if i["level"].lower() in wanted]
    if rule:
        out = [i for i in out if rule.lower() in i["rule_id"].lower()]
    if path_glob:
        out = [i for i in out if check_scope_matches(i["file"], path_glob)]
    if reviewed_ids is not None:
        out = [i for i in out if i["finding_id"] not in reviewed_ids]
    out.sort(
        key=lambda i: (LEVEL_ORDER.get(i["level"].lower(), 9), i["file"], i["start_line"])
    )
    if limit is not None:
        out = out[:limit]
    return out
```

И расширить импорт в шапке файла:

```python
from check_scope import (  # noqa: E402
    ScopeViolation,
    check_path,
    load_policy,
    matches as check_scope_matches,
)
```

- [ ] **Step 5: Подключить к CLI**

Добавить аргументы в `main`:

```python
    parser.add_argument("--level", help="Comma-separated SARIF levels, e.g. error,warning")
    parser.add_argument("--rule", help="Substring match on the rule id")
    parser.add_argument("--path", dest="path_glob", help="Glob on the file path")
    parser.add_argument("--unreviewed", action="store_true",
                        help="Hide findings that already have a verdict on disk")
    parser.add_argument("--limit", type=int, help="Show at most N findings")
    parser.add_argument("--json", dest="as_json", action="store_true",
                        help="Machine-readable output")
    parser.add_argument("--verdicts", type=Path,
                        default=REPO_ROOT / "findings" / "verdicts",
                        help="Where recorded verdicts live, for --unreviewed")
```

Заменить блок листинга целиком:

```python
    if args.list or args.index is None:
        exclusions, _ = load_policy()
        items = annotate(results, args.repo, exclusions)
        shown = apply_filters(
            items,
            levels=args.level.split(",") if args.level else None,
            rule=args.rule,
            path_glob=args.path_glob,
            reviewed_ids=reviewed_finding_ids(args.verdicts) if args.unreviewed else None,
            limit=args.limit,
        )

        if args.as_json:
            print(json.dumps(shown, indent=2))
            return 0

        # "already reviewed" must be a subset of what this SARIF contains.
        # Counting every file in the verdict directory would fold in findings
        # from other scans and report a number nobody can reconcile.
        on_disk = reviewed_finding_ids(args.verdicts)
        present = {i["finding_id"] for i in items if i["finding_id"]}
        reviewed = len(present & on_disk)
        print(f"{len(results)} finding(s) in SARIF, {reviewed} already reviewed, "
              f"{len(shown)} shown\n")
        for i, item in enumerate(shown):
            flag = "" if item["in_scope"] else "  [OUT OF SCOPE]"
            label = item["finding_id"] or "(no id)"
            print(f"  [{i:>3}] {label}  {item['level']:<8} "
                  f"{item['file']}:{item['start_line']}{flag}")
            print(f"        {item['rule_id']}")
        print("\nIndices are positions in this filtered list and change when the")
        print("filters change. Use the id for anything you want to reproduce:")
        print("  make triage ID=<finding-id>   or   make triage N=<index>")
        return 0
```

Индексация в дальнейшем должна брать элемент из `shown`, а не из `results`. Заменить блок выбора:

```python
    exclusions, _ = load_policy()
    items = annotate(results, args.repo, exclusions)
    shown = apply_filters(
        items,
        levels=args.level.split(",") if args.level else None,
        rule=args.rule,
        path_glob=args.path_glob,
        reviewed_ids=reviewed_finding_ids(args.verdicts) if args.unreviewed else None,
        limit=args.limit,
    )

    if not 0 <= args.index < len(shown):
        print(f"Index out of range (0..{len(shown) - 1})", file=sys.stderr)
        return 1
    chosen = shown[args.index]
```

и передавать `chosen` в `build_triage_packet(chosen, args.repo, args.context_lines, exclusions)`.

- [ ] **Step 6: Прогнать**

Run: `make test`
Expected: всё зелёное.

- [ ] **Step 7: Коммит**

```bash
git add scripts/build_packet.py scripts/check_scope.py tests/test_build_packet.py
git commit -m "feat: filter the triage queue by level, rule, path and review state"
```

---

### Task 16: Адресация находок по идентификатору

**Files:**
- Modify: `scripts/build_packet.py:200-280`
- Modify: `Makefile`
- Modify: `tests/test_build_packet.py`

**Interfaces:**
- Consumes: `build_packet.annotate`.
- Produces: `--finding-id` в CLI, `make triage ID=`, `make list LEVEL= RULE= PATH= UNREVIEWED= LIMIT=`.

- [ ] **Step 1: Написать падающий тест**

```python
class TestFindingIdAddressing(unittest.TestCase):
    def run_builder(self, args):
        return subprocess.run(
            [sys.executable, str(REPO_ROOT / "scripts" / "build_packet.py"), *args],
            capture_output=True,
            text=True,
        )

    def test_unknown_id_is_reported_and_non_zero(self):
        proc = self.run_builder(
            ["--sarif", str(SARIF), "--finding-id", "F-doesnotexist"]
        )
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("F-doesnotexist", proc.stderr)

    def test_id_and_index_together_are_refused(self):
        proc = self.run_builder(
            ["--sarif", str(SARIF), "--finding-id", "F-x", "--index", "0"]
        )
        self.assertNotEqual(proc.returncode, 0)
```

(`subprocess`, `sys` и `REPO_ROOT` уже импортированы в Task 15.)

- [ ] **Step 2: Прогнать**

Run: `python3 -m unittest tests.test_build_packet.TestFindingIdAddressing -v`
Expected: FAIL — аргумент неизвестен.

- [ ] **Step 3: Добавить аргумент и разрешение**

```python
    parser.add_argument("--finding-id",
                        help="Address a finding by id; survives filter changes")
```

Расширить условие листинга — до этой задачи оно не знало про id, и без правки
`--finding-id` без `--index` провалился бы в печать списка:

```python
    if args.list or (args.index is None and not args.finding_id):
```

Сразу после `args = parser.parse_args()`:

```python
    if args.finding_id and args.index is not None:
        parser.error("pass either --finding-id or --index, not both")
```

В блоке выбора, перед индексацией:

```python
    if args.finding_id:
        matching = [i for i in items if i["finding_id"] == args.finding_id]
        if not matching:
            print(f"No finding with id {args.finding_id} in {args.sarif}.",
                  file=sys.stderr)
            print("Run --list to see the current ids. An id changes only when "
                  "the flagged code itself changes.", file=sys.stderr)
            return 1
        chosen = matching[0]
    else:
        if not 0 <= args.index < len(shown):
            print(f"Index out of range (0..{len(shown) - 1})", file=sys.stderr)
            return 1
        chosen = shown[args.index]
```

- [ ] **Step 4: Обновить Makefile**

```make
list:
	@python3 scripts/build_packet.py --sarif $(SARIF) --list \
		$(if $(LEVEL),--level $(LEVEL),) \
		$(if $(RULE),--rule $(RULE),) \
		$(if $(PATH_GLOB),--path $(PATH_GLOB),) \
		$(if $(UNREVIEWED),--unreviewed,) \
		$(if $(LIMIT),--limit $(LIMIT),)

triage:
	@python3 scripts/build_packet.py --sarif $(SARIF) --repo $(REPO) \
		$(if $(ID),--finding-id $(ID),--index $(N))
```

В блоке `help`:

```make
	@echo "  make list LEVEL=error UNREVIEWED=1   filtered triage queue"
	@echo "  make triage ID=F-abc      build a packet by finding id"
```

`PATH_GLOB`, а не `PATH`: `PATH` в make наследует переменную окружения и переопределять её нельзя.

- [ ] **Step 5: Прогнать**

Run: `make test`
Expected: всё зелёное.

Run: `make list SARIF=tests/fixtures/sample.sarif LEVEL=error`
Expected: одна находка, сводка в шапке, подсказка про id внизу.

- [ ] **Step 6: Коммит**

```bash
git add scripts/build_packet.py tests/test_build_packet.py Makefile
git commit -m "feat: address findings by id so filters cannot change what N means"
```

**Слой 4 завершён.**

---

# Слой 5 — решение человека и пересмотр вердиктов

### Task 17: Явный пересмотр вердикта

**Files:**
- Modify: `scripts/record_verdict.py`
- Modify: `tests/test_record_verdict.py`

**Interfaces:**
- Produces: `record_verdict.verdict_rows(path: Path, finding_id: str) -> list[dict]`, флаг `--supersede`, колонка `supersedes`.

- [ ] **Step 1: Написать падающий тест**

```python
class TestVerdictRows(unittest.TestCase):
    def test_verdict_rows_are_found(self):
        with temp_tree({}) as root:
            log = root / "triage-log.csv"
            write_log(log, [{
                "finding_id": "F-000000000001",
                "id_scheme": "content-v1",
                "initial_verdict": "true_positive",
                "reviewed_at": "2026-09-01T10:00:00+00:00",
            }])
            rows = record_verdict.verdict_rows(log, "F-000000000001")
        self.assertEqual(len(rows), 1)

    def test_rows_without_a_verdict_are_not_counted(self):
        # Human-decision rows share the finding_id but decide on a verdict
        # rather than being one, so superseding must not see them.
        with temp_tree({}) as root:
            log = root / "triage-log.csv"
            write_log(log, [{
                "finding_id": "F-000000000001",
                "human_decision": "accepted",
            }])
            self.assertEqual(record_verdict.verdict_rows(log, "F-000000000001"), [])

    def test_absent_log_has_no_rows(self):
        with temp_tree({}) as root:
            self.assertEqual(
                record_verdict.verdict_rows(root / "absent.csv", "F-1"), []
            )


class TestSupersedeCli(unittest.TestCase):
    """Re-recording must be a deliberate act. The log is append-only, so a
    silent second row would let metrics count one finding as two."""

    def write_verdict(self, root, **overrides):
        verdict = make_verdict(severity="low", evidence_level="partial", **overrides)
        (root / "verdict.json").write_text(json.dumps(verdict), encoding="utf-8")

    def run_recorder(self, root, extra=()):
        return subprocess.run(
            [
                sys.executable, str(REPO_ROOT / "scripts" / "record_verdict.py"),
                "--verdict", str(root / "verdict.json"),
                "--agent", "model-a",
                "--log", str(root / "triage-log.csv"),
                "--sarif-out", str(root / "reviewed.sarif"),
                *extra,
            ],
            capture_output=True,
            text=True,
        )

    def test_first_recording_succeeds(self):
        with temp_tree({}) as root:
            self.write_verdict(root)
            proc = self.run_recorder(root)
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_second_recording_without_the_flag_is_refused(self):
        with temp_tree({}) as root:
            self.write_verdict(root)
            self.assertEqual(self.run_recorder(root).returncode, 0)
            proc = self.run_recorder(root)
            rows = record_verdict.verdict_rows(
                root / "triage-log.csv", "F-000000000001"
            )
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("--supersede", proc.stderr)
        self.assertEqual(len(rows), 1, "a refused run must not append")

    def test_supersede_appends_and_points_back(self):
        with temp_tree({}) as root:
            self.write_verdict(root)
            self.assertEqual(self.run_recorder(root).returncode, 0)

            revised = make_verdict(
                severity="low", evidence_level="partial", verdict="false_positive"
            )
            revised["reviewer"]["reviewed_at"] = "2026-09-02T10:00:00+00:00"
            (root / "verdict.json").write_text(json.dumps(revised), encoding="utf-8")

            proc = self.run_recorder(root, ["--supersede"])
            rows = record_verdict.verdict_rows(
                root / "triage-log.csv", "F-000000000001"
            )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[1]["supersedes"], "2026-09-01T10:00:00+00:00")
        self.assertEqual(rows[1]["initial_verdict"], "false_positive")
```

- [ ] **Step 2: Реализовать**

Дописать в `scripts/record_verdict.py`:

```python
def verdict_rows(path: Path, finding_id: str) -> list[dict]:
    """Previously recorded verdicts for one finding.

    Human-decision rows share the finding_id but carry no initial_verdict, so
    they are excluded here: superseding a verdict is a different act from
    deciding on one.
    """
    if not path.exists():
        return []
    with path.open(encoding="utf-8", newline="") as fh:
        return [
            row
            for row in csv.DictReader(fh)
            if row.get("finding_id") == finding_id and row.get("initial_verdict")
        ]
```

Добавить `"supersedes"` в `LOG_FIELDS` (перед `"notes"`), флаг и проверку:

```python
    parser.add_argument("--supersede", action="store_true",
                        help="Record a revision of a verdict already in the log")
```

После проверки совместимости лога:

```python
    prior = verdict_rows(args.log, verdict["finding_id"])
    if prior and not args.supersede:
        print(f"REFUSED: {verdict['finding_id']} already has a verdict recorded "
              f"at {prior[-1].get('reviewed_at', 'an unknown time')}.\n",
              file=sys.stderr)
        print("Pass --supersede to record a revision. The log stays append-only:\n"
              "the earlier row remains and the new one points back at it.",
              file=sys.stderr)
        return 2
```

И в словарь строки лога:

```python
            "supersedes": prior[-1].get("reviewed_at", "") if prior else "",
```

- [ ] **Step 3: Прогнать и закоммитить**

Run: `make test`
Expected: всё зелёное.

```bash
git add scripts/record_verdict.py tests/test_record_verdict.py
git commit -m "feat: require --supersede to revise a recorded verdict"
```

---

### Task 18: Запись решения человека

**Files:**
- Create: `scripts/record_human_decision.py`
- Create: `tests/test_human_decision.py`
- Modify: `scripts/record_verdict.py` (`LOG_FIELDS`)
- Modify: `Makefile`

**Interfaces:**
- Consumes: `record_verdict.LOG_FIELDS`, `record_verdict.load_existing_results`, `record_verdict.sarif_document`, `record_verdict.check_log_compatible`.
- Produces: колонки `human_decision`, `human_decision_at`, `human_decision_by`, `human_rationale`; цель `make decide`.

- [ ] **Step 1: Расширить набор колонок**

В `scripts/record_verdict.py` добавить в `LOG_FIELDS` перед `"supersedes"`:

```python
    "human_decision", "human_decision_at", "human_decision_by", "human_rationale",
```

- [ ] **Step 2: Написать падающие тесты**

`tests/test_human_decision.py`:

```python
"""Tests for the ground-truth record.

Without a human decision the programme can describe what the pipeline did but
not whether it was right, and that is the question a pilot exists to answer.
"""

import csv
import json
import subprocess
import sys
import unittest

import record_verdict
from tests import REPO_ROOT
from tests.helpers import temp_tree, write_log

SCRIPT = REPO_ROOT / "scripts" / "record_human_decision.py"


def verdict_row(fid="F-000000000001"):
    return {
        "reviewed_at": "2026-09-01T10:00:00+00:00",
        "finding_id": fid,
        "id_scheme": "content-v1",
        "initial_verdict": "true_positive",
        "final_state": "confirmed",
        "severity": "high",
        "agent": "model-a",
        "validator": "model-b",
    }


class TestDecisionRecording(unittest.TestCase):
    def run_script(self, args):
        return subprocess.run(
            [sys.executable, str(SCRIPT), *args], capture_output=True, text=True
        )

    def test_unknown_finding_is_refused(self):
        with temp_tree({}) as root:
            log = root / "triage-log.csv"
            write_log(log, [verdict_row()])
            proc = self.run_script([
                "--finding-id", "F-nope", "--decision", "accepted",
                "--by", "appsec-oncall", "--log", str(log),
                "--sarif", str(root / "reviewed.sarif"),
            ])
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("F-nope", proc.stderr)

    def test_invalid_decision_is_refused(self):
        with temp_tree({}) as root:
            log = root / "triage-log.csv"
            write_log(log, [verdict_row()])
            proc = self.run_script([
                "--finding-id", "F-000000000001", "--decision", "maybe",
                "--by", "appsec-oncall", "--log", str(log),
                "--sarif", str(root / "reviewed.sarif"),
            ])
        self.assertNotEqual(proc.returncode, 0)

    def test_decision_is_appended_to_the_log(self):
        with temp_tree({}) as root:
            log = root / "triage-log.csv"
            write_log(log, [verdict_row()])
            proc = self.run_script([
                "--finding-id", "F-000000000001", "--decision", "rejected",
                "--by", "appsec-oncall", "--rationale", "sanitiser upstream",
                "--log", str(log), "--sarif", str(root / "reviewed.sarif"),
            ])
            self.assertEqual(proc.returncode, 0, proc.stderr)
            with log.open(encoding="utf-8", newline="") as fh:
                rows = list(csv.DictReader(fh))
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[-1]["human_decision"], "rejected")
        self.assertEqual(rows[-1]["human_decision_by"], "appsec-oncall")
        self.assertEqual(rows[-1]["finding_id"], "F-000000000001")

    def test_malformed_sarif_refuses_and_leaves_the_log_untouched(self):
        # Regression for the ordering fix: the SARIF is parsed before anything
        # is written, because the triage log is append-only and a row added
        # ahead of a SARIF failure could never be withdrawn.
        with temp_tree({}) as root:
            log = root / "triage-log.csv"
            sarif = root / "reviewed.sarif"
            write_log(log, [verdict_row()])
            sarif.write_text("{ not json", encoding="utf-8")
            before = log.read_text(encoding="utf-8")
            proc = self.run_script([
                "--finding-id", "F-000000000001", "--decision", "accepted",
                "--by", "appsec-oncall", "--log", str(log), "--sarif", str(sarif),
            ])
            after = log.read_text(encoding="utf-8")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("SARIF ERROR", proc.stderr)
        self.assertEqual(before, after, "a refused run must not append to the log")

    def test_sarif_properties_are_updated(self):
        with temp_tree({}) as root:
            log = root / "triage-log.csv"
            sarif = root / "reviewed.sarif"
            write_log(log, [verdict_row()])
            result = record_verdict.build_result(
                {
                    "finding_id": "F-000000000001",
                    "severity": "high",
                    "reasoning": "text",
                    "location": {"file": "app/handler.py", "start_line": 4},
                },
                None,
                "confirmed",
                "rationale",
            )
            sarif.write_text(
                json.dumps(record_verdict.sarif_document([result])), encoding="utf-8"
            )
            proc = self.run_script([
                "--finding-id", "F-000000000001", "--decision", "accepted",
                "--by", "appsec-oncall", "--log", str(log), "--sarif", str(sarif),
            ])
            self.assertEqual(proc.returncode, 0, proc.stderr)
            results = record_verdict.load_existing_results(sarif)
        self.assertEqual(results[0]["properties"]["human_decision"], "accepted")


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 3: Написать скрипт**

`scripts/record_human_decision.py`:

```python
#!/usr/bin/env python3
"""Record the human's decision on a reviewed finding.

CLAUDE.md opens by saying every verdict is a recommendation that a human
accepts, rejects, or escalates. Nothing recorded that decision, so the
programme had no ground truth: metrics could describe what the pipeline did,
but never whether it was right.

The subject of the decision is the pipeline's final_state, not the agent's
original verdict. Two people reading this field differently would make the
number meaningless, so it is stated here and in docs/04.

There is deliberately no JSON schema for this input. The schemas in templates/
are output contracts for a model. A human typing at a terminal is validated by
argparse and an enum; adding a schema here would blur a line worth keeping.

Do not put personal data in --by. The triage log is committed (docs/03), so a
name or an email address becomes a permanent part of repository history. Use a
role or a work handle.

Usage:
    record_human_decision.py --finding-id F-abc --decision rejected \\
                             --by appsec-oncall --rationale "sanitiser upstream"
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from record_verdict import (  # noqa: E402
    LOG_FIELDS,
    LOG_PATH,
    SARIF_OUT,
    ValidationError,
    load_existing_results,
    sarif_document,
    verdict_rows,
)

DECISIONS = ("accepted", "rejected", "escalated")


def latest_verdict_row(path: Path, finding_id: str) -> dict | None:
    """The most recent recorded verdict for a finding, if there is one.

    Delegates to record_verdict.verdict_rows so that "what counts as a verdict
    row" is defined once. Two copies of that predicate would drift the moment
    a new row type appears.
    """
    rows = verdict_rows(path, finding_id)
    return rows[-1] if rows else None


def append_decision(path: Path, row: dict) -> None:
    exists = path.exists()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=LOG_FIELDS)
        if not exists:
            writer.writeheader()
        writer.writerow({k: row.get(k, "") for k in LOG_FIELDS})


def find_sarif_result(results: list[dict], finding_id: str) -> dict | None:
    for result in results:
        if result.get("properties", {}).get("finding_id") == finding_id:
            return result
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--finding-id", required=True)
    parser.add_argument("--decision", required=True, choices=DECISIONS,
                        help="Whether the human accepts the pipeline's final state")
    parser.add_argument("--by", required=True,
                        help="Role or work handle. Not a name or an email address: "
                             "the triage log is committed.")
    parser.add_argument("--rationale", default="")
    parser.add_argument("--minutes", type=float)
    parser.add_argument("--log", type=Path, default=LOG_PATH)
    parser.add_argument("--sarif", type=Path, default=SARIF_OUT)
    args = parser.parse_args()

    verdict_row = latest_verdict_row(args.log, args.finding_id)
    if verdict_row is None:
        print(f"REFUSED: no recorded verdict for {args.finding_id} in {args.log}.",
              file=sys.stderr)
        print("\nRecord the verdict first. A decision with nothing to decide on "
              "would sit in the log describing nothing.", file=sys.stderr)
        return 2

    # Parse the SARIF before writing anything. The triage log is append-only,
    # so a row written before a SARIF failure could never be taken back and the
    # two artefacts would disagree permanently.
    try:
        results = load_existing_results(args.sarif)
    except ValidationError as exc:
        print(f"SARIF ERROR: {exc}", file=sys.stderr)
        return 1
    target = find_sarif_result(results, args.finding_id)

    decided_at = datetime.now(timezone.utc).isoformat()
    append_decision(
        args.log,
        {
            "reviewed_at": decided_at,
            "finding_id": args.finding_id,
            "id_scheme": verdict_row.get("id_scheme", ""),
            "rule_id": verdict_row.get("rule_id", ""),
            "file": verdict_row.get("file", ""),
            "line": verdict_row.get("line", ""),
            "severity": verdict_row.get("severity", ""),
            "final_state": verdict_row.get("final_state", ""),
            "minutes_spent": args.minutes if args.minutes is not None else "",
            "human_decision": args.decision,
            "human_decision_at": decided_at,
            "human_decision_by": args.by,
            "human_rationale": args.rationale,
        },
    )

    if target is not None:
        target["properties"].update(
            {
                "human_decision": args.decision,
                "human_decision_at": decided_at,
                "human_decision_by": args.by,
                "human_rationale": args.rationale,
            }
        )
        args.sarif.write_text(
            json.dumps(sarif_document(results), indent=2), encoding="utf-8"
        )

    print(f"{args.finding_id}: {args.decision} by {args.by}")
    print(f"  logged -> {args.log}")
    if target is not None:
        print(f"  sarif  -> {args.sarif}")
    else:
        print(f"  note: {args.finding_id} is not in {args.sarif}; log updated only")
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 4: Добавить цель make**

```make
decide:
	@test -n "$(ID)" || (echo "Set ID=<finding-id>" && exit 1)
	@test -n "$(DECISION)" || (echo "Set DECISION=accepted|rejected|escalated" && exit 1)
	@test -n "$(BY)" || (echo "Set BY=<role or work handle, not a name>" && exit 1)
	@python3 scripts/record_human_decision.py --finding-id $(ID) \
		--decision $(DECISION) --by "$(BY)" \
		$(if $(RATIONALE),--rationale "$(RATIONALE)",)
```

Дописать `decide` в `.PHONY` и строку в `help`:

```make
	@echo "  make decide ID=F-abc DECISION=rejected BY=appsec-oncall"
```

- [ ] **Step 5: Прогнать и закоммитить**

Run: `make test`
Expected: всё зелёное.

```bash
git add scripts/record_human_decision.py scripts/record_verdict.py tests/test_human_decision.py Makefile
git commit -m "feat: record the human decision as programme ground truth"
```

---

### Task 19: Метрики считают находки и знают точность

**Files:**
- Modify: `scripts/metrics.py:56-211`
- Modify: `tests/test_metrics.py`

**Interfaces:**
- Consumes: колонки из задач 13, 17, 18.
- Produces: `metrics.collapse(rows) -> list[dict]`; ключи `dismissal_rate_pct`, `human_decisions`, `human_decision_coverage_pct`, `agent_accuracy_pct`, `revisions`.

- [ ] **Step 1: Написать падающие тесты**

Дописать в `tests/test_metrics.py`, и заменить обращения к `false_positive_rate_pct` на `dismissal_rate_pct` в существующем `test_rate_excludes_undecided_findings`:

```python
class TestCollapse(unittest.TestCase):
    """The log is append-only, so one finding can occupy several rows. Counting
    rows would report a revised finding as two findings."""

    def test_superseded_verdict_counts_once(self):
        rows = [
            row(final_state="confirmed"),
            row(final_state="dismissed", reviewed_at="2026-09-02T10:00:00+00:00",
                supersedes="2026-09-01T10:00:00+00:00"),
        ]
        collapsed = metrics.collapse(rows)
        self.assertEqual(len(collapsed), 1)
        self.assertEqual(collapsed[0]["final_state"], "dismissed")

    def test_human_decision_row_merges_into_the_finding(self):
        rows = [
            row(final_state="confirmed"),
            {"finding_id": "F-000000000001", "human_decision": "rejected",
             "human_decision_by": "appsec-oncall", "initial_verdict": ""},
        ]
        collapsed = metrics.collapse(rows)
        self.assertEqual(len(collapsed), 1)
        self.assertEqual(collapsed[0]["final_state"], "confirmed")
        self.assertEqual(collapsed[0]["human_decision"], "rejected")

    def test_latest_wins_regardless_of_input_order(self):
        newer = row(final_state="dismissed", reviewed_at="2026-09-02T10:00:00+00:00",
                    supersedes="2026-09-01T10:00:00+00:00")
        older = row(final_state="confirmed")
        collapsed = metrics.collapse([newer, older])
        self.assertEqual(len(collapsed), 1)
        self.assertEqual(collapsed[0]["final_state"], "dismissed")

    def test_revisions_are_counted(self):
        rows = [
            row(),
            row(reviewed_at="2026-09-02T10:00:00+00:00", supersedes="2026-09-01T10:00:00+00:00"),
        ]
        self.assertEqual(metrics.compute(rows)["revisions"], 1)


class TestAgentAccuracy(unittest.TestCase):
    def compute(self, rows):
        return metrics.compute(rows)

    def test_accuracy_uses_only_rows_with_a_decision(self):
        m = self.compute([
            row(finding_id="F-1", human_decision="accepted"),
            row(finding_id="F-2", human_decision="accepted"),
            row(finding_id="F-3", human_decision="rejected"),
            row(finding_id="F-4"),
        ])
        self.assertEqual(m["human_decisions"], 3)
        self.assertAlmostEqual(m["agent_accuracy_pct"], 66.7, places=1)

    def test_escalated_is_not_counted_as_right_or_wrong(self):
        m = self.compute([
            row(finding_id="F-1", human_decision="accepted"),
            row(finding_id="F-2", human_decision="escalated"),
        ])
        self.assertEqual(m["agent_accuracy_pct"], 100.0)

    def test_no_decisions_leaves_accuracy_undefined(self):
        self.assertIsNone(self.compute([row()])["agent_accuracy_pct"])

    def test_low_coverage_warns_in_the_render(self):
        m = self.compute([
            row(finding_id=f"F-{i}", human_decision="accepted" if i == 0 else "")
            for i in range(10)
        ])
        self.assertIn("biased subset", metrics.render(m))

    def test_dismissal_rate_is_no_longer_called_accuracy(self):
        m = self.compute([row(final_state="dismissed")])
        self.assertIn("dismissal_rate_pct", m)
        self.assertNotIn("false_positive_rate_pct", m)
```

Расширить фабрику `row()`, добавив ключи по умолчанию: `"human_decision": ""`, `"supersedes": ""`.

- [ ] **Step 2: Прогнать**

Run: `python3 -m unittest tests.test_metrics -v`
Expected: FAIL — `collapse` отсутствует, ключ переименован.

- [ ] **Step 3: Схлопнуть строки в находки**

В `scripts/metrics.py` добавить перед `compute`:

```python
def collapse(rows: list[dict]) -> list[dict]:
    """One record per finding.

    The triage log is append-only by design: a superseded verdict and a human
    decision both arrive as additional rows carrying the same finding_id.
    Counting rows would report one finding as several and quietly inflate every
    total, so rows are folded onto the finding they describe. Empty values never
    overwrite populated ones, which is what lets a later decision row merge into
    an earlier verdict row without erasing it.
    """
    by_id: dict[str, dict] = {}
    # Fold in timestamp order, not input order. The log is normally
    # chronological, but --since filtering and hand edits can reorder it, and
    # letting input order decide would silently promote a superseded verdict
    # over the one that replaced it.
    for row in sorted(rows, key=lambda r: r.get("reviewed_at", "")):
        fid = row.get("finding_id")
        if not fid:
            continue
        merged = dict(by_id.get(fid, {}))
        merged.update({k: v for k, v in row.items() if v})
        by_id[fid] = merged
    return list(by_id.values())
```

- [ ] **Step 4: Пересчитать метрики**

В `compute` первой строкой:

```python
    revisions = sum(1 for r in rows if r.get("supersedes"))
    rows = collapse(rows)
```

Переименовать величину и добавить точность перед `return`:

```python
    dismissal_rate = (states["dismissed"] / decided * 100) if decided else None

    decisions = Counter(r.get("human_decision") for r in rows if r.get("human_decision"))
    judged = decisions["accepted"] + decisions["rejected"]
    accuracy = (decisions["accepted"] / judged * 100) if judged else None
    coverage = (sum(decisions.values()) / decided * 100) if decided else None
```

В возвращаемом словаре заменить `"false_positive_rate_pct"` на:

```python
        "dismissal_rate_pct": round(dismissal_rate, 1) if dismissal_rate is not None else None,
        "revisions": revisions,
        "human_decisions": sum(decisions.values()),
        "human_decision_breakdown": dict(decisions),
        "human_decision_coverage_pct": round(coverage, 1) if coverage is not None else None,
        "agent_accuracy_pct": round(accuracy, 1) if accuracy is not None else None,
```

- [ ] **Step 5: Переписать вывод**

Заменить заголовок блока 2 и его содержимое:

```python
    add("-" * 58)
    add("  2. DISMISSAL RATE  (of decided findings)")
    add("-" * 58)
    if m["dismissal_rate_pct"] is not None:
        add(f"  Dismissed by the pipeline {m['dismissal_rate_pct']}%")
        add("")
        add("  This is what the pipeline did, not how often it was right.")
        add("  Accuracy is section 5 and needs human decisions.")
    else:
        add("  Nothing decided yet.")
    add("")
```

И добавить новый блок перед разделом EVIDENCE QUALITY:

```python
    add("-" * 58)
    add("  5. AGENT ACCURACY  (ground truth)")
    add("-" * 58)
    coverage = m["human_decision_coverage_pct"]
    if m["human_decisions"]:
        add(f"  Human decisions recorded {m['human_decisions']}"
            f"  (coverage {coverage}%)")
        for name in ("accepted", "rejected", "escalated"):
            if name in m["human_decision_breakdown"]:
                add(f"  {name:<24} {m['human_decision_breakdown'][name]}")
        if m["agent_accuracy_pct"] is not None:
            add(f"  Agent accuracy           {m['agent_accuracy_pct']}%")
        if coverage is not None and coverage < 50:
            add("")
            add("  ! Fewer than half the decided findings carry a human")
            add("    decision, so the accuracy above rests on a biased subset.")
            add("    Record decisions before quoting this number to anyone.")
    else:
        add("  No human decisions recorded. Without them the programme can")
        add("  describe what the pipeline did but not whether it was right,")
        add("  which is the question a pilot exists to answer.")
        add("  Record them with: make decide ID=<id> DECISION=<d> BY=<role>")
    if m["revisions"]:
        add("")
        add(f"  Verdicts revised         {m['revisions']}")
    add("")
```

- [ ] **Step 6: Прогнать и закоммитить**

Run: `make test`
Expected: всё зелёное.

```bash
git add scripts/metrics.py tests/test_metrics.py
git commit -m "feat: collapse rows into findings and report agent accuracy"
```

**Слой 5 завершён.**

---

# Слой 6 — доки против кода

### Task 20: Привести документацию в соответствие

**Files:**
- Modify: `README.md`, `docs/03-data-handling.md`, `docs/04-procedures.md`, `docs/07-graduation.md`, `CLAUDE.md`, `Makefile`
- Modify: `templates/verdict.schema.json`, `templates/challenge.schema.json`, `prompts/adversarial-validate.md`
- Create: `templates/threat-model.md`

**Interfaces:**
- Consumes: всё построенное выше.
- Produces: цель `make check-template`.

- [ ] **Step 1: README**

Заменить таблицу Layout — строка `templates/` описывает несуществующие файлы:

```markdown
| `templates/` | Verdict and challenge schemas, threat-model template |
```

Добавить раздел после Quick start:

```markdown
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
```

Добавить в конце секции про нумерацию:

```markdown
Documentation files follow an internal series, so the numbering has gaps.
```

- [ ] **Step 2: `docs/07-graduation.md`**

Дописать после списка критериев:

```markdown
The golden-set criterion is **blocked**: `goldenset/run_goldenset.py` is a
placeholder with no cases configured. It stays on the list because it belongs
there, but it cannot be met today.

## Pilot exit criteria

A pilot is narrower than graduation. It runs on one repository and answers one
question: is this worth continuing? Use the graduation list minus the golden
set, plus:

- Human decisions recorded for at least `<coverage threshold>` of decided
  findings.
- Agent accuracy of at least `<accuracy threshold>` on those decisions.

**Fill both thresholds in before the pilot starts.** Choosing them after the
numbers arrive is not measurement, it is fitting the criteria to the result.
```

- [ ] **Step 3: `docs/04-procedures.md`**

Обновить команды сценария 1:

```bash
make record ID=F-abc123 AGENT=<triage model> VALIDATOR=<validation model> MINUTES=12
make decide ID=F-abc123 DECISION=accepted BY=appsec-oncall
```

И дописать в конце сценария 1:

```markdown
`make record` refuses when AGENT and VALIDATOR name the same model. That is the
independence mechanism, not a preference — a second pass on the same model
inherits the same blind spots.

`make decide` records what you decided about the pipeline's final state, not
about the agent's original verdict. That distinction is what makes the accuracy
number in `make metrics` mean anything. Use a role or a work handle for `BY=`:
the triage log is committed.
```

Обновить цикл сценария 2:

```bash
for f in findings/verdicts/audit-*.json; do
  python3 scripts/record_verdict.py --verdict "$f" --agent "<triage model>"
done
```

- [ ] **Step 4: Схемы и промпт**

В `templates/verdict.schema.json` заменить описание:

```json
      "agent": { "type": "string", "description": "Tool and model identifier, self-reported by the model and therefore not authoritative. The engineer supplies the authoritative value via record_verdict.py --agent." },
```

В `templates/challenge.schema.json` — то же для `validator.agent`, со ссылкой на `--validator`.

В `prompts/adversarial-validate.md` дописать:

```markdown
The engineer records which models actually ran the two passes. `make record`
refuses when they match, so state your identity honestly and do not guess.
```

- [ ] **Step 5: Шаблон модели угроз**

`templates/threat-model.md`:

```markdown
# Threat model: <component>

- **Date:**
- **Author:**
- **Trigger:** <new feature | architecture change | incident follow-up>
- **Review again when:** <the architectural change that invalidates this>

## Component and scope

What is in scope, and explicitly what is not.

## Assets

What an attacker would want. Data, capability, availability, trust.

## Actors

Who interacts with this, and what each is trusted to do.

## Trust boundaries

Where data crosses from less trusted to more trusted. For systems with an
agent, every tool it can call is a boundary and every retrieval source is
untrusted input.

## Entry points

Concrete: handlers, consumers, uploads, webhooks, CLI arguments.

## Threats

| # | Threat | Boundary | Impact | Likelihood |
|---|---|---|---|---|

For AI systems also cover: prompt injection including the indirect variety,
retrieval poisoning, context and memory poisoning, unsafe tool use, output
handling into interpreters, training and data supply chain, excessive agency.

## Controls

What exists today. Separate implemented from planned.

## Residual risks

What remains after the controls, and who accepted it.

## Review triggers

What change would make this document wrong.
```

- [ ] **Step 6: `CLAUDE.md` и `make check-template`**

Заменить первый пункт «What not to do»:

```markdown
- Do not modify files **in the repository under review**. Analysis is read-only.
  This does not restrict maintenance of the review tooling itself, which is
  ordinary development work with its own tests.
```

Добавить цель в `Makefile`, дописав `check-template` в `.PHONY`:

```make
check-template:
	@if grep -nE '<[A-Za-z][^>]*>' CLAUDE.md; then \
		echo ""; \
		echo "CLAUDE.md still has template placeholders, listed above."; \
		echo "Fill in trust boundaries, entry points and accepted patterns"; \
		echo "for this repository. Until then the evidence standard is hollow:"; \
		echo "the agent cannot know what an attacker controls."; \
		exit 2; \
	else \
		echo "CLAUDE.md has no unfilled placeholders."; \
	fi
```

В `help`:

```make
	@echo "  make check-template       refuse while CLAUDE.md is unfilled"
```

Дописать в `docs/03-data-handling.md` новый подраздел перед пре-флайт чек-листом:

```markdown
## Human decisions carry no schema, deliberately

The contracts in `templates/` are output contracts for a model: they exist
because model output needs validating before it enters the findings store. A
human decision is typed at a terminal by a person and is validated by argparse
and an enum instead.

Do not add a schema for it out of a sense of symmetry. The distinction between
"a model asserted this" and "a person decided this" is the one that makes the
accuracy metric mean anything, and a shared schema would blur it.

`--by` takes a role or a work handle. Not a name, not an email address: this
log is committed, so whatever goes there becomes permanent repository history.
```

И дописать в пре-флайт чек-лист:

```markdown
- [ ] `make check-template` passes, so `CLAUDE.md` describes this repository
      rather than the template
- [ ] Whoever records human decisions knows to use a role in `BY=`, never a
      name or an email address
```

Ожидаемое поведение в этом репозитории: `make check-template` **падает**, потому что `CLAUDE.md` здесь остаётся шаблоном. Это правильно и должно быть отражено в README:

```markdown
`make check-template` fails in this repository on purpose: `CLAUDE.md` here is
the template you copy and fill in per project.
```

- [ ] **Step 7: Финальная проверка**

Run: `make test`
Expected: всё зелёное.

Run: `make check-scope`
Expected: печатает исключения, включая `**/.envrc`.

Run: `make metrics`
Expected: `No reviews recorded yet.`

Run: `make check-template`
Expected: exit 2 со списком плейсхолдеров — ожидаемо для этого репозитория.

Run: `make list SARIF=tests/fixtures/sample.sarif`
Expected: три находки со сводкой и подсказкой про id.

- [ ] **Step 8: Коммит**

```bash
git add README.md docs CLAUDE.md Makefile templates prompts
git commit -m "docs: reconcile documentation with the code that ships"
```

**Слой 6 завершён.**

---

## Definition of Done

- `make test` зелёный на голом Python 3.9+ без единой установки.
- У каждого дефекта из слоёв 1–3 и §5.3 сохранён вывод падавшего теста.
- `make check-scope`, `make list`, `make metrics` работают.
- В тестах нет обращений к сети.
- `make check-template` падает, и README объясняет почему.

## Что остаётся вне этого плана

Перед пилотом на реальном репозитории требуется работа, которой здесь нет и которая не является кодом:

1. Наполнение `rules/` правилами под языки целевого репозитория.
2. Заполнение `CLAUDE.md` реальными точками входа и границами доверия.
3. Подтверждённый доступ к двум разным моделям. Проверить **до** начала реализации: `make record` теперь отказывает при совпадении, а medium и выше без челленджа не выходят из `blocked_needs_challenge`.
