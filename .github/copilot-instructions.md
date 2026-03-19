# MassWeb — Copilot Instructions

## Project Overview

**MassWeb** is a high-performance Python 3 library for massive-scale web application fuzzing and vulnerability scanning (SQL injection, XSS, path traversal, OS command injection, etc.). It was built by Hyperion Gray for the PunkSPIDER project and is capable of scanning hundreds of millions of URLs in days using multiprocessing and optional Hadoop integration.

## Repository Structure

```
massweb/               # Main library package
  mass_requests/       # Core parallel HTTP request handling (multiprocessing)
  fuzzers/             # Fuzzing engines (WebFuzzer)
  masscrawler/         # Web crawler (BeautifulSoup-based)
  targets/             # Target objects (Target, FuzzyTarget, CrawlTarget)
  payloads/            # Attack payload definitions
  vuln_checks/         # Vulnerability detectors (sqli, xss, trav, mxi, osci, xpathi)
  proxy_rotator/       # Transparent proxy rotation
  pnk_net/             # Low-level HTTP request utilities and form discovery
  results/             # Result objects for findings
  hadoop-utils/        # Hadoop MapReduce mapper/reducer scripts
test/                  # Unit and integration tests (unittest)
docs/                  # Sphinx documentation source
QUICKSTART.md          # Quick start guide
START_HERE.md          # Deep-dive architecture guide for new contributors
rules.json             # Project-wide coding and workflow rules
```

## How to Build and Install

```bash
# Install in development mode (recommended)
pip install -e .

# Install dev dependencies (Sphinx, build, wheel)
pip install -r requirements-dev.txt

# Build the package
python -m build
```

## How to Run Tests

```bash
# Run all tests via unittest discovery (preferred)
python -m unittest discover test/

# Run via the test script
cd test && python -m unittest discover

# Run a specific test file
python test/vuln_checks/test_sqli.py

# Run via Makefile (creates a local venv in env/)
make test
```

Tests live in `test/` and use Python's built-in `unittest` framework. There is no pytest config; use `unittest` directly.

## Key Architectural Patterns

- **Target → FuzzyTarget pipeline**: Create `Target` objects, call `fuzzer.generate_fuzzy_targets()` to inject payloads into URL params/POST data, then `fuzzer.fuzz()` to execute and analyze.
- **Multiprocessing, not threads**: `MassRequest` uses `multiprocessing.Pool` to avoid the GIL and enforce hard per-URL timeouts via `AsyncResult.get(timeout=...)`.
- **Special error strings**: Failed requests return `__PNK_THREAD_TIMEOUT` or `__PNK_FAILED_RESPONSE` rather than raising exceptions.
- **Vulnerability checks**: Each checker in `vuln_checks/` inherits from `Check` and implements `check(content) -> bool` using regex or string matching.

## Coding Conventions

- Python 3.7+ compatibility required; supports up to 3.12.
- New vulnerability checks: create a file in `massweb/vuln_checks/`, inherit from `Check`, implement `check(content)`, and register in `WebFuzzer._run_checks()`.
- No demo code mixed with production code. Demo code goes in `demo/` and must show a large `DEMO` banner.
- All documentation goes in `docs/`. Do not scatter doc files in the root.
- Code files should stay under a few hundred lines. Split complex logic into focused modules.
- No duplicate filenames or directories — use symlinks if a file is needed in multiple places.
- No TODOs left in code — capture them in a `TODO.md` file instead.

## Repository Organization Rules

The repo must stay clean. Acceptable top-level structure:

```
massweb/    QUICKSTART.md    README.md
test/       docs/            bak/       (for cleanup/archiving)
```

Additional directories are allowed if logically categorized. Sub-directories should be equally organized.

## Workflow Rules

- Always check `rules.json`, `START_HERE.md`, and `QUICKSTART.md` for context before starting tasks.
- First task in any task list: clean up the target directory.
- Mark any unfinished items in `TODO.md`; do not leave silent dead-end code.
- When asked to clean up: moving files to a `bak/` folder is acceptable and encouraged.
- Summarize completed work in comments and leave a checklist of remaining items.

## Tooling Preferences

- **Container runtime**: Podman over Docker (never use Docker directly).
- **Language choices**: Python for non-performance-critical code; C or Rust for performance-critical code; TypeScript + React for web UIs.
- **Web testing**: Playwright scripts for automated web testing, including HTTP error detection.
- **Security**: Always use TLS for secure communications. Good security practices are required.
- **Key-value store** preferred over PostgreSQL for database needs.

## Style Rules

- NO emojis, NO color output in scripts/tools (ASCII skulls are OK).
- Only production or real test code — no calculation-based emulations or placeholder stubs.
- Be straightforward about what is done vs. not done; do not exaggerate completion.
