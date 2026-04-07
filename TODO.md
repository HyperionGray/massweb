# TODO

## Daily Progress: 2026-04-05

### Natural direction

The project continues incremental modernization: adding coverage for the least-tested
modules, cleaning up historical debt, and keeping developer tooling accurate. The
2026-04-05 pass focused on three concrete deliverables: removing tracked Sphinx build
output from version control, adding first-pass unit tests for the two previously
untested core modules (`proxy_rotator` and `mass_requests/response_analysis`), and
correcting the `QUICKSTART.md` code examples so they reflect the actual public API.

### Completed (2026-04-05)

- [x] Add `docs/_build/` to `.gitignore` and un-track the 144 committed build files
- [x] Add focused unit tests for `massweb/proxy_rotator/proxy_rotate.py`
      (`test/proxy_rotator/test_proxy_rotate.py` — 5 tests)
- [x] Add focused unit tests for `massweb/mass_requests/response_analysis.py`
      (`test/mass_requests/test_response_analysis.py` — 13 tests)
- [x] Fix `QUICKSTART.md` — corrected `WebFuzzer`, `MassCrawl`, vuln-check, proxy, and
      payload examples to match the real API; updated test commands from pytest to
      `python -m unittest discover test/`

### Quick wins remaining

- [ ] Align the documented test setup with the actual test requirements so
      `python -m unittest discover test/` can run with the documented dependencies
      (note: `beautifulsoup4` is required but not listed in `requirements.txt`)
- [ ] Convert the remaining `FIXME` comments in core modules into tracked fixes here
      (see FIXME inventory below) or follow-up issues with clear owners and scope
- [ ] Add regression tests for crawler scope handling in
      `massweb/masscrawler/masscrawl.py`

### Incremental improvements

- [ ] Expand modern vulnerability coverage in `massweb/vuln_checks/` and
      `massweb/payloads/`, especially around SSRF and newer SQLi/traversal patterns
- [ ] Update `docs/` source RST files to reflect the SSRF/SSTI additions from
      the 2026-03-09 pass (the vuln_checks module docs are stale)

### Larger follow-ups

- [ ] Evaluate a modern crawler path for JavaScript-rendered applications while
      preserving the current BeautifulSoup-based crawler
- [ ] Prototype a request-engine modernization plan only if it can preserve
      MassWeb's hard timeout behavior

---

## FIXME Inventory (tracked 2026-04-05)

The following `FIXME` comments exist in the codebase and need follow-up.
Each has been left in place; this list captures them for issue tracking.

| File | Line | Summary |
|------|------|---------|
| `massweb/fuzz_generators/url_generator.py` | 46 | UTF-8 query param encoding may produce incorrect keys (PNKTHR-42) |
| `massweb/fuzzers/bsqli_fuzzer.py` | 174, 198 | Unclear why `append([])` is required; investigate |
| `massweb/fuzzers/bsqli_fuzzer.py` | 236 | Local variables unnecessary; simplify |
| `massweb/fuzzers/web_fuzzer.py` | 166 | `_run_checks` not yet multiprocessed; evaluate whether it should be |
| `massweb/fuzzers/web_fuzzer.py` | 203 | `fuzz()` return type is complex / inconsistent; clarify |
| `massweb/fuzzers/ifuzzer.py` | 68 | Remove shared method to unify bsqli and web fuzzer interfaces |
| `massweb/masscrawler/masscrawl.py` | 109 | Out-of-scope POSTs appear in large-scale crawls |
| `massweb/masscrawler/masscrawl.py` | 155 | Crawler may not stay in scope |
| `massweb/pnk_net/find_post.py` | 31 | Link normalisation omits path; incorrect results for some URLs |
| `massweb/pnk_net/pnk_request.py` | 14 | Error sentinel constants should move to a central `const` module |
| `massweb/payloads/bsqli_payload_group.py` | 2 | `add_payload` handling unclear (PNKTHR-43) |
| `massweb/payloads/bsqli_payload_group.py` | 20 | Logic could be simplified by negating condition |

---

## Daily Progress: 2026-03-09

### Natural direction

MassWeb's current direction is incremental modernization around a stable large-scale scanning core:

- Preserve the existing multiprocessing-based fuzzing and request pipeline in `massweb/mass_requests/` and `massweb/fuzzers/`
- Continue repository cleanup and automation maintenance in `.github/workflows/`
- Improve developer usability through clearer setup, targeted tests, and tracked technical debt

Recent commits are concentrated on removing workflow files that no longer match the shared `.github` templates, which suggests the next useful work should stay focused on cleanup, validation, and small reliability improvements rather than large architectural rewrites.

### Quick wins (2026-03-09)

- [x] Add `docs/_build/` to `.gitignore` and remove tracked documentation build output from version control
- [ ] Align the documented test setup with the actual test requirements so `python -m unittest discover test/` can run with the documented dependencies
- [ ] Convert the remaining `FIXME` comments in core modules into tracked fixes in this `TODO.md` or follow-up issues with clear owners and scope
- [x] Add focused test coverage for the least-covered core paths in `massweb/proxy_rotator/` and `massweb/mass_requests/`

### Incremental improvements (2026-03-09)

- [x] Expand modern vulnerability coverage in `massweb/vuln_checks/` and `massweb/payloads/`, especially around SSRF and newer SQLi/traversal patterns
- [x] Update `QUICKSTART.md` and related docs so installation, test commands, and AI workflow guidance match the current repository state
- [ ] Add targeted regression tests for crawler scope handling in `massweb/masscrawler/masscrawl.py`

### Larger follow-ups (2026-03-09)

- [ ] Evaluate a modern crawler path for JavaScript-rendered applications while preserving the current BeautifulSoup-based crawler
- [ ] Prototype a request-engine modernization plan only if it can preserve MassWeb's hard timeout behavior

### Evidence gathered for this update

- Recent repository activity is mostly workflow-template cleanup in `.github/workflows/`
- Open issues are dominated by recurring daily progress analysis requests
- Local `python -m unittest discover test/` currently fails before execution because `bs4` is not available in the environment
- Current technical-debt hotspots include:
  - `massweb/fuzz_generators/url_generator.py`
  - `massweb/masscrawler/masscrawl.py`
  - `massweb/fuzzers/web_fuzzer.py`
  - `massweb/fuzzers/bsqli_fuzzer.py`
  - `massweb/pnk_net/find_post.py`
  - `massweb/pnk_net/pnk_request.py`
  - `massweb/payloads/bsqli_payload_group.py`
