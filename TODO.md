# TODO

## Daily Progress: 2026-03-09

### Natural direction

MassWeb's current direction is incremental modernization around a stable large-scale scanning core:

- Preserve the existing multiprocessing-based fuzzing and request pipeline in `massweb/mass_requests/` and `massweb/fuzzers/`
- Continue repository cleanup and automation maintenance in `.github/workflows/`
- Improve developer usability through clearer setup, targeted tests, and tracked technical debt

Recent commits are concentrated on removing workflow files that no longer match the shared `.github` templates, which suggests the next useful work should stay focused on cleanup, validation, and small reliability improvements rather than large architectural rewrites.

### Quick wins

- [ ] Clean up this directory by deciding whether `docs/_build/` should remain tracked or be treated as generated output
- [ ] Align the documented test setup with the actual test requirements so `python -m unittest discover test/` can run with the documented dependencies
- [ ] Convert the remaining `FIXME` comments in core modules into tracked fixes with clear owners and scope
- [ ] Add focused test coverage for the least-covered core paths in `massweb/proxy_rotator/` and `massweb/mass_requests/`

### Incremental improvements

- [ ] Expand modern vulnerability coverage in `massweb/vuln_checks/` and `massweb/payloads/`, especially around SSRF and newer SQLi/traversal patterns
- [ ] Update `QUICKSTART.md` and related docs so installation, test commands, and AI workflow guidance match the current repository state
- [ ] Add targeted regression tests for crawler scope handling in `massweb/masscrawler/masscrawl.py`

### Larger follow-ups

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
