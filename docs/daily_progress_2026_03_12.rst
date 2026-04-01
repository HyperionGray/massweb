Daily Progress: 2026-03-12
==========================

This note captures the current repository direction and the next logical
incremental tasks for MassWeb.

Project direction
-----------------

The repository still points toward the same core goal documented in
``README.md`` and ``START_HERE.md``: keep MassWeb useful as a large-scale web
fuzzing and scanning library while tightening its quality around the existing
scanner pipeline.

The most recent repository signals support that direction:

* Recent commits on ``master`` removed workflow files that no longer match the
  shared automation templates, which suggests active cleanup of repository
  automation rather than new product scope.
* Recent open pull requests focus on vulnerability coverage and test quality,
  including expanded traversal and SQL injection detection and a new SSTI
  checker.
* The issue tracker is dominated by recurring daily progress prompts, so a
  small, explicit backlog inside the repository is useful for turning those
  prompts into concrete engineering work.

What the repository already says
--------------------------------

The current documentation and source tree point to a few clear themes:

* ``START_HERE.md`` documents MassWeb as a modular scanning pipeline built from
  targets, payloads, fuzzers, request handling, and vulnerability checks.
* ``README.md`` currently emphasizes repository automation and AI review
  workflows more than the scanner itself, so the core product story is stronger
  in ``START_HERE.md`` than in the top-level readme.
* The codebase still contains a small cluster of ``FIXME`` notes in the
  crawler, request utilities, fuzzers, and payload handling:

  * ``massweb/masscrawler/masscrawl.py``
  * ``massweb/pnk_net/find_post.py``
  * ``massweb/pnk_net/pnk_request.py``
  * ``massweb/fuzzers/web_fuzzer.py``
  * ``massweb/fuzzers/bsqli_fuzzer.py``
  * ``massweb/fuzz_generators/url_generator.py``
  * ``massweb/payloads/bsqli_payload_group.py``

These are good candidates for small, repository-aligned follow-up work because
they touch existing scanner behavior rather than introducing unrelated features.

Prioritized next steps
----------------------

Quick wins
~~~~~~~~~~

#. Add focused tests around the existing vulnerability checks that recently
   changed or still have sparse coverage, especially ``osci``, ``trav``, and
   ``sqli`` patterns.
#. Fix the URL and form normalization ``FIXME`` items in
   ``massweb/pnk_net/find_post.py`` and ``massweb/fuzz_generators/url_generator.py``.
#. Move request-related magic strings from ``massweb/pnk_net/pnk_request.py``
   into a shared constants module so timeout and failure markers are defined in
   one place.
#. Clarify and simplify the response-analysis path in
   ``massweb/fuzzers/web_fuzzer.py``, where the existing source already calls
   out complexity.

Incremental follow-up work
~~~~~~~~~~~~~~~~~~~~~~~~~~

#. Continue expanding the vulnerability check set in the same style as the
   recent checker work, prioritizing gaps that fit the current response-pattern
   architecture.
#. Improve crawler scope handling in ``massweb/masscrawler/masscrawl.py`` so
   large crawls stay in scope more reliably for discovered forms and links.
#. Add more offline tests around request failure paths and special failure
   markers such as ``__PNK_THREAD_TIMEOUT`` and ``__PNK_FAILED_RESPONSE``.
#. Rebalance documentation so the top-level readme introduces the scanner
   architecture first and treats AI workflows as supporting automation.

Actionable task list
--------------------

Use the following order for incremental progress:

#. Clean up the request and URL normalization ``FIXME`` items.
#. Add or extend regression tests for the changed parsing and checker behavior.
#. Refine ``WebFuzzer`` response analysis without changing the public API.
#. Improve README and documentation alignment with the scanner's actual purpose.
#. Only after the above, consider adding new checkers or larger crawler
   enhancements.

Why this order
--------------

This sequence keeps work close to the current direction of the repository:

* it builds on the existing scanner and checker architecture,
* it prioritizes correctness and coverage over speculative new subsystems, and
* it produces small, reviewable changes that fit the recurring daily progress
  workflow used in this repository.
