""" Nikto-style scanner module.

Provides NiktoScanner, a lean standalone scanner that performs the passive
checks that Nikto and Burp Suite Pro perform against individual web targets:

* HTTP security-header auditing (low false-positive, header-only analysis).
* Detection of dangerous HTTP methods (PUT/DELETE/TRACE/CONNECT) via OPTIONS.
* Server-software version disclosure.
* Detection of well-known sensitive/dangerous paths (admin panels, backup
  files, default credentials pages, version-control directories, etc.).

All checks are designed for a low false-positive rate: each finding is tied
to a concrete, unambiguous indicator. """
