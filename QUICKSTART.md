# MassWeb Quick Start Guide

## Installation

1. Clone the repository:
```bash
git clone https://github.com/HyperionGray/massweb.git
cd massweb
```

2. Install dependencies:
```bash
pip install -e .
```

For development (Sphinx docs, build tools):
```bash
pip install -r requirements-dev.txt
```

## Basic Usage

### Web Fuzzing

```python
from massweb.fuzzers.web_fuzzer import WebFuzzer
from massweb.payloads.payload import Payload
from massweb.targets.target import Target

# Create a target with URL parameters to fuzz
target = Target("http://example.com/page?param=1&other=2")

# Define payloads with the vulnerability types to check
payloads = [
    Payload('"><ScRipT>alert(31337)</ScrIpT>', check_type_list=["xss"]),
    Payload("')", check_type_list=["sqli", "xpathi"]),
    Payload("../../etc/passwd", check_type_list=["trav"]),
]

# Create fuzzer, add payloads, generate fuzzy targets, then run
fuzzer = WebFuzzer(targets=[target], num_threads=10, time_per_url=10)
for p in payloads:
    fuzzer.add_payload(p)
fuzzer.generate_fuzzy_targets()
results = fuzzer.fuzz()

# Process results
for result in results:
    print(result)
```

### Mass HTTP Requests

```python
from massweb.masscrawler.masscrawl import MassCrawl
from massweb.targets.crawl_target import CrawlTarget

# Create a crawl target with a seed URL
target = CrawlTarget("http://example.com")

# Run crawler with a depth limit and a seed list
crawler = MassCrawl(seed_list=["http://example.com"], num_threads=10)
crawler.crawl()

# View discovered URLs
for url in crawler.accumulated_target_urls:
    print(url)
```

### Proxy Rotation

```python
from massweb.fuzzers.web_fuzzer import WebFuzzer
from massweb.targets.target import Target

# Provide a list of proxies in the format expected by requests
proxies = [{"http": "http://proxy1.com:8080"}, {"http": "http://proxy2.com:8080"}]
target = Target("http://example.com/page?q=1")
fuzzer = WebFuzzer(targets=[target], proxy_list=proxies)
```

### Payload Customization

```python
from massweb.payloads.payload import Payload

# Create a payload with the vulnerability types to detect when that payload fires
p = Payload('"><ScRipT>alert(31337)</ScrIpT>', check_type_list=["xss"])
```

## Running Tests

```bash
# Run all tests via unittest discovery (preferred)
python -m unittest discover test/

# Run a specific test file directly
python -m unittest test/test_proxy_rotator.py

# Integration tests (require live targets) are skipped by default; enable them with:
# MASSWEB_RUN_INTEGRATION_TESTS=1 MASSWEB_INTEGRATION_TARGETS=http://target/ python -m unittest discover test/
```

## Documentation

- Full documentation: https://hyperiongray.atlassian.net/wiki/display/PUB/MassWeb
- API documentation: Run `make html` in the `docs/` directory

## Getting Help

- **Issues**: Open an issue on GitHub
- **Documentation**: Check the `docs/` directory

## Common Tasks

### Check a Response for SQL Injection
```python
from massweb.vuln_checks.sqli import SQLICheck

check = SQLICheck()
# Pass raw response body text from a fuzzer result
is_vulnerable = check.check("you have an error in your sql syntax")
print(is_vulnerable)  # True
```

### Check a Response for Directory Traversal
```python
from massweb.vuln_checks.trav import TravCheck

check = TravCheck()
is_vulnerable = check.check("root:x:0:0:root:/root:/bin/bash")
print(is_vulnerable)  # True
```

## Next Steps

1. Read the full documentation
2. Explore example scripts in `examples/` (if available)
3. Try the AI-powered workflows for code review
4. Join discussions in GitHub Issues

## License

Apache 2.0 - See LICENSE.txt for details
