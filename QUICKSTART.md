# MassWeb Quick Start Guide

## Installation

1. Clone the repository:
```bash
git clone https://github.com/HyperionGray/massweb.git
cd massweb
```

2. Install in development mode:
```bash
pip install -e .
```

## Basic Usage

### Web Fuzzing

```python
from massweb.fuzzers.web_fuzzer import WebFuzzer
from massweb.targets.target import Target
from massweb.payloads.payload import Payload

# Create a target with query parameters to fuzz
target = Target("http://example.com/page?param=1")

# Define typed payloads (check_type_list controls which vuln checkers run)
payloads = [
    Payload("'--", check_type_list=["sqli"]),
    Payload('"><ScRipT>alert(31337)</ScrIpT>', check_type_list=["xss"]),
    Payload("../../etc/passwd", check_type_list=["trav"]),
]

# Create fuzzer with targets
fuzzer = WebFuzzer(targets=[target], num_threads=10, time_per_url=10,
                   request_timeout=10)

# Add payloads, generate concrete fuzzy targets, then run
for p in payloads:
    fuzzer.add_payload(p)
fuzzer.generate_fuzzy_targets()
results = fuzzer.fuzz()

# Process results
for result in results:
    print(result.target, result.result_dic)
```

### Mass Crawling

```python
from massweb.masscrawler.masscrawl import MassCrawl

# Seed URLs define both the starting points and the crawl scope
seeds = ["http://example.com/"]

crawler = MassCrawl(seeds=seeds)
crawler.crawl(depth=3, num_threads=10, time_per_url=10, request_timeout=10)

# View discovered targets
for target in crawler.targets:
    print(target.url)
```

## Configuration

### Proxy Settings

```python
from massweb.fuzzers.web_fuzzer import WebFuzzer
from massweb.targets.target import Target

proxies = [{"http": "http://proxy1.example.com:8080"},
           {"http": "http://proxy2.example.com:8080"}]
fuzzer = WebFuzzer(targets=[Target("http://example.com/?q=1")],
                   proxy_list=proxies)
```

### Rate Limiting

```python
from massweb.mass_requests.mass_request import MassRequest

# Limit to 5 requests per second
mr = MassRequest(num_threads=10, requests_per_second=5.0)
```

## Running Tests

```bash
# Run all tests via unittest discovery (preferred)
python -m unittest discover test/

# Run a specific module
python -m unittest test.test_webfuzzer_offline

# Run live network integration tests (requires a target URL with query params)
MASSWEB_RUN_INTEGRATION_TESTS=1 MASSWEB_INTEGRATION_TARGETS=http://example.com/?q=1 \
    python -m unittest test.test_fuzzers
```

## Documentation

- Architecture guide: [START_HERE.md](START_HERE.md)
- API documentation: Run `make html` in `docs/` directory

## Getting Help

- **Issues**: Open an issue on GitHub
- **Documentation**: Check the `docs/` directory and `START_HERE.md`

## License

Apache 2.0 - See LICENSE.txt for details
