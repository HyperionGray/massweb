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
from massweb.targets.target import Target
from massweb.payloads.payload import Payload

# Create a target with query parameters to fuzz
target = Target("http://example.com/page?param=1&other=2", ttype="get")

# Define payloads tagged with the check type(s) to run
payloads = [
    Payload("' OR '1'='1", check_type_list=["sqli"]),
    Payload("<script>alert(1)</script>", check_type_list=["xss"]),
]

# Create fuzzer with targets and payloads
fuzzer = WebFuzzer(targets=[target], payloads=payloads)

# Generate concrete fuzzy targets, then run the fuzzing process
fuzzer.generate_fuzzy_targets()
results = fuzzer.fuzz()

# Process results
for result in results:
    print(result)
```

### Mass HTTP Requests

```python
from massweb.mass_requests.mass_request import MassRequest

mr = MassRequest(num_threads=5, time_per_url=10)

# GET a list of URLs
mr.get_urls(["http://example.com/", "http://example.com/page"])
for target, response in mr.results:
    print(target.url, response)
```

### Proxy Rotation

```python
from massweb.proxy_rotator.proxy_rotate import get_random_proxy

proxy_list = [
    {"http": "http://proxy1.example.com:8080"},
    {"http": "http://proxy2.example.com:8080"},
]

# Pass the proxy list directly to MassRequest or WebFuzzer
mr = MassRequest(proxy_list=proxy_list)
```

## Running Tests

```bash
# Run all tests using unittest discovery (preferred)
python -m unittest discover test/

# Run a specific test file
cd test && python -m unittest test_webfuzzer_offline
```

## Documentation

- Full documentation: https://hyperiongray.atlassian.net/wiki/display/PUB/MassWeb
- API documentation: Run `make html` in the `docs/` directory

## Getting Help

- **Issues**: Open an issue on GitHub
- **Documentation**: Check the `docs/` directory

## License

Apache 2.0 - See LICENSE.txt for details
