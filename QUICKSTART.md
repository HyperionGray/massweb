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

## Basic Usage

### Web Fuzzing

```python
from massweb.fuzzers.web_fuzzer import WebFuzzer
from massweb.targets.fuzzy_target import FuzzyTarget

# Create a target
target = FuzzyTarget(
    url="http://example.com/page?param=FUZZ",
    method="GET",
    name="example-param-fuzz",
)

# Define payloads to fuzz with
payloads = ["FUZZ1", "FUZZ2", "FUZZ3"]

# Create fuzzer with targets and payloads
fuzzer = WebFuzzer(targets=[target], payloads=payloads)

# Generate concrete fuzzy targets, then run the fuzzing process
fuzzer.generate_fuzzy_targets()
results = fuzzer.fuzz()

# Process results
for result in results:
    print(f"Status: {result.status_code}, URL: {result.url}")
```

### Mass Crawling

```python
from massweb.masscrawler.masscrawl import MassCrawl

# Initialize crawler with one or more seed URLs
crawler = MassCrawl(seeds=["http://example.com"])

# Run crawler (updates crawler.targets in place)
crawler.crawl(depth=2)

# View discovered pages
for page in crawler.targets:
    print(page.url)
```

## Using AI-Powered Workflows (Gemini & Others)

### Quick Test

1. **Test Gemini on an Issue**:
   - Create or open any issue in this repository
   - Add the label: `gemini:gemini-1.5-pro`
   - Wait for the automated review comment

2. **Test Gemini on a Pull Request**:
   - Create a PR with some code changes
   - Add the label: `gemini:gemini-1.5-flash`
   - Review the AI-generated feedback

### Available AI Labels

- `gemini` - Google Gemini using default model (`gemini-1.5-pro` unless overridden)
- `gemini:gemini-1.5-pro` - Google Gemini 1.5 Pro (explicit model label)
- `gemini:gemini-1.5-flash` - Google Gemini 1.5 Flash (faster, cheaper)
- `openai` - OpenAI using default model (repository-configured)
- `anthropic` - Anthropic using default model (repository-configured)
- `gpt-4` - OpenAI GPT-4
- `claude-3.5-sonnet` - Anthropic Claude

For more details, see [docs/AI_WORKFLOWS.md](docs/AI_WORKFLOWS.md)

## Configuration

### Proxy Settings

```python
from massweb.fuzzers.web_fuzzer import WebFuzzer
from massweb.targets.target import Target
from massweb.payloads.payload import Payload

target = Target("http://example.com/page?param=FUZZ")
payloads = [Payload("FUZZ", ["xss"])]

# Provide proxies directly to the fuzzer as requests-compatible proxy dicts
proxies = [
    {"http": "http://proxy1.com:8080", "https": "http://proxy1.com:8080"},
    {"http": "http://proxy2.com:8080", "https": "http://proxy2.com:8080"},
]
fuzzer = WebFuzzer(targets=[target], payloads=payloads, proxy_list=proxies)
```

### Payload Customization

```python
from massweb.fuzzers.web_fuzzer import WebFuzzer
from massweb.payloads.payload import Payload
from massweb.targets.target import Target

target = Target("http://example.com/page?param=FUZZ")

# Create custom payload objects
payloads = [
    Payload("' OR '1'='1", ["sqli"]),
    Payload("<script>alert(1)</script>", ["xss"]),
]

fuzzer = WebFuzzer(targets=[target], payloads=payloads)
```

## Running Tests

```bash
# Run all tests
python -m pytest test/

# Run specific test module
python -m pytest test/test_fuzzers.py
```

## Documentation

- Full documentation: https://hyperiongray.atlassian.net/wiki/display/PUB/MassWeb
- API documentation: Run `make html` in `docs/` directory
- AI Workflows: [docs/AI_WORKFLOWS.md](docs/AI_WORKFLOWS.md)

## Getting Help

- **Issues**: Open an issue on GitHub
- **AI Review**: Add `gemini` label to get AI-powered assistance
- **Documentation**: Check the `docs/` directory

## Common Tasks

### Scan for SQL Injection
```python
from massweb.vuln_checks.sqli import SQLICheck

check = SQLICheck(target)
vulnerabilities = check.scan()
```

### Directory Traversal Check
```python
from massweb.vuln_checks.trav import TravCheck

check = TravCheck(target)
results = check.scan()
```

## Next Steps

1. Read the full documentation
2. Explore example scripts in `examples/` (if available)
3. Try the AI-powered workflows for code review
4. Join discussions in GitHub Issues

## License

Apache 2.0 - See LICENSE.txt for details
