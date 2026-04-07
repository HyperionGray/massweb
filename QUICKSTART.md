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
from massweb.targets.target import Target
from massweb.payloads.payload import Payload

# Create a target URL with a query parameter to fuzz
target = Target("http://example.com/page?param=1")

# Define payloads to inject
payloads = [Payload("'"), Payload("1 OR 1=1"), Payload("<script>alert(1)</script>")]

# Create fuzzer with targets and payloads
fuzzer = WebFuzzer(targets=[target], payloads=payloads)

# Generate concrete fuzzy targets, then run the fuzzing process
fuzzy_targets = fuzzer.generate_fuzzy_targets()
results = fuzzer.fuzz()

# Process results
for result in results:
    print(result)
```

### Mass Crawling

```python
from massweb.masscrawler.masscrawl import MassCrawl

# Create crawler with seed URLs
crawler = MassCrawl(seeds=["http://example.com"])

# Run the crawl
crawler.crawl()

# View discovered targets
for target in crawler.targets:
    print(target.url)
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

- `gemini:gemini-1.5-pro` - Google Gemini 1.5 Pro (recommended default)
- `gemini:gemini-1.5-flash` - Google Gemini 1.5 Flash (faster, cheaper)
- `gpt-4` - OpenAI GPT-4
- `claude-3.5-sonnet` - Anthropic Claude

For more details, see [docs/AI_WORKFLOWS.md](docs/AI_WORKFLOWS.md)

## Configuration

### Proxy Settings

```python
from massweb.fuzzers.web_fuzzer import WebFuzzer
from massweb.targets.target import Target

# Proxies are dicts mapping scheme to address
proxy_list = [{"http": "proxy1.com:8080"}, {"http": "proxy2.com:8080"}]
target = Target("http://example.com/page?q=1")
fuzzer = WebFuzzer(targets=[target], proxy_list=proxy_list)
```

### Payload Customization

```python
from massweb.payloads.payload import Payload

# Create payloads manually
payloads = [Payload("'"), Payload("1 OR 1=1"), Payload("<script>")]
```

## Running Tests

```bash
# Install test dependencies first
pip install -e .
pip install beautifulsoup4

# Run all tests
python -m unittest discover test/

# Run a specific test module
python -m unittest test.vuln_checks.test_sqli
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

### Check a Response for SQL Injection
```python
from massweb.vuln_checks.sqli import SQLICheck

check = SQLICheck()
response_body = "You have an error in your SQL syntax"
if check.check(response_body):
    print("SQL injection detected!")
```

### Check a Response for Directory Traversal
```python
from massweb.vuln_checks.trav import TravCheck

check = TravCheck()
response_body = "root:x:0:0:root:/root:/bin/bash"
if check.check(response_body):
    print("Directory traversal detected!")

## Next Steps

1. Read the full documentation
2. Explore example scripts in `examples/` (if available)
3. Try the AI-powered workflows for code review
4. Join discussions in GitHub Issues

## License

Apache 2.0 - See LICENSE.txt for details
