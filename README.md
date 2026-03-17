# MassWeb

## Author

Hyperion Gray, LLC  
http://www.hyperiongray.com

## Purpose

MassWeb is a simple, scalable and super-fast web app fuzzer. It can also be used for mass requests of HTTP resources.

## Documentation

Full documentation: https://hyperiongray.atlassian.net/wiki/display/PUB/MassWeb

## Installation

```bash
pip install -e .
```

## AI-Powered Code Review

This repository supports automated AI-powered code reviews using multiple LLM providers:

### Supported Providers

- **OpenAI** (GPT models)
- **Gemini** (Google's Gemini models)
- **Anthropic** (Claude models)

### Using Gemini for Code Review

To trigger a Gemini-powered review on issues or pull requests, add one of these labels:

- `gemini` - Alias for the default Gemini model (`gemini-1.5-pro`)
- `gemini:<model-name>` - Uses specific Gemini model (e.g., `gemini:gemini-1.5-flash`)
- `gemini-1.5-pro`, `gemini-2.0-flash`, etc. - Direct model names

Bare provider labels are supported for all configured providers:
- `openai` -> default `gpt-5`
- `gemini` -> default `gemini-1.5-pro`
- `anthropic` -> default `claude-3-5-sonnet-latest`

### Workflow Triggers

The Gemini integration works through GitHub Actions workflows:

1. **Issue Review** (`auto-llm-issue-review.yml`) - Reviews issues when labeled
2. **PR Review** (`auto-llm-pr-review.yml`) - Reviews pull requests when labeled
3. **Advance Ball** (`auto-advance-ball.yml`) - Automated progress on tasks

For workflow details and troubleshooting, see [docs/AI_WORKFLOWS.md](docs/AI_WORKFLOWS.md).

### Manual Trigger

You can also manually trigger workflows via GitHub Actions UI and select:
- Provider: `gemini`
- Model: Your preferred Gemini model name

## License

MassWeb is released under the Apache 2.0 License.

## Issues

MassWeb is currently beta software. All issues should be directed to our GitHub repo.
