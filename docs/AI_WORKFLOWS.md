# AI-Powered Workflow Documentation

## Overview

This document covers the repository's core label-driven LLM workflows:

- `auto-llm-issue-review.yml`
- `auto-llm-pr-review.yml`
- `auto-advance-ball.yml`

Other AI workflows also exist (for example `auto-tag-based-review.yml` and `auto-amazonq-review.yml`), but they use different trigger and execution patterns.

## Supported LLM Providers

### OpenAI (GPT Models)
- Labels: `gpt-*`, `openai`, `openai:*`, `llm:openai:*`
- Default model for bare provider label: `gpt-5`
- Secret required: `OPENAI_API_KEY`

### Gemini (Google AI)
- Labels: `gemini`, `gemini-*`, `gemini:*`, `llm:gemini:*`
- Default model for bare provider label: `gemini-1.5-pro`
- Secret required: `GEMINI_API_KEY`

### Anthropic (Claude)
- Labels: `claude-*`, `anthropic`, `anthropic:*`, `llm:anthropic:*`
- Default model for bare provider label: `claude-3-5-sonnet-latest`
- Secret required: `ANTHROPIC_API_KEY`

## Label Parsing Rules

The LLM review workflows accept:

1. Explicit provider labels, for example:
   - `gemini:gemini-1.5-flash`
   - `openai:gpt-5`
   - `anthropic:claude-3-5-sonnet-latest`
2. Generic form:
   - `llm:<provider>:<model>`
3. Short model labels:
   - `gpt-5`
   - `gemini-2.0-flash`
   - `claude-3.5-sonnet`
4. Bare provider labels:
   - `openai`, `gemini`, `anthropic`
   - These map to provider defaults listed above.

## Workflows

### LLM Issue Review (`auto-llm-issue-review.yml`)

**Purpose**: Review issue content and post an AI analysis comment.

**Triggers**:
- Issue labeled with a supported LLM/model label
- Manual workflow dispatch

### LLM PR Review (`auto-llm-pr-review.yml`)

**Purpose**: Review PR diffs and post/update a structured review comment.

**Triggers**:
- PR labeled with a supported LLM/model label (or review label)
- PR synchronize events while a matching label is present
- Manual workflow dispatch

### Advance Ball (`auto-advance-ball.yml`)

**Purpose**: Autonomous implementation loop for issue/task progression.

**Capabilities**:
- Reads issue context
- Executes code changes
- Commits and pushes updates

## Setup Requirements

### Repository Secrets

Add these in GitHub Settings -> Secrets and variables -> Actions:

```
OPENAI_API_KEY
GEMINI_API_KEY
ANTHROPIC_API_KEY
```

### Optional Repository Variables

```
LLM_PROVIDER
LLM_MODEL
OPENAI_BASE_URL
```

## Testing

1. **Issue test**:
   - Create/open an issue
   - Add label `gemini` (or `gemini:gemini-1.5-flash`)
2. **PR test**:
   - Create/open a PR
   - Add label `gemini` (or any supported provider/model label)
3. **Manual test**:
   - Run either workflow from the Actions UI with explicit provider/model inputs

## Troubleshooting

### Gemini not responding

1. Verify `GEMINI_API_KEY` is set.
2. Verify the label is supported (`gemini`, `gemini:<model>`, `gemini-*`, or `llm:gemini:<model>`).
3. Review the Actions run logs for provider/model resolution and API errors.
4. Confirm the self-hosted runner is available.

### Multiple provider labels and concurrency

`auto-llm-issue-review.yml` and `auto-llm-pr-review.yml` run with `concurrency.cancel-in-progress: true` per issue/PR. If you add multiple labels quickly, newer runs can cancel older runs.

For provider comparison, run tests sequentially (wait for one run to finish before applying the next label).

### Common API failures

- **401 Unauthorized**: Missing/invalid API key
- **429 Too Many Requests**: Rate limit
- **400 Bad Request**: Invalid model name/parameters
