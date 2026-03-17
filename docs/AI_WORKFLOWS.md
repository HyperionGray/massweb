# AI-Powered Workflow Documentation

## Overview

This repository includes several GitHub Actions workflows that integrate with Large Language Model (LLM) providers for automated code review, issue analysis, and development assistance.

## Supported LLM Providers

### 1. OpenAI (GPT Models)
- Models: GPT-4, GPT-5, o1, o3, etc.
- Trigger labels: `gpt-*`, `openai:*`
- Environment: Requires `OPENAI_API_KEY` secret

### 2. Gemini (Google AI)
- Models: gemini-1.5-pro, gemini-1.5-flash, gemini-2.0-flash, etc.
- Trigger labels: `gemini:*`, `gemini-*`, `llm:gemini:*`
- Environment: Requires `GEMINI_API_KEY` secret

### 3. Anthropic (Claude)
- Models: claude-3, claude-3.5-sonnet, etc.
- Trigger labels: `claude-*`, `anthropic:*`
- Environment: Requires `ANTHROPIC_API_KEY` secret

## Workflows

### LLM Issue Review (`auto-llm-issue-review.yml`)

**Purpose**: Automatically reviews issues using AI when specific labels are added.

**Triggers**:
- Issue labeled with LLM-specific labels
- Manual workflow dispatch

**Label Formats**:
- Provider-specific: `openai:gpt-4`, `gemini:gemini-1.5-pro`, `anthropic:claude-3`
- Short format: `gpt-4`, `claude-3.5-sonnet`
- Generic: `llm:<provider>:<model>`

**Example Usage**:
1. Create or open an issue
2. Add label: `gemini:gemini-1.5-pro` or `gemini:gemini-2.0-flash`
3. Workflow automatically triggers and posts AI analysis as comment

### LLM PR Review (`auto-llm-pr-review.yml`)

**Purpose**: Reviews pull requests using AI for code quality, bugs, and suggestions.

**Triggers**:
- PR labeled with LLM-specific labels
- Manual workflow dispatch

**Features**:
- Analyzes code changes in the PR
- Provides suggestions and identifies issues
- Posts review as PR comment

### Advance Ball (`auto-advance-ball.yml`)

**Purpose**: Autonomous AI agent that advances work on issues/tasks.

**Features**:
- Reads issue content and context
- Makes decisions on next steps
- Can create commits and push changes
- Iteratively works toward issue resolution

## Gemini-Specific Information

### Default Model
- `gemini-1.5-pro` (recommended default model for most use cases)

### Available Models
- `gemini-1.5-pro` - Most capable, balanced
- `gemini-1.5-flash` - Faster, lighter
- `gemini-2.0-flash` - Latest version
- Other Gemini variants

### API Configuration
Gemini uses the Google AI API:
```
Base URL: https://generativelanguage.googleapis.com/v1beta/
Requires: GEMINI_API_KEY secret
```

### Label Examples
```
gemini:gemini-1.5-pro          # Recommended default model label
gemini:gemini-1.5-flash        # Specific model
gemini-2.0-flash               # Direct model name label
llm:gemini:gemini-1.5-pro      # Explicit format
```

## Setup Requirements

### Repository Secrets
Add these secrets in GitHub Settings > Secrets and variables > Actions:

```
OPENAI_API_KEY      # For OpenAI/GPT
GEMINI_API_KEY      # For Google Gemini
ANTHROPIC_API_KEY   # For Anthropic/Claude
```

### Repository Variables (Optional)
```
LLM_PROVIDER        # Default provider
LLM_MODEL           # Default model
OPENAI_BASE_URL     # Custom OpenAI endpoint
```

## Testing

To test if Gemini is working:

1. **Issue Test**: Create an issue and add label `gemini`
2. **PR Test**: Create a PR and add label `gemini:gemini-1.5-flash`
3. **Manual Test**: Go to Actions > Select workflow > Run workflow manually

## Troubleshooting

### Gemini Not Responding

1. Check that `GEMINI_API_KEY` secret is set
2. Verify label format is correct (`gemini`, `gemini:model-name`)
3. Check workflow runs in Actions tab for errors
4. Ensure self-hosted runner is available and healthy

### API Errors

- **401 Unauthorized**: Invalid or missing API key
- **429 Rate Limited**: Too many requests, wait and retry
- **400 Bad Request**: Invalid model name or parameters

## Advanced Usage

### Custom Model Selection
```yaml
# Workflow dispatch inputs
llm_provider: gemini
llm_model: gemini-2.0-flash
```

### Parallel Provider Testing
To compare providers, you can use different labels (one provider/model per label):
```
gemini:gemini-1.5-pro
gpt-4
claude-3.5-sonnet
```

**Important:** The provided workflows (`auto-llm-issue-review.yml` and `auto-llm-pr-review.yml`) use `concurrency.cancel-in-progress: true` per issue/PR. If you add multiple labels in quick succession, earlier runs will usually be cancelled, so you will typically only see the _latest_ provider’s review comment. To get separate comments from multiple providers, either:
- Add and process one label at a time (wait for each workflow run to finish before adding the next label), or
- Fork/adjust the workflows to change the `concurrency` settings so multiple provider runs can complete in parallel.

<!--
Summary of changes:
- Clarified that concurrency.cancel-in-progress prevents guaranteed parallel comments for multiple providers.
- Updated wording so expectations match the actual workflow behavior.

TODO checklist:
- [ ] Consider adding a docs snippet showing an example concurrency configuration that allows true parallel provider runs.
- [ ] Optionally document recommended timing (e.g., how to confirm a run is finished before adding another label).
-->
