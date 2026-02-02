# Droid LLM Hunter - GitHub Action

This action allows you to integrate **Droid LLM Hunter** directly into your GitHub Actions workflow to automatically scan Android applications (APKs) for vulnerabilities using AI.

## Usage

### Pre-requisites

1.  **Build your APK**: Your workflow must build the APK first (e.g., using `gradlew`).
2.  **API Key**: You need an API key for your chosen LLM provider (Gemini, OpenAI, etc.) stored in GitHub Secrets.

> [!IMPORTANT]
> **Provider Recommendation**: For CI/CD (GitHub Actions), we strictly recommend using **Cloud APIs** (Gemini, Groq, OpenAI).
> Using **Ollama** is not recommended on standard GitHub Runners because they lack GPUs and require complex setup to run the Ollama service, leading to timeouts or failures.

### Example Workflow

Create a file `.github/workflows/security.yml` in your repository:

```yaml
name: Security Scan

on:
  push:
    branches: ["main"]
  pull_request:
    branches: ["main"]
  schedule:
    - cron: "0 0 * * *" # Run nightly

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read

    steps:
      - uses: actions/checkout@v4

      - name: Set up JDK 17
        uses: actions/setup-java@v4
        with:
          java-version: "17"
          distribution: "temurin"

      - name: Build with Gradle
        run: ./gradlew assembleDebug

      - name: Droid LLM Hunter Scan
        uses: roomkangali/droid-llm-hunter@v1.1.6 # Replace with tag/version if available
        with:
          apk-path: app/build/outputs/apk/debug/app-debug.apk
          provider: "gemini"
          model: "gemini-1.5-pro"
          api-key: ${{ secrets.GEMINI_API_KEY }}

      - name: Upload Report
        uses: actions/upload-artifact@v4
        with:
          name: security-report
          path: droid-llm-report.json
```

## Inputs

| Input      | Description                                             | Required | Default          |
| ---------- | ------------------------------------------------------- | -------- | ---------------- |
| `apk-path` | Path to the APK file relative to the repository root.   | **Yes**  | N/A              |
| `provider` | LLM Provider (`gemini`, `openai`, `groq`, `anthropic`). | **Yes**  | `gemini`         |
| `api-key`  | Your API Key. Should be passed via secrets.             | **Yes**  | N/A              |
| `model`    | Specific model name (e.g., `gpt-4`).                    | No       | Provider default |

## Outputs

The action generates a `droid-llm-report.json` file in the root of the workspace. You should upload this as an artifact.

## Behavior

This action is **Non-Blocking** by default. It will generate a report but will not fail the build if vulnerabilities are found, unless a critical tool error occurs. This is to account for potential False Positives common in AI analysis.
