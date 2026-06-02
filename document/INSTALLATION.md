# 🔩 Droid LLM Hunter - Installation Guide

→ [Back to README](../README.md)

---

## Requirements

- Python 3.11+
- Apktool (Required)
- JADX (Optional but Recommended for `hybrid` / `jadx` decompiler mode)
- Java (Required for Apktool and JADX)

---

## Standard Installation

### 1. Clone the Repository

```bash
git clone https://github.com/roomkangali/droid-llm-hunter.git
cd droid-llm-hunter
```

### 2. Create and Activate a Virtual Environment

- **Linux/macOS:**
  ```bash
  python3 -m venv venv
  source venv/bin/activate
  ```

- **Windows:**
  ```bash
  python -m venv venv
  venv\\Scripts\\activate
  ```

### 3. Install Python Dependencies

```bash
pip install -r requirements.txt
```

### 4. Install Apktool & JADX

- **Apktool (Required):** Must be installed and available in your PATH.
  → [Installation Instructions](https://apktool.org/docs/install)

- **JADX (Optional but Recommended):** Required if you want to use `jadx` or `hybrid` decompiler modes.
  → [GitHub Releases](https://github.com/skylot/jadx)

### 5. Configure the Tool

Open `config/settings.yaml` and set your LLM provider and API key:

```yaml
llm:
  provider: "gemini"
  gemini_model: "gemini-2.5-flash"
  gemini_api_key: "YOUR_API_KEY_HERE"
```

Or use the interactive wizard:

```bash
python dlh.py config wizard
```

---

## Docker Installation

Running via Docker ensures all dependencies (Java, Python, Apktool) are correctly configured without manual setup.

### 1. Build Image

```bash
docker build -t dlh .
```

### 2. Run Scan

Mount the volume to access input files and save output results.

```bash
# Syntax:
docker run -v [HOST_DIR]:/app/output dlh scan [APK_FILE]

# Example (APK is in the 'output' folder of current directory):
docker run --rm -v $(pwd)/output:/app/output dlh scan [APK_FILE]
```

### 3. Run with Flags

```bash
docker run --rm -v $(pwd)/output:/app/output dlh -v scan [APK_FILE]
```

### 4. Custom Configuration (Live Editing)

To edit `settings.yaml` without rebuilding the image, mount the local config file:

```bash
docker run --rm \
  -v $(pwd)/output:/app/output \
  -v $(pwd)/config/settings.yaml:/app/config/settings.yaml \
  dlh scan [APK_FILE]
```

_Changes made to `config/settings.yaml` on the host machine will immediately apply to the scan._

---

## Verifying the Installation

```bash
python dlh.py --help
```

You should see the Droid LLM Hunter banner and the list of available commands.
