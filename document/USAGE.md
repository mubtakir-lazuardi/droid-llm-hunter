# 💡 Droid LLM Hunter - Usage Guide

→ [Back to README](../README.md)

---

## Basic Command

```bash
python dlh.py scan [APK file]
```

---

## Examples

- **Scan with verbose logging:**
  ```bash
  python dlh.py -v scan target.apk
  ```

- **Scan and generate PoC exploit scripts:**
  ```bash
  python dlh.py scan target.apk --generate-exploit
  ```

- **Skip the decompilation step:**
  ```bash
  python dlh.py --no-decompile scan target.apk
  ```

- **Run only specific rules:**
  ```bash
  python dlh.py --rules "sql_injection,webview_xss" scan target.apk
  ```

- **Save output to a specific file:**
  ```bash
  python dlh.py --output results.json scan target.apk
  ```

- **Use a configuration profile:**
  ```bash
  python dlh.py --profile pentest scan target.apk
  ```

- **List all available rules:**
  ```bash
  python dlh.py --list-rules
  ```

---

## Flags

```
+--------------------+------+----------------------------------------------------+
| Flag               | Short| Description                                        |
+--------------------+------+----------------------------------------------------+
| --verbose          | -v   | Enable verbose logging.                            |
| --output           | -o   | Output file for the scan results.                  |
| --no-decompile     | —    | Skip the decompilation step.                       |
| --rules            | -r   | Comma-separated list of rules to run.              |
| --list-rules       | —    | List all available rules and exit.                 |
| --profile          | -p   | Use a specific configuration profile.              |
+--------------------+------+----------------------------------------------------+
```

---

## Commands

```
+------------------------------------+---------------------------------------------------------------+
| Command                            | Description                                                   |
+------------------------------------+---------------------------------------------------------------+
| scan                               | Scan an APK file for vulnerabilities.                         |
| scan [APK] --generate-exploit      | Generate PoC scripts for confirmed vulnerabilities.           |
| config wizard                      | Run the interactive configuration wizard.                     |
| config provider <provider>         | Set the LLM provider.                                         |
| config model <model>               | Set the LLM model.                                            |
| config rules --enable <rules>      | Enable rules.                                                 |
| config rules --disable <rules>     | Disable rules.                                                |
| config validate                    | Validate the configuration file.                              |
| config show                        | Show the current configuration.                               |
| config profile create <name>       | Create a new profile.                                         |
| config profile list                | List all available profiles.                                  |
| config profile switch <name>       | Switch to a different profile.                                |
| config profile delete <name>       | Delete a profile.                                             |
| config attack-surface --enable     | Enable attack surface map generation.                         |
| config context-injection --enable  | Enable Cross-Reference Context Injection.                     |
| config filter-mode                 | Set or show the filter mode.                                  |
| config decompiler-mode             | Set or show decompiler mode (apktool, jadx, hybrid).          |
| list-rules                         | List all available rules.                                     |
+------------------------------------+---------------------------------------------------------------+
```
