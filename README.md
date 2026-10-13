# Alfred Device Monitor scripts

Public installers and agents for the Alfred Device Monitor. The agent reports basic device posture to your Alfred workspace every hour. It reports a hardware identifier, hostname, OS and version, serial number, and disk encryption state. Compliance is evaluated by Alfred from these facts, not by the agent. Each check-in also sends an inventory of the AI clients and MCP servers configured on the device, with every secret value masked.

## What you need

- An agent key (`alfa_...`), created in Alfred under **Settings > Agent keys**.
- The owner's email, the region (`us`, `eu` or `aus`), and your Alfred address (`https://...`).
- Administrator or root rights on the device.

## Install

### macOS (launchd)

```bash
curl -fsSLo /tmp/install-alfred.sh https://raw.githubusercontent.com/opencybersecurityinc/alfred-agent-scripts/main/install-macos.sh
sudo ALFRED_KEY='alfa_...' ALFRED_OWNER_EMAIL='person@example.com' ALFRED_REGION='us' \
  ALFRED_API_URL='https://alfred.example.com' bash /tmp/install-alfred.sh
```

### Linux (systemd)

```bash
curl -fsSLo /tmp/install-alfred.sh https://raw.githubusercontent.com/opencybersecurityinc/alfred-agent-scripts/main/install-linux.sh
sudo ALFRED_KEY='alfa_...' ALFRED_OWNER_EMAIL='person@example.com' ALFRED_REGION='us' \
  ALFRED_API_URL='https://alfred.example.com' bash /tmp/install-alfred.sh
```

### Windows (Task Scheduler, from an elevated PowerShell)

```powershell
$env:ALFRED_KEY = 'alfa_...'
$env:ALFRED_OWNER_EMAIL = 'person@example.com'
$env:ALFRED_REGION = 'us'
$env:ALFRED_API_URL = 'https://alfred.example.com'
irm https://raw.githubusercontent.com/opencybersecurityinc/alfred-agent-scripts/main/install-windows.ps1 | iex
```

### Install options

| Variable | Default | Effect |
| --- | --- | --- |
| `ALFRED_NOSTART` | `false` | `true` installs the agent and configuration without enrolling or starting the schedule |
| `ALFRED_SKIP_REGISTRATION_CHECK` | `false` | `true` skips the post-install check that Alfred has registered the device |
| `ALFRED_REGISTRATION_ATTEMPTS` | `6` | Registration checks before the installer gives up (1 to 99) |
| `ALFRED_REGISTRATION_DELAY` | `10` | Seconds between registration checks (0 to 999) |
| `ALFRED_AGENT_DIR` | unset | Install the agent from a local directory instead of downloading it; the pinned SHA-256 still applies |

Switches accept only `true`, `false` or an empty value. Any other value stops the install.

The installer writes an activation nonce (the install time in epoch milliseconds) to the configuration. Alfred refuses an enrollment whose nonce is older than the last one seen for the device, so an old configuration copied onto another machine cannot replay its enrollment.

## Commands

| Command | Purpose |
| --- | --- |
| `checkin` | Report posture, enrolling first if the device is unknown |
| `enroll` | Register the device |
| `status` | Show local configuration, scheduler, and registration |
| `check-registration` | Exit `0` if registered and `3` if not |
| `report` | Print the JSON report without sending it |
| `ai-scan` | Print the AI clients and MCP servers found, with secrets masked |
| `ai-report` | Send the AI inventory now |
| `uninstall` | Remove the agent, the schedule, and the configuration |

`status` exits `0` when the schedule is running and Alfred knows the device, `2` when the schedule is running but the device is not registered, and `1` when the schedule is not running.

On macOS and Linux, run `sudo alfred-agent <command>`. On Windows, run `powershell -File "C:\ProgramData\Alfred Device Monitor\alfred-agent.ps1" <command>` as Administrator.

## AI inventory

The collector looks for the configuration files of common AI clients and coding assistants, in each user's home and in system-wide locations, on macOS, Linux and Windows. Examples include Claude Code and Claude Desktop, Codex, Cursor, VS Code, GitHub Copilot CLI, JetBrains IDEs and Junie, Windsurf, Zed and Gemini CLI.

For each client it reports the client name and the MCP servers it declares. For each server it reports the name, the transport, the command or URL, and the tools when the configuration declares them.

Secrets are masked on the device before anything is sent:

- Environment variables and HTTP headers declared for a server are never sent, neither names nor values.
- Arguments that follow flags such as `--token`, `--api-key` or `--password`, `key=value` arguments with secret-like names, and values that look like keys or tokens are replaced with `{secret}`.
- Query strings and credentials in the user part are dropped from URLs, and secret-like path segments are replaced with `{secret}`.
- Paths inside a user's home are rewritten to start with `~`, so the report does not include user names.

Alfred computes the fingerprint of each asset on the server and links it to the device and its owner.

## File locations

| Platform | Agent | Configuration and key | Schedule |
| --- | --- | --- | --- |
| macOS | `/usr/local/bin/alfred-agent` | `/Library/Application Support/Alfred Device Monitor` | LaunchDaemon `com.alfred.devicemonitor` |
| Linux | `/usr/local/bin/alfred-agent` | `/etc/alfred-agent` | `alfred-agent.timer` |
| Windows | `C:\ProgramData\Alfred Device Monitor\alfred-agent.ps1` | same directory | Task `Alfred Device Monitor` (SYSTEM) |

## Security model

- Each installer downloads the agent over HTTPS and verifies a pinned SHA-256 before installing it. If the hashes differ, or no hashing tool is available, the install stops.
- When a signing certificate is pinned, the installer also verifies the agent signature. On macOS and Linux it checks the certificate SHA-256 fingerprint and its subject before verifying the signature with `openssl`. On Windows it requires a valid Authenticode signature whose thumbprint and subject match the pin.
- After installing, the installer checks that Alfred has registered the device, retrying a few times before it reports a failure.
- The API address must use `https://`. The agent refuses any other scheme.
- The key is stored in a file readable only by root, or by SYSTEM and Administrators on Windows. The agent refuses to run if the file permissions are looser.
- The agent does not pass the key on the command line; `curl` reads it from a config file.
- Inputs such as the key format, email, region and URL are validated before anything is written.
- The agent only sends the fields listed above. Apart from AI client configuration files, it does not read files, browsing data, or user content, and it does not run remote commands.
- The configuration directory and its files are owned by root (or SYSTEM) with mode `0600`. On macOS and Linux, the collector only reads AI client files owned by the user whose home it scans or by root, skips files larger than 1 MiB, and caps the number of projects and servers per device.

## Maintainers

After editing `alfred-agent.sh` or `alfred-agent.ps1`, run `./update-checksums.sh` and commit the updated installers in the same change.

Tests:

- `bash tests/run-ai-scan.sh` and `pwsh tests/run-ai-scan-windows.ps1` compare the collector output with golden files under `tests/ai-scan` and `tests/ai-scan-windows`. Any fixture value containing `CANARY` is a secret, and the tests fail if it reaches the output. Set `UPDATE_GOLDEN=1` to rewrite the expected files after a deliberate change.
- `bash tests/smoke-install.sh` installs the agent for real against a local mock API (`tests/mock-alfred.py`) with a fake key, then uninstalls it. It needs passwordless `sudo`, so run it on a disposable machine.

CI runs shellcheck, PSScriptAnalyzer, the checksum pin check, the golden tests on Linux, macOS and Windows (PowerShell 7 and 5.1), and the smoke install on Linux and macOS.
