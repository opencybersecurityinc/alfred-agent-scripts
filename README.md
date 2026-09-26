# Alfred Device Monitor scripts

Public installers and agents for the Alfred Device Monitor. The agent reports basic device posture to your Alfred workspace every hour. It reports a hardware identifier, hostname, OS and version, serial number, and disk encryption state.

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

Set `ALFRED_NOSTART=true` to install without enrolling or starting the schedule.

## Commands

| Command | Purpose |
| --- | --- |
| `checkin` | Report posture, enrolling first if the device is unknown |
| `enroll` | Register the device |
| `status` | Show local configuration, scheduler, and registration |
| `check-registration` | Exit `0` if registered and `3` if not |
| `report` | Print the JSON report without sending it |
| `uninstall` | Remove the agent, the schedule, and the configuration |

On macOS and Linux, run `sudo alfred-agent <command>`. On Windows, run `powershell -File "C:\ProgramData\Alfred Device Monitor\alfred-agent.ps1" <command>` as Administrator.

## File locations

| Platform | Agent | Configuration and key | Schedule |
| --- | --- | --- | --- |
| macOS | `/usr/local/bin/alfred-agent` | `/Library/Application Support/Alfred Device Monitor` | LaunchDaemon `com.alfred.devicemonitor` |
| Linux | `/usr/local/bin/alfred-agent` | `/etc/alfred-agent` | `alfred-agent.timer` |
| Windows | `C:\ProgramData\Alfred Device Monitor\alfred-agent.ps1` | same directory | Task `Alfred Device Monitor` (SYSTEM) |

## Security model

- Each installer downloads the agent over HTTPS and verifies a pinned SHA-256 before installing it. If the hashes differ, the install stops.
- The API address must use `https://`. The agent refuses any other scheme.
- The key is stored in a file readable only by root, or by SYSTEM and Administrators on Windows. The agent refuses to run if the file permissions are looser.
- The agent does not pass the key on the command line; `curl` reads it from a config file.
- Inputs such as the key format, email, region and URL are validated before anything is written.
- The agent only sends the fields listed above. It does not read files, browsing data, or user content, and it does not run remote commands.

## Maintainers

After editing `alfred-agent.sh` or `alfred-agent.ps1`, run `./update-checksums.sh` and commit the updated installers in the same change.
