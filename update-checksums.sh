#!/usr/bin/env bash
# Pins the installers to the current agent files. Run after editing an agent.
set -euo pipefail
cd "$(dirname "$0")"
sha() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1
}
sum="$(sha alfred-agent.sh)"
psum="$(sha alfred-agent.ps1)"
for f in install-macos.sh install-linux.sh; do
  sed -E -i.bak "s/^AGENT_SHA256=\"[^\"]*\"/AGENT_SHA256=\"$sum\"/" "$f" && rm -f "$f.bak"
done
sed -E -i.bak "s/^( *)\\\$AgentSha256 = '[^']*'/\\1\$AgentSha256 = '$psum'/" install-windows.ps1 && rm -f install-windows.ps1.bak
echo "alfred-agent.sh  $sum"
echo "alfred-agent.ps1 $psum"
