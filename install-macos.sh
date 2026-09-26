#!/bin/bash
set -e

# Environment variables:
# ALFRED_KEY (the Alfred per-domain secret key)
# ALFRED_OWNER_EMAIL (the email of the person who owns this computer)
# ALFRED_REGION (the region Alfred Device Monitor talks to, such as "us", "eu" or "aus".)

PKG_URL="https://agent-downloads.trust.builders/targets/versions/1.0.0/alfred-universal.pkg"
# Checksum needs to be updated when PKG_URL is updated.
CHECKSUM="REPLACE_WITH_ALFRED_PKG_SHA256"
DEVELOPER_ID="Open Cybersecurity LLC (REPLACE_WITH_APPLE_TEAM_ID)"
CERT_SHA_FINGERPRINT="REPLACE_WITH_ALFRED_CERT_SHA256_FINGERPRINT"
PKG_PATH="$(mktemp -d)/alfred.pkg"
ALFRED_CONF_PATH="/etc/alfred.conf"

##
# Alfred needs to be installed as root; use sudo if not already uid 0
##
if [ $(echo "$UID") = "0" ]; then
    SUDO=''
else
    SUDO='sudo -E'
fi

if [ -z "$ALFRED_KEY" ]; then
    printf "\033[31m
You must specify the ALFRED_KEY environment variable in order to install Alfred Device Monitor.
\n\033[0m\n"
    exit 1
fi

if [ -z "$ALFRED_OWNER_EMAIL" ]; then
    printf "\033[31m
You must specify the ALFRED_OWNER_EMAIL environment variable in order to install Alfred Device Monitor.
\n\033[0m\n"
    exit 1
fi

if [ -z "$ALFRED_REGION" ]; then
    printf "\033[31m
You must specify the ALFRED_REGION environment variable in order to install Alfred Device Monitor.
\n\033[0m\n"
    exit 1
fi


function onerror() {
    printf "\033[31m$ERROR_MESSAGE
Something went wrong while installing Alfred Device Monitor.

If you're having trouble installing, please send an email to support@trust.builders, and we'll help you fix it!
\n\033[0m\n"
}
trap onerror ERR

##
# Download Alfred Device Monitor
##
printf "\033[34m\n* Downloading Alfred Device Monitor\n\033[0m"
rm -f $PKG_PATH
curl --progress-bar $PKG_URL >$PKG_PATH

##
# Checksum
##
printf "\033[34m\n* Ensuring checksums match\n\033[0m"
downloaded_checksum=$(shasum -a256 $PKG_PATH | cut -d" " -f1)
if [ $downloaded_checksum = $CHECKSUM ]; then
    printf "\033[34mChecksums match.\n\033[0m"
else
    printf "\033[31m Checksums do not match. Please contact support@trust.builders \033[0m\n"
    rm -f $PKG_PATH
    exit 1
fi

##
# Check Developer ID
##
printf "\033[34m\n* Ensuring package Developer ID matches\n\033[0m"

if pkgutil --check-signature $PKG_PATH | /usr/bin/grep -q "$DEVELOPER_ID"; then
    printf "\033[34mDeveloper ID matches.\n\033[0m"
else
    printf "\033[31m Developer ID does not match. Please contact support@trust.builders \033[0m\n"
    rm -f $PKG_PATH
    exit 1
fi

##
# Check Developer Certificate Fingerprint
##
printf "\033[34m\n* Ensuring package Developer Certificate Fingerprint matches\n\033[0m"
if pkgutil --check-signature $PKG_PATH | /usr/bin/tr -d '\n' | /usr/bin/tr -d ' ' | /usr/bin/grep -q "SHA256Fingerprint:$CERT_SHA_FINGERPRINT"; then
    printf "\033[34mDeveloper Certificate Fingerprint matches.\n\033[0m"
else
    printf "\033[31m Developer Certificate Fingerprint does not match. Please contact support@trust.builders \033[0m\n"
    rm -f $PKG_PATH
    exit 1
fi

##
# Install Alfred Device Monitor
##
printf "\033[34m\n* Installing Alfred Device Monitor. You might be asked for your password...\n\033[0m"
ACTIVATION_REQUESTED_NONCE=$(date +%s000)
CONFIG="{\"ACTIVATION_REQUESTED_NONCE\":$ACTIVATION_REQUESTED_NONCE,\"AGENT_KEY\":\"$ALFRED_KEY\",\"OWNER_EMAIL\":\"$ALFRED_OWNER_EMAIL\",\"NEEDS_OWNER\":true,\"REGION\":\"$ALFRED_REGION\"}"
echo "$CONFIG" | $SUDO tee "$ALFRED_CONF_PATH" > /dev/null
$SUDO /bin/chmod 600 "$ALFRED_CONF_PATH"
$SUDO /usr/sbin/chown root:wheel "$ALFRED_CONF_PATH"
$SUDO /usr/sbin/installer -pkg $PKG_PATH -target / >/dev/null
rm -f $PKG_PATH

##
# check if Alfred Device Monitor is running
# return val 0 means running,
# return val 2 means running but needs to register
##
$SUDO /usr/local/alfred/alfred-cli status || [ $? == 2 ]

printf "\033[32m
Your Alfred Device Monitor is running properly. It will continue to run in the
background and submit data to Alfred.

You can check the status of Alfred Device Monitor using the \"alfred-cli status\" command.

If you ever want to stop Alfred Device Monitor, please use the toolbar icon or
the alfred-cli command. It will restart automatically at login.

To register this device to a new user, run \"alfred-cli register\" or click on \"Register Alfred Device Monitor\"
on the toolbar.
\033[0m"
