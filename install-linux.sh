#!/bin/bash

# Available environment variables:
# ALFRED_KEY (the Alfred per-domain secret key)
# ALFRED_OWNER_EMAIL (the email of the person who owns this computer)
# ALFRED_REGION (the region Alfred Agent talks to, such as "us", "eu" or "aus".)
# ALFRED_NOSTART (if true, then don't start the service upon installation.)

set -e

DEB_URL="https://agent-downloads.alfred.app/targets/versions/2.19.0/alfred-amd64.deb"
# Checksums need to be updated when DEB_URL is updated.
DEB_CHECKSUM="e2e708f2ce4697e9c116dcb2e59ba35a02db128887247782a70af6b9b39ff706"
DEB_PATH="$(mktemp -d)/alfred.deb"
DEB_INSTALL_CMD="dpkg -Ei"

UUID_PATH="/sys/class/dmi/id/product_uuid"

# OS/Distro Detection
# Try lsb_release, fallback with /etc/issue then uname command
# Detection code taken from https://github.com/DataDog/datadog-agent/blob/master/cmd/agent/install_script.sh
KNOWN_DISTRIBUTION="(Debian|Ubuntu)"
DISTRIBUTION=$(lsb_release -d 2>/dev/null | grep -Eo $KNOWN_DISTRIBUTION  || grep -Eo $KNOWN_DISTRIBUTION /etc/issue 2>/dev/null || grep -Eo $KNOWN_DISTRIBUTION /etc/Eos-release 2>/dev/null || grep -m1 -Eo $KNOWN_DISTRIBUTION /etc/os-release 2>/dev/null || uname -s)

if [ -f /etc/debian_version -o "$DISTRIBUTION" == "Debian" -o "$DISTRIBUTION" == "Ubuntu" ]; then
    OS="Debian"
fi

##
# Alfred needs to be installed as root; use sudo if not already uid 0
##
if [ $(echo "$UID") = "0" ]; then
    SUDO=''
else
    SUDO='sudo'
fi

function get_platform() {
    if ! command -v lsb_release &> /dev/null; then
        echo "${DISTRIBUTION}"
    else
	lsb_release -sd
    fi
}

if [ "${OS}" == "Debian" ]; then
    printf "\033[34m\n* Debian detected \n\033[0m"
    PKG_URL=$DEB_URL
    PKG_PATH=$DEB_PATH
    INSTALL_CMD=$DEB_INSTALL_CMD
    CHECKSUM=$DEB_CHECKSUM
else
    printf "\033[31m
Cannot install Alfred Agent on unsupported platform $(get_platform).
Please reach out to support@opencybersecurity.co for help.
\n\033[0m\n"
    exit 1
fi

if [ ! -f "$UUID_PATH" ]; then
    printf "\033[31m
Unable to detect hardware UUID – Alfred Agent is only supported on platforms which provide a value in $UUID_PATH
\n\033[0m\n"
    exit 1
fi

hardware_uuid=$($SUDO cat $UUID_PATH)

printf "\033[34m\nHardware UUID: $hardware_uuid\n\033[0m"

bad_uuids=(
    "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF"
    "ffffffff-ffff-ffff-ffff-ffffffffffff"
    "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA"
    "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
    "00000000-0000-0000-0000-000000000000"
    "11111111-1111-1111-1111-111111111111"
    "03000200-0400-0500-0006-000700080009"
    "03020100-0504-0706-0809-0a0b0c0d0e0f"
    "03020100-0504-0706-0809-0a0b0c0d0e0f"
    "10000000-0000-8000-0040-000000000000"
    "01234567-8910-1112-1314-151617181920"
)

for uuid in ${bad_uuids[*]}; do
    if [ "$uuid" = "$hardware_uuid" ]; then
        printf "\033[31m
Invalid hardware UUID – Alfred Agent is only supported on platforms which provide a unique value in $UUID_PATH
\n\033[0m\n"
        exit 1
    fi
done
printf "\033[34m\nUUID check passed.\n\033[0m"



if [ -z "$ALFRED_KEY" ]; then
    printf "\033[31m
You must specify the ALFRED_KEY environment variable in order to install Alfred Agent.
\n\033[0m\n"
    exit 1
fi
if [ -z "$ALFRED_OWNER_EMAIL" ]; then
    printf "\033[31m
You must specify the ALFRED_OWNER_EMAIL environment variable in order to install Alfred Agent.
\n\033[0m\n"
    exit 1
fi
if [ -z "$ALFRED_REGION" ]; then
    printf "\033[31m
You must specify the ALFRED_REGION environment variable in order to install Alfred Agent.
\n\033[0m\n"
    exit 1
fi

function onerror() {
    printf "\033[31m$ERROR_MESSAGE
Something went wrong while installing Alfred Agent.

If you're having trouble installing, please send an email to support@opencybersecurity.co, and we'll help you fix it!
\n\033[0m\n"
}
trap onerror ERR

##
# Download Alfred Agent
##
printf "\033[34m\n* Downloading Alfred Agent\n\033[0m"
rm -f $PKG_PATH
curl --progress-bar --output $PKG_PATH $PKG_URL

##
# Checksum
##
printf "\033[34m\n* Ensuring checksums match\n\033[0m"

if [ -x "$(command -v shasum)" ]; then
  downloaded_checksum=$(shasum -a256 $PKG_PATH | cut -d" " -f1)
elif [ -x "$(command -v sha256sum)" ]; then
  downloaded_checksum=$(sha256sum $PKG_PATH | cut -d" " -f1)
else
  printf "\033[31m shasum is not installed. Not checking binary contents. \033[0m\n"
  # For now, don't fail if shasum is not installed. Delete this check if you want to
  # ensure that the checksum is always enforced.
  CHECKSUM=""
fi

if [ $downloaded_checksum = $CHECKSUM ]; then
    printf "\033[34mChecksums match.\n\033[0m"
else
    printf "\033[31m Checksums do not match. Please contact support@opencybersecurity.co \033[0m\n"
    exit 1
fi

##
# Install Alfred Agent
##
printf "\033[34m\n* Installing Alfred Agent. You might be asked for your password...\n\033[0m"
$SUDO env \
    ALFRED_KEY="$ALFRED_KEY" \
    ALFRED_OWNER_EMAIL="$ALFRED_OWNER_EMAIL" \
    ALFRED_REGION="$ALFRED_REGION" \
    ${ALFRED_NOSTART:+ALFRED_NOSTART="$ALFRED_NOSTART"} \
    $INSTALL_CMD $PKG_PATH


##
# Check whether Alfred Agent is registered. It may take a couple of seconds,
# so try 5 times with 5-second pauses in between.
##
if [ -z "$ALFRED_SKIP_REGISTRATION_CHECK" ] && [ -z "$ALFRED_NOSTART" ]; then
    printf "\033[34m\n* Checking registration with Alfred\n\033[0m"
    registration_success=false
    for i in {1..5}
    do
        # Pause first, as the chances of registration working immediately are low.
        sleep 5
        echo "Attempt $i/5"
        if $SUDO /var/alfred/alfred-cli check-registration; then
            registration_success=true
            break
        fi
    done

    if [ "$registration_success" = false ] ; then
        printf "\033[31m
    Could not verify that Alfred Agent is registered to an Alfred domain. Are you sure you used the right key?
    \n\033[0m\n" >&2
        exit 0
    fi

else
    printf "\033[34m\n* Skipping registration check\n\033[0m"
fi

printf "\033[32m
Alfred Agent has been installed successfully.
It will run in the background and submit data to Alfred.

You can check the status of Alfred Agent using the \"/var/alfred/alfred-cli status\" command.
\033[0m"
