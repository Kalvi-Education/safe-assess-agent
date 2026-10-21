#!/bin/bash
set -euo pipefail
if [[ ${EUID} -ne 0 ]]; then
  echo 'Run with sudo; registration is system-wide.' >&2
  exit 1
fi
if [[ ${1:-} != --confirm-no-active-assessment ]]; then
  echo 'Finish every assessment and close Chrome for all users first.' >&2
  echo 'Then rerun with --confirm-no-active-assessment.' >&2
  exit 1
fi
# Never kill the agent or browser. A running process is a reason to stop.
if pgrep -x safeagent >/dev/null || pgrep -x 'Google Chrome' >/dev/null; then
  echo 'Close Chrome and SafeAgent normally for every user before uninstalling.' >&2
  exit 1
fi
rm -f '/Library/Google/Chrome/NativeMessagingHosts/com.kalvium.safeagent.json'
rm -f '/Library/Application Support/Kalvium/SafeAgent/safeagent'
rm -f '/Library/Application Support/Kalvium/SafeAgent/uninstall.sh'
rmdir '/Library/Application Support/Kalvium/SafeAgent' 2>/dev/null || true
pkgutil --forget com.kalvium.safeagent
