Kalvium SafeAgent

Install SafeAgent before your assessment day, from the HIBu setup page. Chrome can stay open. If the installer says a SafeAgent check is running, wait a few seconds and run it again.


This package installs the native messaging binary and Chrome registration system-wide. The agent runs only when invoked, as the invoking user; it installs no daemon or service. Installation needs administrator authorization, but runtime does not.

SafeAgent provides local observations, not trusted attestation or proof that a device is clean. It does not record keystrokes, inspect process memory, terminate programs, or make network requests.

Repair: rerun the approved installer outside an assessment. Uninstall: run sudo bash '/Library/Application Support/Kalvium/SafeAgent/uninstall.sh' --confirm-no-active-assessment after closing Chrome for all users.

After installation, return to HIBu; it detects SafeAgent automatically within a few seconds. Installing SafeAgent does not grant monitoring consent or start monitoring; review and explicitly start monitoring separately when requested.
