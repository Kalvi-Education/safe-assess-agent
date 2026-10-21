Kalvium SafeAgent

Finish every active assessment before installing, repairing, upgrading, rolling back, or uninstalling. Quit Google Chrome with Command-Q for ALL signed-in users; closing browser windows is not enough. Close any manually started SafeAgent process normally. This installer will not stop processes or restart the browser. Do not schedule unattended updates during an assessment.

If the installer asks you to quit Chrome, quit it and reopen this installer. SafeAgent processes and applications started after the initial check are still checked immediately before installation. If installation fails, open Installer's Window > Installer Log (or /var/log/install.log) and look for the message asking you to close Chrome and SafeAgent for every user; finish assessments, close them normally and rerun the installer. Do not bypass this guard.

This package installs the native messaging binary and Chrome registration system-wide. The agent runs only when invoked, as the invoking user; it installs no daemon or service. Installation needs administrator authorization, but runtime does not.

SafeAgent provides local observations, not trusted attestation or proof that a device is clean. It does not record keystrokes, inspect process memory, terminate programs, or make network requests.

Repair: rerun the approved installer outside an assessment. Uninstall: run sudo bash '/Library/Application Support/Kalvium/SafeAgent/uninstall.sh' --confirm-no-active-assessment after closing Chrome for all users.

After installation, reopen Chrome and return to the assessment's Device integrity section. Select Check connection. Installing SafeAgent does not grant monitoring consent or start monitoring; review and explicitly start monitoring separately when requested.
