import re
import unittest
from pathlib import Path

SCRIPT = Path(__file__).with_name("windows.iss").read_text(encoding="utf-8")


class WindowsInstallerTests(unittest.TestCase):
    def test_no_unsuppressible_message_boxes(self):
        # /SUPPRESSMSGBOXES only affects SuppressibleMsgBox; a plain MsgBox blocks silent installs forever.
        self.assertEqual(re.findall(r"(?<![A-Za-z])MsgBox\(", SCRIPT), [])

    def test_silent_prompts_default_to_continue(self):
        calls = re.findall(r"SuppressibleMsgBox\((.*?)\)\s*=\s*IDYES", SCRIPT)
        self.assertEqual(len(calls), 2)
        for call in calls:
            self.assertTrue(call.rstrip().endswith("IDYES"), call)

    def test_short_student_path(self):
        for directive in ("DisableWelcomePage=yes", "DisableReadyPage=yes", "DisableDirPage=yes"):
            self.assertIn(directive, SCRIPT)
        self.assertIn("msgButtonInstall", SCRIPT)

    def test_silent_update_never_blocked_by_wizard_page(self):
        # B1 (Dev VM 26 Nov): /VERYSILENT update aborted with EAbort because the unticked
        # safety page returned False from NextButtonClick.
        body = SCRIPT[SCRIPT.index("function NextButtonClick"):]
        body = body[:body.index("end;")]
        self.assertLess(body.index("WizardSilent"), body.index("SafetyPage.Values[0]"))

    def test_stale_registration_is_overwritten_not_blocking(self):
        self.assertIn("FileExists(RegisteredManifest)", SCRIPT)


if __name__ == "__main__":
    unittest.main()
