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


if __name__ == "__main__":
    unittest.main()
