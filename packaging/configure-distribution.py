"""Configure native architecture, installation guidance and Chrome preflight."""
import sys
import xml.etree.ElementTree as ET

path, arch = sys.argv[1:]
architecture = {"arm64": "arm64", "x64": "x86_64"}[arch]
tree = ET.parse(path)
root = tree.getroot()
options = root.find("options")
if options is None:
    options = ET.SubElement(root, "options")
options.set("hostArchitectures", architecture)
options.set("customize", "never")
ET.SubElement(root, "title").text = "Kalvium SafeAgent"
ET.SubElement(root, "readme", {"file": "installer-readme.txt", "mime-type": "text/plain"})
# Built-in application lookup needs no external-script permission. SafeAgent is
# a CLI process; the package preinstall remains the all-user safety guard.
ET.SubElement(root, "installation-check", {"script": "checkChromeClosed()"})
ET.SubElement(root, "script").text = """
function checkChromeClosed() {
    if (system.applications.fromIdentifier('com.google.Chrome').length > 0) {
        my.result.type = 'Fatal';
        my.result.title = 'Quit Chrome before installing SafeAgent';
        my.result.message = 'Finish all active assessments first. Quit Google Chrome with Command-Q for every signed-in user; closing its windows is not enough. Close any manually started SafeAgent process normally, then reopen this installer. The installer will not close applications for you. After installation, reopen Chrome, return to Device integrity and select Check connection. Monitoring requires your separate consent and start action.';
        return false;
    }
    return true;
}
"""
tree.write(path, encoding="utf-8", xml_declaration=True)
