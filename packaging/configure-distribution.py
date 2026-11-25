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
# Chrome may stay open: it launches SafeAgent per check and reads the host manifest each time.
# The package preinstall only waits for a SafeAgent check that is running at that moment.
tree.write(path, encoding="utf-8", xml_declaration=True)
