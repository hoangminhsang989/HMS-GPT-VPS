from __future__ import annotations

from dataclasses import dataclass
from xml.etree import ElementTree as ET


UNATTEND_NS = "urn:schemas-microsoft-com:unattend"
ET.register_namespace("", UNATTEND_NS)


@dataclass(frozen=True)
class UnattendConfig:
    computer_name: str
    locale: str = "en-US"
    timezone: str = "SE Asia Standard Time"
    owner: str = "HMS"
    organization: str = "HMS"

    def validate(self) -> None:
        if not self.computer_name.strip():
            raise ValueError("computer_name is required")
        if len(self.computer_name) > 15:
            raise ValueError("computer_name must be 15 characters or fewer")
        forbidden = set('\\/:*?"<>|')
        if any(char in forbidden for char in self.computer_name):
            raise ValueError("computer_name contains forbidden characters")


def _component(parent: ET.Element, name: str, *, pass_name: str) -> ET.Element:
    settings = next(
        (
            item
            for item in parent.findall(f"{{{UNATTEND_NS}}}settings")
            if item.get("pass") == pass_name
        ),
        None,
    )
    if settings is None:
        settings = ET.SubElement(parent, f"{{{UNATTEND_NS}}}settings", {"pass": pass_name})
    return ET.SubElement(
        settings,
        f"{{{UNATTEND_NS}}}component",
        {
            "name": name,
            "processorArchitecture": "amd64",
            "publicKeyToken": "31bf3856ad364e35",
            "language": "neutral",
            "versionScope": "nonSxS",
        },
    )


def generate_unattend(config: UnattendConfig) -> str:
    """Generate a minimal Windows answer file without reusable credentials.

    The generated file intentionally does not embed product keys, passwords,
    long-lived tokens, or HMS pairing secrets.
    """
    config.validate()
    root = ET.Element(f"{{{UNATTEND_NS}}}unattend")

    intl = _component(root, "Microsoft-Windows-International-Core-WinPE", pass_name="windowsPE")
    for tag in ("InputLocale", "SystemLocale", "UILanguage", "UserLocale"):
        ET.SubElement(intl, f"{{{UNATTEND_NS}}}{tag}").text = config.locale

    shell = _component(root, "Microsoft-Windows-Shell-Setup", pass_name="specialize")
    ET.SubElement(shell, f"{{{UNATTEND_NS}}}ComputerName").text = config.computer_name
    ET.SubElement(shell, f"{{{UNATTEND_NS}}}RegisteredOwner").text = config.owner
    ET.SubElement(shell, f"{{{UNATTEND_NS}}}RegisteredOrganization").text = config.organization
    ET.SubElement(shell, f"{{{UNATTEND_NS}}}TimeZone").text = config.timezone

    oobe = _component(root, "Microsoft-Windows-Shell-Setup", pass_name="oobeSystem")
    oobe_node = ET.SubElement(oobe, f"{{{UNATTEND_NS}}}OOBE")
    ET.SubElement(oobe_node, f"{{{UNATTEND_NS}}}HideEULAPage").text = "true"
    ET.SubElement(oobe_node, f"{{{UNATTEND_NS}}}ProtectYourPC").text = "3"

    return ET.tostring(root, encoding="unicode", xml_declaration=True)
