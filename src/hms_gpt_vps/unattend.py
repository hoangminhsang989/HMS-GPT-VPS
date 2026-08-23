from __future__ import annotations

from dataclasses import dataclass, field
from xml.etree import ElementTree as ET


UNATTEND_NS = "urn:schemas-microsoft-com:unattend"
WCM_NS = "http://schemas.microsoft.com/WMIConfig/2002/State"
ET.register_namespace("", UNATTEND_NS)
ET.register_namespace("wcm", WCM_NS)


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
        if not self.locale.strip():
            raise ValueError("locale is required")
        if not self.timezone.strip():
            raise ValueError("timezone is required")


@dataclass(frozen=True)
class BootstrapAccount:
    username: str
    password: str = field(repr=False)

    def validate(self) -> None:
        username = self.username.strip()
        if not username:
            raise ValueError("bootstrap username is required")
        if len(username) > 20:
            raise ValueError("bootstrap username must be 20 characters or fewer")
        forbidden = set('/\\[]:|<>+=;,?*%@`')
        if any(char in forbidden for char in username):
            raise ValueError("bootstrap username contains forbidden characters")
        if username.upper() == "NONE":
            raise ValueError("bootstrap username is reserved")
        if len(self.password) < 20:
            raise ValueError("bootstrap password must be at least 20 characters")
        if len(self.password) > 127:
            raise ValueError("bootstrap password is too long")


@dataclass(frozen=True)
class InstallUnattendConfig:
    base: UnattendConfig
    bootstrap: BootstrapAccount
    image_index: int = 1
    disk_id: int = 0
    efi_size_mb: int = 300
    msr_size_mb: int = 16
    dedicated_blank_disk_acknowledged: bool = False

    def validate(self) -> None:
        self.base.validate()
        self.bootstrap.validate()
        if self.image_index < 1:
            raise ValueError("image_index must be >= 1")
        if self.disk_id != 0:
            raise ValueError("R002C supports only the dedicated guest disk 0")
        if self.efi_size_mb < 300:
            raise ValueError("EFI system partition must be at least 300 MB")
        if self.msr_size_mb != 16:
            raise ValueError("MSR partition must be 16 MB")
        if not self.dedicated_blank_disk_acknowledged:
            raise ValueError(
                "refusing to emit WillWipeDisk without dedicated blank guest disk acknowledgement"
            )


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


def _text(parent: ET.Element, tag: str, value: object) -> ET.Element:
    node = ET.SubElement(parent, f"{{{UNATTEND_NS}}}{tag}")
    node.text = str(value)
    return node


def _add(parent: ET.Element, tag: str) -> ET.Element:
    return ET.SubElement(
        parent,
        f"{{{UNATTEND_NS}}}{tag}",
        {f"{{{WCM_NS}}}action": "add"},
    )


def _add_international_settings(root: ET.Element, config: UnattendConfig, pass_name: str) -> None:
    component_name = (
        "Microsoft-Windows-International-Core-WinPE"
        if pass_name == "windowsPE"
        else "Microsoft-Windows-International-Core"
    )
    intl = _component(root, component_name, pass_name=pass_name)
    for tag in ("InputLocale", "SystemLocale", "UILanguage", "UserLocale"):
        _text(intl, tag, config.locale)


def _add_shell_identity(root: ET.Element, config: UnattendConfig) -> None:
    shell = _component(root, "Microsoft-Windows-Shell-Setup", pass_name="specialize")
    _text(shell, "ComputerName", config.computer_name)
    _text(shell, "RegisteredOwner", config.owner)
    _text(shell, "RegisteredOrganization", config.organization)
    _text(shell, "TimeZone", config.timezone)


def _add_oobe(root: ET.Element, config: UnattendConfig) -> ET.Element:
    _add_international_settings(root, config, "oobeSystem")
    shell = _component(root, "Microsoft-Windows-Shell-Setup", pass_name="oobeSystem")
    oobe = ET.SubElement(shell, f"{{{UNATTEND_NS}}}OOBE")
    _text(oobe, "HideEULAPage", "true")
    _text(oobe, "HideOnlineAccountScreens", "true")
    _text(oobe, "HideWirelessSetupInOOBE", "true")
    _text(oobe, "ProtectYourPC", "3")
    return shell


def _serialize(root: ET.Element) -> str:
    ET.indent(root, space="  ")
    return ET.tostring(root, encoding="unicode", xml_declaration=True)


def generate_unattend(config: UnattendConfig) -> str:
    """Generate a minimal Windows answer file without reusable credentials.

    This preview/foundation form intentionally does not wipe disks or embed
    product keys, passwords, long-lived tokens, or HMS pairing secrets.
    """
    config.validate()
    root = ET.Element(f"{{{UNATTEND_NS}}}unattend")
    _add_international_settings(root, config, "windowsPE")
    _add_shell_identity(root, config)
    _add_oobe(root, config)
    return _serialize(root)


def generate_install_unattend(config: InstallUnattendConfig) -> str:
    """Generate the transient unattended-install answer for a managed VM.

    The output intentionally contains the *ephemeral* bootstrap account
    password because Windows Setup requires a usable guest credential for the
    post-install PowerShell Direct bootstrap. Therefore the resulting answer
    media is a secret artifact: it must live only in protected runtime storage,
    never in Git/audit logs, and must be detached/deleted after bootstrap.

    No Windows product key, HMS pairing token or reusable agent credential is
    ever embedded here.
    """
    config.validate()
    root = ET.Element(f"{{{UNATTEND_NS}}}unattend")
    _add_international_settings(root, config.base, "windowsPE")

    setup = _component(root, "Microsoft-Windows-Setup", pass_name="windowsPE")
    disk_configuration = ET.SubElement(setup, f"{{{UNATTEND_NS}}}DiskConfiguration")
    disk = _add(disk_configuration, "Disk")
    _text(disk, "DiskID", config.disk_id)
    _text(disk, "WillWipeDisk", "true")

    create_partitions = ET.SubElement(disk, f"{{{UNATTEND_NS}}}CreatePartitions")
    efi = _add(create_partitions, "CreatePartition")
    _text(efi, "Order", 1)
    _text(efi, "Type", "EFI")
    _text(efi, "Size", config.efi_size_mb)

    msr = _add(create_partitions, "CreatePartition")
    _text(msr, "Order", 2)
    _text(msr, "Type", "MSR")
    _text(msr, "Size", config.msr_size_mb)

    windows = _add(create_partitions, "CreatePartition")
    _text(windows, "Order", 3)
    _text(windows, "Type", "Primary")
    _text(windows, "Extend", "true")

    modify_partitions = ET.SubElement(disk, f"{{{UNATTEND_NS}}}ModifyPartitions")
    efi_modify = _add(modify_partitions, "ModifyPartition")
    _text(efi_modify, "Order", 1)
    _text(efi_modify, "PartitionID", 1)
    _text(efi_modify, "Label", "System")
    _text(efi_modify, "Format", "FAT32")

    windows_modify = _add(modify_partitions, "ModifyPartition")
    _text(windows_modify, "Order", 2)
    _text(windows_modify, "PartitionID", 3)
    _text(windows_modify, "Label", "Windows")
    _text(windows_modify, "Letter", "C")
    _text(windows_modify, "Format", "NTFS")

    _text(disk_configuration, "WillShowUI", "OnError")

    image_install = ET.SubElement(setup, f"{{{UNATTEND_NS}}}ImageInstall")
    os_image = ET.SubElement(image_install, f"{{{UNATTEND_NS}}}OSImage")
    install_from = ET.SubElement(os_image, f"{{{UNATTEND_NS}}}InstallFrom")
    metadata = _add(install_from, "MetaData")
    _text(metadata, "Key", "/IMAGE/INDEX")
    _text(metadata, "Value", config.image_index)
    install_to = ET.SubElement(os_image, f"{{{UNATTEND_NS}}}InstallTo")
    _text(install_to, "DiskID", config.disk_id)
    _text(install_to, "PartitionID", 3)
    _text(os_image, "WillShowUI", "OnError")

    user_data = ET.SubElement(setup, f"{{{UNATTEND_NS}}}UserData")
    _text(user_data, "AcceptEula", "true")
    _text(user_data, "FullName", config.base.owner)
    _text(user_data, "Organization", config.base.organization)

    _add_shell_identity(root, config.base)
    oobe_shell = _add_oobe(root, config.base)

    user_accounts = ET.SubElement(oobe_shell, f"{{{UNATTEND_NS}}}UserAccounts")
    local_accounts = ET.SubElement(user_accounts, f"{{{UNATTEND_NS}}}LocalAccounts")
    account = _add(local_accounts, "LocalAccount")
    _text(account, "Name", config.bootstrap.username)
    _text(account, "DisplayName", "HMS Bootstrap")
    _text(account, "Description", "Temporary HMS provisioning account")
    _text(account, "Group", "Administrators")
    account_password = ET.SubElement(account, f"{{{UNATTEND_NS}}}Password")
    _text(account_password, "Value", config.bootstrap.password)
    _text(account_password, "PlainText", "true")

    auto_logon = ET.SubElement(oobe_shell, f"{{{UNATTEND_NS}}}AutoLogon")
    auto_password = ET.SubElement(auto_logon, f"{{{UNATTEND_NS}}}Password")
    _text(auto_password, "Value", config.bootstrap.password)
    _text(auto_password, "PlainText", "true")
    _text(auto_logon, "Enabled", "true")
    _text(auto_logon, "LogonCount", 1)
    _text(auto_logon, "Username", config.bootstrap.username)

    return _serialize(root)
