"""Port risk knowledge base for security insight generation.

Each rule maps a port number to a risk assessment that varies by device type.
Device types where the port is expected (e.g. SSH on a computer) are excluded
from alerts.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from squirrelops_home_sensor.alerts.types import Severity


@dataclass(frozen=True)
class PortRisk:
    """A single port risk rule."""

    port: int
    service_name: str
    risk_description: str
    remediation: str
    severity: Severity
    # Device types where this port is expected (no alert generated)
    expected_on: frozenset[str] = field(default_factory=frozenset)


# -- Always-risky ports (alert on ANY device) --------------------------------

ALWAYS_RISKY: list[PortRisk] = [
    PortRisk(
        port=23,
        service_name="Telnet",
        risk_description=(
            "Telnet transmits all data including passwords in plaintext. "
            "Any device running Telnet is vulnerable to credential interception."
        ),
        remediation=(
            "Disable Telnet and use SSH instead. Check your device's admin panel "
            "for a 'Remote Access' or 'Management' setting."
        ),
        severity=Severity.HIGH,
    ),
    PortRisk(
        port=21,
        service_name="FTP",
        risk_description=(
            "FTP transmits files and credentials in plaintext. "
            "It can be intercepted by anyone on your network."
        ),
        remediation=(
            "Disable FTP and use SFTP or SCP instead. If the device requires "
            "FTP for firmware updates, disable it after updating."
        ),
        severity=Severity.MEDIUM,
    ),
]


# -- Context-dependent risky ports --------------------------------------------

CONTEXT_RISKY: list[PortRisk] = [
    PortRisk(
        port=22,
        service_name="SSH",
        risk_description=(
            "SSH access is open. While encrypted, SSH on IoT devices "
            "often uses default credentials that are easy to guess."
        ),
        remediation=(
            "If you don't need remote terminal access, disable SSH in the "
            "device settings. If you do need it, change the default password."
        ),
        severity=Severity.MEDIUM,
        expected_on=frozenset({
            "computer", "network_equipment", "nas", "sbc",
        }),
    ),
    PortRisk(
        port=445,
        service_name="SMB file sharing",
        risk_description=(
            "Windows file sharing (SMB) is open. SMB has a long history "
            "of critical vulnerabilities including WannaCry and EternalBlue."
        ),
        remediation=(
            "Disable file sharing on this device unless you specifically use it. "
            "Ensure the device firmware is up to date."
        ),
        severity=Severity.HIGH,
        expected_on=frozenset({"computer", "nas"}),
    ),
    PortRisk(
        port=3389,
        service_name="Remote Desktop (RDP)",
        risk_description=(
            "Remote Desktop is open. RDP is a frequent target for brute-force "
            "attacks and has had critical vulnerabilities."
        ),
        remediation=(
            "Disable Remote Desktop if you don't use it. If you need it, ensure "
            "strong passwords and Network Level Authentication are enabled."
        ),
        severity=Severity.HIGH,
        expected_on=frozenset({"computer"}),
    ),
    PortRisk(
        port=5900,
        service_name="VNC",
        risk_description=(
            "VNC remote desktop is open. Many VNC implementations use weak "
            "or no authentication."
        ),
        remediation=(
            "Disable VNC if you don't need remote desktop access. If you do, "
            "set a strong password and consider using SSH tunneling."
        ),
        severity=Severity.MEDIUM,
        expected_on=frozenset({"computer"}),
    ),
    PortRisk(
        port=3306,
        service_name="MySQL",
        risk_description=(
            "A MySQL database port is exposed on the network. Databases should "
            "not be directly accessible from other devices."
        ),
        remediation=(
            "Configure MySQL to listen only on localhost (127.0.0.1). "
            "Check the bind-address setting in the MySQL configuration."
        ),
        severity=Severity.HIGH,
        expected_on=frozenset({"computer", "nas"}),
    ),
    PortRisk(
        port=5432,
        service_name="PostgreSQL",
        risk_description=(
            "A PostgreSQL database port is exposed on the network. Databases should "
            "not be directly accessible from other devices."
        ),
        remediation=(
            "Configure PostgreSQL to listen only on localhost. "
            "Check pg_hba.conf and the listen_addresses setting."
        ),
        severity=Severity.HIGH,
        expected_on=frozenset({"computer", "nas"}),
    ),
    PortRisk(
        port=554,
        service_name="RTSP video streaming",
        risk_description=(
            "RTSP video streaming is open. This could allow unauthorized "
            "viewing of camera feeds if authentication is weak or missing."
        ),
        remediation=(
            "Ensure your camera requires authentication for RTSP streams. "
            "Change the default password if you haven't already."
        ),
        severity=Severity.MEDIUM,
        expected_on=frozenset({"camera"}),
    ),
]


# -- Unencrypted admin interface detection ------------------------------------

UNENCRYPTED_ADMIN_PORTS: frozenset[int] = frozenset({80, 8080, 8000, 8888, 9090})
ENCRYPTED_ADMIN_PORTS: frozenset[int] = frozenset({443, 8443})
ADMIN_EXPECTED_DEVICES: frozenset[str] = frozenset({
    "computer", "network_equipment", "nas", "sbc", "streaming",
})


def evaluate_device_ports(
    open_ports: frozenset[int],
    device_type: str,
) -> list[PortRisk]:
    """Evaluate a device's open ports against the risk knowledge base.

    Returns a list of PortRisk objects for ports that are risky given the
    device's type. Returns an empty list if no risks are found.
    """
    findings: list[PortRisk] = []

    for rule in ALWAYS_RISKY:
        if rule.port in open_ports:
            findings.append(rule)

    for rule in CONTEXT_RISKY:
        if rule.port in open_ports and device_type not in rule.expected_on:
            findings.append(rule)

    # Check for unencrypted admin interfaces on IoT devices
    if device_type not in ADMIN_EXPECTED_DEVICES:
        http_ports = open_ports & UNENCRYPTED_ADMIN_PORTS
        https_ports = open_ports & ENCRYPTED_ADMIN_PORTS
        if http_ports and not https_ports:
            for port in sorted(http_ports):
                findings.append(PortRisk(
                    port=port,
                    service_name=f"Unencrypted admin (port {port})",
                    risk_description=(
                        f"An unencrypted web interface is running on port {port} "
                        f"with no HTTPS alternative. Credentials and data sent to "
                        f"this interface can be intercepted on your network."
                    ),
                    remediation=(
                        "Check if the device supports HTTPS and enable it. If not, "
                        "avoid entering sensitive information through this interface."
                    ),
                    severity=Severity.MEDIUM,
                ))

    return findings
