
import ipaddress

COMMON_VENDORS = {
    "40:3F:8C": "TP-Link Technologies",
    "A4:E2:87": "Xiaomi Communications",
    "E2:D5:1A": "Android TV / TV Box",
    "26:9F:46": "Xiaomi / Redmi",
    "9A:90:14": "Xiaomi / Redmi",
    "36:BA:8F": "Generic IoT / Android",
    "12:E9:2D": "Generic IoT / Android",
}

def normalize_mac(mac: str | None) -> str | None:
    if not mac:
        return None
    mac = mac.strip().upper().replace('-', ':')
    return mac

def guess_vendor_from_mac(mac: str | None) -> str | None:
    mac = normalize_mac(mac)
    if not mac:
        return None
    prefix = ":".join(mac.split(":")[:3])
    return COMMON_VENDORS.get(prefix)

def safe_int_ip(ip: str) -> int:
    try:
        return int(ipaddress.ip_address(ip))
    except Exception:
        return 0


def derive_subnet_for_ip(ip: str, configured_target: str) -> str:
    try:
        network = ipaddress.ip_network(configured_target, strict=False)
        if ipaddress.ip_address(ip) in network:
            return str(network)
    except Exception:
        pass
    try:
        host_addr = ipaddress.ip_address(ip)
        if host_addr.version == 4:
            return f"{host_addr}/32"
        return f"{host_addr}/128"
    except Exception:
        return configured_target

def build_vuln_notes_for_host(host: dict) -> list[str]:
    notes: list[str] = []
    tcp = host.get("tcp", [])
    udp = host.get("udp", [])

    tcp_ports = {e.get("port") for e in tcp}
    udp_ports = {e.get("port") for e in udp}

    if 80 in tcp_ports or 443 in tcp_ports:
        notes.append("HTTP/HTTPS open – check for outdated web apps and default credentials.")
    if 445 in tcp_ports:
        notes.append("SMB (445/tcp) open – check SMBv1/EternalBlue, null sessions, weak shares.")
    if 23 in tcp_ports:
        notes.append("Telnet open – legacy and insecure protocol, consider disabling.")
    if 21 in tcp_ports:
        notes.append("FTP open – ensure TLS (FTPS) or migrate to SFTP/SSH.")
    if 53 in udp_ports:
        notes.append("DNS (53/udp) open – check recursion, amplification and misconfigurations.")
    if 161 in udp_ports or 162 in udp_ports:
        notes.append("SNMP open – verify community strings, restrict access, prefer SNMPv3.")
    if 1900 in udp_ports:
        notes.append("SSDP/UPnP open – check for exposed UPnP devices and abuse potential.")
    if 500 in udp_ports or 4500 in udp_ports:
        notes.append("IPsec/IKE open – verify VPN configuration and authentication methods.")

    return notes
