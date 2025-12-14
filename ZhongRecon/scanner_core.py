
import json
import platform
import subprocess
import threading
import urllib.request
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Optional

import nmap  # python-nmap

from utils import derive_subnet_for_ip, guess_vendor_from_mac, build_vuln_notes_for_host


class ScanConfig:
    def __init__(
        self,
        subnet: str,
        tcp_ports: str,
        udp_ports: str,
        profile_name: str = "custom",
        os_scan: bool = True,
        service_version: bool = False,
        timing: str = "T4",
        scan_type: str = "SYN",
        extra_args: str = "",
        exclude: str = "",
        retries: int = 2,
        threads: int = 64,
        udp_fallback: bool = True,
        discovery_mode: str = "arp_ping",
        target_type: str = "subnet",
        wan_scan: bool = False,
        osint_lookup: bool = False,
        traceroute: bool = False,
        aggressive: bool = False,
        disable_dns: bool = False,
        reason_flag: bool = False,
    ) -> None:
        self.subnet = subnet
        self.tcp_ports = tcp_ports
        self.udp_ports = udp_ports
        self.profile_name = profile_name
        self.os_scan = os_scan
        self.service_version = service_version
        self.timing = timing
        self.scan_type = scan_type
        self.extra_args = extra_args
        self.exclude = exclude
        self.retries = retries
        self.threads = threads
        self.udp_fallback = udp_fallback
        self.discovery_mode = discovery_mode
        self.target_type = target_type
        self.wan_scan = wan_scan
        self.osint_lookup = osint_lookup
        self.traceroute = traceroute
        self.aggressive = aggressive
        self.disable_dns = disable_dns
        self.reason_flag = reason_flag


def _build_discovery_args(cfg: ScanConfig) -> str:
    args = "-sn "
    if cfg.discovery_mode in ("arp", "arp_ping") and not cfg.wan_scan:
        args += "-PR "
    if cfg.discovery_mode == "ping":
        args += "-PE -PP -PM "
    if cfg.discovery_mode == "noprobe":
        args = "-Pn "
    if cfg.timing:
        args += f"-{cfg.timing} "
    if cfg.exclude:
        args += f"--exclude {cfg.exclude} "
    args += cfg.extra_args or ""
    return args.strip()


def discover_hosts(cfg: ScanConfig, log_func=None) -> List[str]:
    nm = nmap.PortScanner()
    args = _build_discovery_args(cfg)
    if log_func:
        log_func(f"[+] Host discovery on {cfg.subnet} with args: {args}")
    try:
        nm.scan(hosts=cfg.subnet, arguments=args)
    except Exception as e:
        if log_func:
            log_func(f"[!] Discovery scan error: {e}")
        return []

    up_hosts = []
    for host in nm.all_hosts():
        try:
            if nm[host].state() == "up":
                up_hosts.append(host)
        except Exception:
            continue

    up_hosts.sort()
    if log_func:
        log_func(f"[+] Discovery found {len(up_hosts)} hosts: {up_hosts}")
    return up_hosts


def _run_traceroute(ip: str, cfg: ScanConfig, log_func=None) -> list[str]:
    if not cfg.traceroute:
        return []
    traceroute_cmd = "traceroute"
    args = [traceroute_cmd, "-n", ip]
    if platform.system().lower().startswith("win"):
        traceroute_cmd = "tracert"
        args = [traceroute_cmd, "-d", ip]
    try:
        if log_func:
            log_func(f"[*] Traceroute to {ip} using {traceroute_cmd}")
        proc = subprocess.run(args, capture_output=True, text=True, timeout=120)
        output = proc.stdout.splitlines()
        hops: list[str] = []
        for line in output:
            parts = line.strip().split()
            if not parts or not parts[0].isdigit():
                continue

            hop_ips = re.findall(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", line)
            for hop_ip in hop_ips:
                if hop_ip != "*":
                    hops.append(hop_ip)
        unique_hops: list[str] = []
        for hop_ip in hops:
            if hop_ip not in unique_hops:
                unique_hops.append(hop_ip)
        if ip not in unique_hops:
            unique_hops.append(ip)
        return unique_hops
    except Exception as e:
        if log_func:
            log_func(f"[!] Traceroute failed for {ip}: {e}")
        return []


def _osint_lookup(ip: str, cfg: ScanConfig, log_func=None) -> dict:
    if not cfg.osint_lookup:
        return {}
    url = f"https://ipinfo.io/{ip}/json"
    try:
        if log_func:
            log_func(f"[*] OSINT lookup for {ip} at {url}")
        with urllib.request.urlopen(url, timeout=15) as resp:  # nosec B310
            data = json.loads(resp.read().decode("utf-8"))
            filtered = {k: data.get(k) for k in ("org", "city", "region", "country", "loc") if data.get(k)}
            return filtered
    except Exception as e:
        if log_func:
            log_func(f"[!] OSINT lookup failed for {ip}: {e}")
        return {"error": str(e)}


def _scan_os(ip: str, cfg: ScanConfig, log_func=None) -> Dict[str, Any]:
    if not cfg.os_scan:
        return {"os": None}
    nm = nmap.PortScanner()
    args = f"-O -Pn -{cfg.timing} {cfg.extra_args or ''}"
    if cfg.disable_dns:
        args += " -n"
    if cfg.reason_flag:
        args += " --reason"
    if cfg.aggressive:
        args += " -A"
    if cfg.exclude:
        args += f" --exclude {cfg.exclude}"
    args = args.strip()
    if log_func:
        log_func(f"[*] OS scan {ip}: nmap {args}")
    try:
        nm.scan(hosts=ip, arguments=args)
        if ip not in nm.all_hosts():
            return {"os": None}
        h = nm[ip]
        osmatches = h.get("osmatch", [])
        os_name = osmatches[0]["name"] if osmatches else None
        vendor = None
        mac = h["addresses"].get("mac") if "addresses" in h else None
        if mac:
            vendor = h["vendor"].get(mac) if "vendor" in h else None
        if not vendor:
            vendor = guess_vendor_from_mac(mac)
        return {
            "os": os_name,
            "mac": h["addresses"].get("mac") if "addresses" in h else None,
            "vendor": vendor,
        }
    except Exception as e:
        if log_func:
            log_func(f"[!] OS scan error on {ip}: {e}")
        return {"os": None}


def _scan_ports_for_host(
    ip: str,
    cfg: ScanConfig,
    log_func=None,
    tcp_only: bool = False,
    udp_only: bool = False,
) -> Dict[str, Any]:
    host_data: Dict[str, Any] = {
        "ip": ip,
        "mac": None,
        "hostname": None,
        "os": None,
        "vendor": None,
        "subnet": None,
        "type": None,
        "tcp": [],
        "udp": [],
        "upnp": {},
        "dhcp": {},
        "mdns": {},
        "traffic": {},
        "vuln_notes": [],
        "traceroute": [],
        "osint": {},
    }

    os_info = _scan_os(ip, cfg, log_func=log_func)
    host_data.update({k: v for k, v in os_info.items() if k in ("os", "mac", "vendor")})
    host_data["subnet"] = derive_subnet_for_ip(ip, cfg.subnet)

    def _scan_tcp() -> list:
        if not cfg.tcp_ports or udp_only:
            return []
        nm = nmap.PortScanner()
        scan_type_flag = "-sS" if cfg.scan_type.upper() == "SYN" else "-sT"
        args = f"{scan_type_flag} -Pn -{cfg.timing} "
        if cfg.aggressive:
            args += "-A "
        if cfg.service_version:
            args += "-sV "
        if cfg.disable_dns:
            args += "-n "
        if cfg.reason_flag:
            args += "--reason "
        if cfg.exclude:
            args += f"--exclude {cfg.exclude} "
        args += cfg.extra_args or ""
        args = args.strip()
        if log_func:
            log_func(f"[*] TCP scan {ip}: ports={cfg.tcp_ports} args={args}")
        nm.scan(hosts=ip, ports=cfg.tcp_ports, arguments=args)
        if ip not in nm.all_hosts():
            if log_func:
                log_func(f"[!] TCP scan: {ip} missing from results")
            return []

        res = []
        try:
            h = nm[ip]
            host_data["hostname"] = h.hostname() or host_data.get("hostname")
            if "addresses" in h and h["addresses"].get("mac"):
                host_data["mac"] = host_data.get("mac") or h["addresses"].get("mac")
            for port, pdata in h.get("tcp", {}).items():
                if pdata.get("state") == "open":
                    res.append({
                        "port": port,
                        "service": pdata.get("name", ""),
                        "product": pdata.get("product", ""),
                        "version": pdata.get("version", ""),
                        "extrainfo": pdata.get("extrainfo", ""),
                    })
        except Exception as e:
            if log_func:
                log_func(f"[!] Error parsing TCP data for {ip}: {e}")
        return res

    def _scan_udp() -> list:
        if not cfg.udp_ports or tcp_only:
            return []
        nm = nmap.PortScanner()
        args = f"-sU -Pn -{cfg.timing} "
        if cfg.aggressive:
            args += "-A "
        if cfg.service_version:
            args += "-sV "
        if cfg.disable_dns:
            args += "-n "
        if cfg.reason_flag:
            args += "--reason "
        if cfg.exclude:
            args += f"--exclude {cfg.exclude} "
        args += cfg.extra_args or ""
        args = args.strip()
        if log_func:
            log_func(f"[*] UDP scan {ip}: ports={cfg.udp_ports} args={args}")
        nm.scan(hosts=ip, ports=cfg.udp_ports, arguments=args)
        if ip not in nm.all_hosts():
            if log_func:
                log_func(f"[!] UDP scan: {ip} missing from results")
            return []
        res = []
        try:
            h = nm[ip]
            host_data["hostname"] = host_data.get("hostname") or h.hostname() or None
            if "addresses" in h and h["addresses"].get("mac"):
                host_data["mac"] = host_data.get("mac") or h["addresses"].get("mac")
            for port, pdata in h.get("udp", {}).items():
                if pdata.get("state") in ("open", "open|filtered"):
                    res.append({
                        "port": port,
                        "service": pdata.get("name", ""),
                        "product": pdata.get("product", ""),
                        "version": pdata.get("version", ""),
                        "extrainfo": pdata.get("extrainfo", ""),
                    })
        except Exception as e:
            if log_func:
                log_func(f"[!] Error parsing UDP data for {ip}: {e}")
        return res

    tcp_res = []
    udp_res = []

    try:
        if not udp_only and not tcp_only:
            tcp_res = _scan_tcp()
            udp_res = _scan_udp()
        elif tcp_only:
            tcp_res = _scan_tcp()
        elif udp_only:
            udp_res = _scan_udp()
    except Exception as e:
        if log_func:
            log_func(f"[!] Error in port scan helper for {ip}: {e}")

    host_data["tcp"] = sorted(tcp_res, key=lambda x: x["port"])
    host_data["udp"] = sorted(udp_res, key=lambda x: x["port"])
    host_data["vuln_notes"] = build_vuln_notes_for_host(host_data)
    return host_data


def scan_host_with_retry(ip: str, cfg: ScanConfig, log_func=None) -> Dict[str, Any]:
    last_result: Optional[Dict[str, Any]] = None
    for attempt in range(1, cfg.retries + 1):
        if log_func:
            log_func(f"[*] {ip}: full TCP+UDP attempt {attempt}/{cfg.retries}")
        try:
            res = _scan_ports_for_host(ip, cfg, log_func=log_func)
            last_result = res
            if res.get("tcp") or res.get("udp") or res.get("os"):
                return res
        except Exception as e:
            if log_func:
                log_func(f"[!] {ip}: error on attempt {attempt}: {e}")

    if cfg.udp_fallback:
        if log_func:
            log_func(f"[*] {ip}: retrying with UDP-only fallback ...")
        try:
            res = _scan_ports_for_host(ip, cfg, udp_only=True, log_func=log_func)
            last_result = res
        except Exception as e:
            if log_func:
                log_func(f"[!] {ip}: UDP-only fallback failed: {e}")
    return last_result or {
        "ip": ip,
        "mac": None,
        "hostname": None,
        "os": None,
        "vendor": None,
        "subnet": derive_subnet_for_ip(ip, cfg.subnet),
        "type": None,
        "tcp": [],
        "udp": [],
        "upnp": {},
        "dhcp": {},
        "mdns": {},
        "traffic": {},
        "vuln_notes": [],
        "traceroute": _run_traceroute(ip, cfg, log_func=log_func),
        "osint": _osint_lookup(ip, cfg, log_func=log_func),
    }


def parallel_scan(hosts: List[str], cfg: ScanConfig, log_func=None) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    lock = threading.Lock()

    if log_func:
        log_func(f"[+] Parallel scan of {len(hosts)} hosts with {cfg.threads} threads")

    with ThreadPoolExecutor(max_workers=cfg.threads) as executor:
        future_map = {
            executor.submit(scan_host_with_retry, ip, cfg, log_func): ip
            for ip in hosts
        }
        for fut in as_completed(future_map):
            ip = future_map[fut]
            try:
                res = fut.result()
            except Exception as e:
                if log_func:
                    log_func(f"[!] Exception from {ip}: {e}")
                continue
            with lock:
                results.append(res)

    try:
        results.sort(key=lambda h: h["ip"])
    except Exception:
        pass
    return results


def run_full_scan(cfg: ScanConfig, log_func=None) -> list[dict]:
    hosts: list[str]
    if cfg.target_type == "host":
        hosts = [cfg.subnet]
        if log_func:
            log_func(f"[+] Direct host scan for {cfg.subnet}")
    else:
        hosts = discover_hosts(cfg, log_func=log_func)
        if not hosts:
            if log_func:
                log_func("[!] No hosts discovered. Nothing to scan.")
            return []
    results = parallel_scan(hosts, cfg, log_func=log_func)
    for host in results:
        host["traceroute"] = _run_traceroute(host.get("ip", ""), cfg, log_func=log_func)
        host["osint"] = _osint_lookup(host.get("ip", ""), cfg, log_func=log_func)
    return results


if __name__ == "__main__":
    cfg = ScanConfig(
        subnet="192.168.0.0/24",
        tcp_ports="22,80,443,445",
        udp_ports="53,67,123,1900",
        profile_name="balanced",
    )
    data = run_full_scan(cfg, log_func=print)
    print(json.dumps(data, indent=4))
