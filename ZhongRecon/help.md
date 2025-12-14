# Zhong – Network Reconnaissance Toolkit

Zhong is a LAN-focused reconnaissance and mapping tool. It wraps `nmap` into a parallel,
GUI-driven workflow aimed at defenders, students, and lab environments.

## How to use
1. Launch the Zhong GUI (`python zhong_gui.py`).
2. Enter a CIDR subnet or a single IP and choose **Subnet** or **Single host**.
3. Pick a profile (Fast/Balanced/Deep/Stealth) or choose **Full sweep (all ports)** to send `-p-` for TCP/UDP.
4. Toggle options such as OS detection, service/version detection, traceroute, OSINT lookup, and WAN scan.
5. Press **Start Scan**. Progress appears in the log; the results table and topology update when complete.
6. Select a host to view details including open ports, vulnerability notes, traceroute hops, and OSINT data.
7. Export results as JSON, Markdown, or HTML (exports include the scan date/time and context metadata).

## How it works
- Zhong builds an nmap command based on your choices (discovery mode, timing, scan type, port list, and extras).
- Host discovery runs first (unless single-host mode) followed by concurrent TCP/UDP scans and optional OS detection.
- Optional traceroute collects every hop (including the target) and draws them in the topology map.
- OSINT lookups query ipinfo.io for WAN mode targets to enrich host context.
- Reports bundle raw results plus the generation timestamp so you can trace when and how the scan ran.
