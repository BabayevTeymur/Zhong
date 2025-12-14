import json
import datetime
import os

import datetime
import json
from typing import Any


# ---------------------------------------------------------
# JSON EXPORT
# ---------------------------------------------------------


def export_json(data, filename="scan_result.json", metadata: dict[str, Any] | None = None):
    payload = {
        "generated_at": datetime.datetime.now().isoformat(),
        "metadata": metadata or {},
        "results": data,
    }
    try:
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=4)
        return True, f"JSON exported to {filename}"
    except Exception as e:
        return False, str(e)


def generate_markdown_report(results, metadata: dict[str, Any] | None = None):
    """
    Generate a simple Markdown report for the scan results.
    """

    metadata = metadata or {}
    md = []
    md.append("# Zhong Scan Report\n")
    md.append(f"**Generated:** {metadata.get('generated_at', datetime.datetime.now())}  \n")
    if metadata:
        md.append("**Scan context:**  \n")
        if metadata.get("target"):
            md.append(f"- Target: {metadata['target']}  \n")
        if metadata.get("profile"):
            md.append(f"- Profile: {metadata['profile']}  \n")
        if metadata.get("mode"):
            md.append(f"- Mode: {metadata['mode']}  \n")
        md.append("\n")

    for host in results:
        md.append(f"## Host: {host.get('ip')}\n")
        md.append(f"- **MAC:** {host.get('mac')}  ")
        md.append(f"- **OS:** {host.get('os')}  ")
        md.append(f"- **Vendor:** {host.get('vendor')}  ")
        md.append(f"- **Hostname:** {host.get('hostname')}  ")
        md.append(f"- **Type:** {host.get('type')}  ")
        md.append(f"- **Traceroute hops:** {len(host.get('traceroute', []))}  ")
        md.append("\n")

        # TCP
        md.append("### TCP Ports\n")
        if host.get("tcp"):
            for port in host["tcp"]:
                md.append(f"- `{port['port']}` {port['service']} {port['product']} {port['version']}")
        else:
            md.append("_No open TCP ports found_\n")

        # UDP
        md.append("\n### UDP Ports\n")
        if host.get("udp"):
            for port in host["udp"]:
                md.append(f"- `{port['port']}` {port['service']} {port['product']} {port['version']}")
        else:
            md.append("_No open UDP ports found_\n")

        # Vulnerabilities
        md.append("\n### Notes / Potential Vulnerabilities\n")
        if host.get("vuln_notes"):
            for note in host["vuln_notes"]:
                md.append(f"- {note}")
        else:
            md.append("_No vulnerability notes_\n")

        if host.get("traceroute"):
            md.append("\n### Traceroute\n")
            for idx, hop in enumerate(host.get("traceroute", []), start=1):
                md.append(f"- {idx}. {hop}")

        md.append("\n---\n")

    return "\n".join(md)


def generate_html_report(results, metadata: dict[str, Any] | None = None):
    """
    Generate an HTML report with basic styling.
    """

    metadata = metadata or {}
    generated_at = metadata.get("generated_at", datetime.datetime.now())
    html = """
<html>
<head>
<style>
body { font-family: 'Segoe UI', Arial, sans-serif; background: radial-gradient(circle at 20% 20%, #0b0516, #05030b); color: #e6dcff; padding: 24px; }
h1 { color: #c598ff; letter-spacing: 1px; text-shadow: 0 0 12px rgba(197, 152, 255, 0.35); }
h2 { color: #e4c4ff; border-bottom: 1px solid #2f1a44; padding-bottom: 4px; }
h3 { color: #b789ff; }
.pill { display: inline-block; padding: 8px 14px; margin: 0 8px 10px 0; border-radius: 14px; background: linear-gradient(120deg, #1d0f2d, #2b143e); border: 1px solid #3f1c5a; color: #f0e8ff; box-shadow: 0 4px 16px rgba(0,0,0,0.35); }
.table { border-collapse: collapse; width: 100%; margin-bottom: 22px; box-shadow: 0 0 16px rgba(0,0,0,0.4); }
.table th, .table td { border: 1px solid #3f1c5a; padding: 10px; }
.table th { background: linear-gradient(90deg, #2c1640, #1d102d); color: #f5e7ff; text-transform: uppercase; letter-spacing: 0.5px; }
.table tr:nth-child(even) { background: rgba(64, 32, 92, 0.25); }
.table tr:nth-child(odd) { background: rgba(40, 20, 64, 0.35); }
.meta { margin-bottom: 18px; }
.card { background: linear-gradient(140deg, rgba(55, 29, 82, 0.8), rgba(28, 14, 46, 0.85)); padding: 14px; border-radius: 12px; border: 1px solid #3f1c5a; box-shadow: 0 8px 24px rgba(0, 0, 0, 0.45); }
.divider { border: none; border-bottom: 1px dashed #4c2a6d; margin: 28px 0; }
</style>
</head>
<body>
<h1>Zhong Scan Report</h1>
"""

    html += f"<div class='meta'><span class='pill'>Generated: {generated_at}</span>"
    if metadata.get("target"):
        html += f"<span class='pill'>Target: {metadata['target']}</span>"
    if metadata.get("profile"):
        html += f"<span class='pill'>Profile: {metadata['profile']}</span>"
    if metadata.get("mode"):
        html += f"<span class='pill'>Mode: {metadata['mode']}</span>"
    html += "</div>"

    for host in results:
        html += f"""
<div class="card">
  <h2>Host: {host.get('ip')}</h2>
  <p><b>MAC:</b> {host.get('mac')}<br>
  <b>OS:</b> {host.get('os')}<br>
  <b>Vendor:</b> {host.get('vendor')}<br>
  <b>Hostname:</b> {host.get('hostname')}<br>
  <b>Type:</b> {host.get('type')}<br>
  <b>Traceroute hops:</b> {len(host.get('traceroute', []))}</p>
"""

        # TCP
        html += """
<h3>TCP Ports</h3>
<table class="table">
<tr><th>Port</th><th>Service</th><th>Product</th><th>Version</th></tr>
"""
        if host.get("tcp"):
            for port in host["tcp"]:
                html += f"<tr><td>{port['port']}</td><td>{port['service']}</td><td>{port['product']}</td><td>{port['version']}</td></tr>"
        else:
            html += "<tr><td colspan=4>No open TCP ports</td></tr>"
        html += "</table>"

        # UDP
        html += """
<h3>UDP Ports</h3>
<table class="table">
<tr><th>Port</th><th>Service</th><th>Product</th><th>Version</th></tr>
"""
        if host.get("udp"):
            for port in host["udp"]:
                html += f"<tr><td>{port['port']}</td><td>{port['service']}</td><td>{port['product']}</td><td>{port['version']}</td></tr>"
        else:
            html += "<tr><td colspan=4>No open UDP ports</td></tr>"
        html += "</table>"

        # Vulns
        html += "<h3>Notes / Potential Vulnerabilities</h3><ul>"
        if host.get("vuln_notes"):
            for note in host["vuln_notes"]:
                html += f"<li>{note}</li>"
        else:
            html += "<li>No vulnerability notes</li>"
        html += "</ul>"

        if host.get("traceroute"):
            html += "<h3>Traceroute</h3><ol>"
            for hop in host.get("traceroute", []):
                html += f"<li>{hop}</li>"
            html += "</ol>"

        html += "</div><hr class=\"divider\">"

    html += "</body></html>"
    return html
