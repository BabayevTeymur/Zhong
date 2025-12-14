
import json
import datetime
from pathlib import Path
from typing import List, Dict, Any

from PyQt6 import QtWidgets, QtCore, QtGui

from scanner_core import ScanConfig, run_full_scan
from reporting import export_json, generate_markdown_report, generate_html_report

from utils import safe_int_ip


BASE_DIR = Path(__file__).resolve().parent
PROFILES_PATH = BASE_DIR / "profiles.json"
HELP_HTML_PATH = BASE_DIR / "help.html"
THEME_PATH = BASE_DIR / "themes" / "zhong_dark.qss"


class ScanWorker(QtCore.QThread):
    progress = QtCore.pyqtSignal(str)
    finished = QtCore.pyqtSignal(list)

    def __init__(self, cfg: ScanConfig, parent=None):
        super().__init__(parent)
        self.cfg = cfg
        self._stop = False

    def run(self):
        def log_func(msg: str):
            self.progress.emit(msg)

        results = run_full_scan(self.cfg, log_func=log_func)
        if self._stop:
            return
        self.finished.emit(results)

    def stop(self):
        self._stop = True


class TopologyView(QtWidgets.QGraphicsView):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setScene(QtWidgets.QGraphicsScene(self))
        self.setRenderHints(
            QtGui.QPainter.RenderHint.Antialiasing |
            QtGui.QPainter.RenderHint.TextAntialiasing
        )

    def draw_topology(self, hosts: List[Dict[str, Any]]):
        scene = self.scene()
        scene.clear()
        if not hosts:
            return

        center_x, center_y = 0, 0
        radius = 200
        scene.addEllipse(center_x - 40, center_y - 40, 80, 80,
                         pen=QtGui.QPen(QtGui.QColor("#c598ff"), 2),
                         brush=QtGui.QBrush(QtGui.QColor("#120a1f")))
        gw_label = scene.addText("GW", QtGui.QFont("Segoe UI", 9, weight=QtGui.QFont.Weight.Bold))
        gw_label.setDefaultTextColor(QtGui.QColor("#f0e8ff"))
        gw_label.setPos(center_x - 14, center_y - 14)

        import math
        others = hosts
        n = len(others)
        if n == 0:
            return

        host_positions: dict[str, tuple[float, float]] = {}

        for idx, host in enumerate(sorted(others, key=lambda h: safe_int_ip(h["ip"]))):
            angle = 2 * math.pi * idx / n
            x = center_x + radius * math.cos(angle)
            y = center_y + radius * math.sin(angle)
            host_positions[host.get("ip", f"host-{idx}")] = (x, y)

            color = QtGui.QColor("#b583ff")
            os_name = host.get("os") or ""
            vendor = host.get("vendor") or ""
            if "Windows" in os_name:
                color = QtGui.QColor("#a67cff")
            elif "Linux" in os_name or "Unix" in os_name:
                color = QtGui.QColor("#7f9bff")
            elif "Xiaomi" in vendor or "Android" in os_name:
                color = QtGui.QColor("#d88cff")

            item = scene.addEllipse(x - 25, y - 25, 50, 50,
                                    pen=QtGui.QPen(QtGui.QColor("#2b1844"), 1.5),
                                    brush=QtGui.QBrush(color.darker(170)))
            label = scene.addText(host.get("ip", ""), QtGui.QFont("Segoe UI", 7))
            label.setDefaultTextColor(QtGui.QColor("#f0e8ff"))
            label.setPos(x - 35, y + 30)

            tooltip = [
                f"IP: {host.get('ip')}",
                f"Subnet: {host.get('subnet') or '-'}",
                f"MAC: {host.get('mac') or '-'}",
                f"OS: {host.get('os') or '-'}",
                f"Vendor: {host.get('vendor') or '-'}",
                f"TCP open: {len(host.get('tcp', []))}",
                f"UDP open: {len(host.get('udp', []))}",
            ]
            if host.get("traceroute"):
                tooltip.append(f"Traceroute hops: {len(host['traceroute'])}")
                tooltip.append("Path: " + " → ".join(host.get("traceroute", [])))
            item.setToolTip("\n".join(tooltip))
            label.setToolTip("\n".join(tooltip))

        for host in sorted(others, key=lambda h: safe_int_ip(h["ip"])):
            dest = host_positions.get(host.get("ip"), (center_x, center_y))
            hops = host.get("traceroute") or []
            if hops:
                points: list[tuple[float, float, str]] = []
                for idx, hop in enumerate(hops):
                    frac = (idx + 1) / (len(hops) + 1)
                    hx = center_x + (dest[0] - center_x) * frac
                    hy = center_y + (dest[1] - center_y) * frac
                    points.append((hx, hy, hop))
                prev = (center_x, center_y, "GW")
                for hx, hy, hop in points:
                    path = QtGui.QPainterPath()
                    path.moveTo(prev[0], prev[1])
                    path.lineTo(hx, hy)
                    scene.addPath(path, QtGui.QPen(QtGui.QColor("#6b5ea3"), 1.2, QtCore.Qt.PenStyle.DashLine))
                    hop_item = scene.addEllipse(hx - 10, hy - 10, 20, 20,
                                                pen=QtGui.QPen(QtGui.QColor("#2c1b45"), 1),
                                                brush=QtGui.QBrush(QtGui.QColor("#7d68ad")))
                    hop_label = scene.addText(hop, QtGui.QFont("Segoe UI", 6))
                    hop_label.setDefaultTextColor(QtGui.QColor("#f0e8ff"))
                    hop_label.setPos(hx - 20, hy + 12)
                    hop_item.setToolTip(f"Hop: {hop}")
                    hop_label.setToolTip(f"Hop: {hop}")
                    prev = (hx, hy, hop)
                path = QtGui.QPainterPath()
                path.moveTo(prev[0], prev[1])
                path.lineTo(dest[0], dest[1])
                scene.addPath(path, QtGui.QPen(QtGui.QColor("#c598ff"), 1.2))
            else:
                path = QtGui.QPainterPath()
                path.moveTo(center_x, center_y)
                path.lineTo(dest[0], dest[1])
                scene.addPath(path, QtGui.QPen(QtGui.QColor("#2b1844"), 1))


class ZhongMainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Zhong – LAN Recon")
        self.resize(1400, 850)

        self.cfg: ScanConfig | None = None
        self.worker: ScanWorker | None = None
        self.hosts: List[Dict[str, Any]] = []
        self.scan_started: datetime.datetime | None = None

        self._load_profiles()
        self._build_ui()
        self._apply_theme()

    def _load_profiles(self):
        self.profiles = {}
        if PROFILES_PATH.exists():
            try:
                self.profiles = json.loads(PROFILES_PATH.read_text(encoding="utf-8"))
            except Exception:
                self.profiles = {}

    def _apply_theme(self):
        if THEME_PATH.exists():
            try:
                qss = THEME_PATH.read_text(encoding="utf-8")
                self.setStyleSheet(qss)
            except Exception:
                pass

    def _build_ui(self):
        central = QtWidgets.QWidget()
        self.setCentralWidget(central)

        layout = QtWidgets.QVBoxLayout(central)

        top_bar = QtWidgets.QHBoxLayout()
        layout.addLayout(top_bar)

        self.subnet_edit = QtWidgets.QLineEdit("192.168.0.0/24")
        self.target_mode_combo = QtWidgets.QComboBox()
        self.target_mode_combo.addItems(["Subnet", "Single host"])
        self.target_mode_combo.currentTextChanged.connect(self.on_target_mode_changed)
        self.profile_combo = QtWidgets.QComboBox()
        self.profile_combo.addItems(["Fast", "Balanced", "Deep", "Stealth", "Custom"])
        self.profile_combo.currentTextChanged.connect(self.on_profile_changed)

        self.os_check = QtWidgets.QCheckBox("OS detection")
        self.os_check.setChecked(True)
        self.service_check = QtWidgets.QCheckBox("Service/version detection")
        self.service_check.setChecked(False)
        self.traceroute_check = QtWidgets.QCheckBox("Traceroute path")
        self.osint_check = QtWidgets.QCheckBox("OSINT lookup (ipinfo.io)")
        self.wan_check = QtWidgets.QCheckBox("WAN scan")

        self.start_btn = QtWidgets.QPushButton("Start Scan")
        self.stop_btn = QtWidgets.QPushButton("Stop")
        self.stop_btn.setEnabled(False)
        self.start_btn.clicked.connect(self.start_scan)
        self.stop_btn.clicked.connect(self.stop_scan)

        top_bar.addWidget(QtWidgets.QLabel("Target:"))
        top_bar.addWidget(self.subnet_edit, 2)
        top_bar.addWidget(self.target_mode_combo)
        top_bar.addWidget(QtWidgets.QLabel("Profile:"))
        top_bar.addWidget(self.profile_combo, 1)
        top_bar.addWidget(self.os_check)
        top_bar.addWidget(self.service_check)
        top_bar.addWidget(self.traceroute_check)
        top_bar.addWidget(self.osint_check)
        top_bar.addWidget(self.wan_check)
        top_bar.addStretch()
        top_bar.addWidget(self.start_btn)
        top_bar.addWidget(self.stop_btn)

        splitter = QtWidgets.QSplitter()
        splitter.setOrientation(QtCore.Qt.Orientation.Vertical)
        layout.addWidget(splitter, 1)

        self.tabs = QtWidgets.QTabWidget()
        splitter.addWidget(self.tabs)

        self._build_scan_tab()
        self._build_results_tab()
        self._build_topology_tab()
        self._build_help_tab()

        self.log_output = QtWidgets.QPlainTextEdit()
        self.log_output.setReadOnly(True)
        splitter.addWidget(self.log_output)

        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 1)

        self.on_profile_changed(self.profile_combo.currentText())

    def _build_scan_tab(self):
        scan_tab = QtWidgets.QWidget()
        self.tabs.addTab(scan_tab, "Scan Settings")
        layout = QtWidgets.QVBoxLayout(scan_tab)

        grid = QtWidgets.QGridLayout()
        layout.addLayout(grid)

        self.tcp_ports_edit = QtWidgets.QLineEdit()
        self.udp_ports_edit = QtWidgets.QLineEdit()
        self.full_port_check = QtWidgets.QCheckBox("Full sweep (all ports)")
        self.full_port_check.setToolTip("Scan the entire TCP/UDP range using nmap -p-.")
        self.full_port_check.toggled.connect(self.on_full_port_toggle)

        self.timing_combo = QtWidgets.QComboBox()
        self.timing_combo.addItems(["T0", "T1", "T2", "T3", "T4", "T5"])
        self.timing_combo.setCurrentText("T4")

        self.scan_type_combo = QtWidgets.QComboBox()
        self.scan_type_combo.addItems(["SYN", "CONNECT"])
        self.scan_type_combo.setCurrentText("SYN")

        self.discovery_combo = QtWidgets.QComboBox()
        self.discovery_combo.addItems(["ARP+Ping", "ARP only", "Ping only", "No ping (-Pn)"])
        self.discovery_combo.setCurrentText("ARP+Ping")

        self.threads_spin = QtWidgets.QSpinBox()
        self.threads_spin.setRange(1, 512)
        self.threads_spin.setValue(64)

        self.retries_spin = QtWidgets.QSpinBox()
        self.retries_spin.setRange(1, 5)
        self.retries_spin.setValue(2)

        self.udp_fallback_check = QtWidgets.QCheckBox("UDP-only fallback on failure")
        self.udp_fallback_check.setChecked(True)

        self.exclude_edit = QtWidgets.QLineEdit()
        self.extra_args_edit = QtWidgets.QLineEdit()
        self.aggressive_check = QtWidgets.QCheckBox("Aggressive (-A)")
        self.dns_check = QtWidgets.QCheckBox("Disable DNS (-n)")
        self.reason_check = QtWidgets.QCheckBox("Show reasons (--reason)")

        row = 0
        grid.addWidget(QtWidgets.QLabel("TCP ports:"), row, 0)
        grid.addWidget(self.tcp_ports_edit, row, 1, 1, 3)
        row += 1
        grid.addWidget(QtWidgets.QLabel("UDP ports:"), row, 0)
        grid.addWidget(self.udp_ports_edit, row, 1, 1, 3)
        row += 1

        grid.addWidget(self.full_port_check, row, 0, 1, 4)
        row += 1

        grid.addWidget(QtWidgets.QLabel("Timing:"), row, 0)
        grid.addWidget(self.timing_combo, row, 1)
        grid.addWidget(QtWidgets.QLabel("Scan type:"), row, 2)
        grid.addWidget(self.scan_type_combo, row, 3)
        row += 1

        grid.addWidget(QtWidgets.QLabel("Discovery:"), row, 0)
        grid.addWidget(self.discovery_combo, row, 1)
        grid.addWidget(QtWidgets.QLabel("Threads:"), row, 2)
        grid.addWidget(self.threads_spin, row, 3)
        row += 1

        grid.addWidget(QtWidgets.QLabel("Retries:"), row, 0)
        grid.addWidget(self.retries_spin, row, 1)
        grid.addWidget(self.udp_fallback_check, row, 2, 1, 2)
        row += 1

        grid.addWidget(self.aggressive_check, row, 0)
        grid.addWidget(self.dns_check, row, 1)
        grid.addWidget(self.reason_check, row, 2)
        row += 1

        grid.addWidget(QtWidgets.QLabel("Exclude hosts:"), row, 0)
        grid.addWidget(self.exclude_edit, row, 1, 1, 3)
        row += 1

        grid.addWidget(QtWidgets.QLabel("Extra nmap args:"), row, 0)
        grid.addWidget(self.extra_args_edit, row, 1, 1, 3)
        row += 1

        layout.addStretch()

    def _build_results_tab(self):
        res_tab = QtWidgets.QWidget()
        self.tabs.addTab(res_tab, "Results")
        layout = QtWidgets.QHBoxLayout(res_tab)

        left = QtWidgets.QVBoxLayout()
        layout.addLayout(left, 2)

        self.scan_info_label = QtWidgets.QLabel("No scans run yet.")
        self.scan_info_label.setObjectName("scanInfo")
        left.addWidget(self.scan_info_label)

        self.host_table = QtWidgets.QTableWidget(0, 7)
        self.host_table.setHorizontalHeaderLabels(["IP", "Subnet", "MAC", "OS", "Vendor", "TCP", "UDP"])
        self.host_table.horizontalHeader().setStretchLastSection(True)
        self.host_table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectionBehavior.SelectRows)
        self.host_table.setEditTriggers(QtWidgets.QAbstractItemView.EditTrigger.NoEditTriggers)
        self.host_table.itemSelectionChanged.connect(self.on_host_selected)

        left.addWidget(self.host_table)

        export_bar = QtWidgets.QHBoxLayout()
        left.addLayout(export_bar)
        self.export_json_btn = QtWidgets.QPushButton("Export JSON")
        self.export_md_btn = QtWidgets.QPushButton("Export MD")
        self.export_html_btn = QtWidgets.QPushButton("Export HTML")
        self.export_json_btn.clicked.connect(self.export_json_report)
        self.export_md_btn.clicked.connect(self.export_md_report)
        self.export_html_btn.clicked.connect(self.export_html_report)
        export_bar.addWidget(self.export_json_btn)
        export_bar.addWidget(self.export_md_btn)
        export_bar.addWidget(self.export_html_btn)
        export_bar.addStretch()

        right = QtWidgets.QVBoxLayout()
        layout.addLayout(right, 3)

        self.details_text = QtWidgets.QTextEdit()
        self.details_text.setReadOnly(True)
        right.addWidget(self.details_text)

        btn_bar = QtWidgets.QHBoxLayout()
        right.addLayout(btn_bar)
        self.copy_details_btn = QtWidgets.QPushButton("Copy host summary")
        self.copy_details_btn.clicked.connect(self.copy_host_summary)
        btn_bar.addWidget(self.copy_details_btn)
        btn_bar.addStretch()

    def _build_topology_tab(self):
        topo_tab = QtWidgets.QWidget()
        self.tabs.addTab(topo_tab, "Topology")
        layout = QtWidgets.QVBoxLayout(topo_tab)
        self.topology_view = TopologyView()
        layout.addWidget(self.topology_view)

    def _build_help_tab(self):
        help_tab = QtWidgets.QWidget()
        self.tabs.addTab(help_tab, "Help")
        layout = QtWidgets.QVBoxLayout(help_tab)

        self.help_browser = QtWidgets.QTextBrowser()
        if HELP_HTML_PATH.exists():
            self.help_browser.setSource(QtCore.QUrl.fromLocalFile(str(HELP_HTML_PATH)))
        else:
            self.help_browser.setHtml("<h1>Zhong</h1><p>Help file not found.</p>")

        layout.addWidget(self.help_browser)

        btn_bar = QtWidgets.QHBoxLayout()
        layout.addLayout(btn_bar)
        self.open_html_btn = QtWidgets.QPushButton("Open help.html")
        self.open_html_btn.clicked.connect(self.open_html_help)
        self.open_pdf_btn = QtWidgets.QPushButton("Open PDF manual (if present)")
        self.open_pdf_btn.clicked.connect(self.open_pdf_manual)
        btn_bar.addWidget(self.open_html_btn)
        btn_bar.addWidget(self.open_pdf_btn)
        btn_bar.addStretch()

    def log(self, msg: str):
        self.log_output.appendPlainText(msg)
        cursor = self.log_output.textCursor()
        cursor.movePosition(QtGui.QTextCursor.MoveOperation.End)
        self.log_output.setTextCursor(cursor)

    def on_profile_changed(self, text: str):
        key = text.lower()
        if key in self.profiles:
            p = self.profiles[key]
            if not self.full_port_check.isChecked():
                self.tcp_ports_edit.setText(p.get("tcp_ports", ""))
                self.udp_ports_edit.setText(p.get("udp_ports", ""))
            if p.get("timing"):
                self.timing_combo.setCurrentText(p["timing"])
        else:
            pass

    def on_target_mode_changed(self, text: str):
        if text == "Single host":
            self.subnet_edit.setPlaceholderText("Enter a single IP (e.g. 8.8.8.8)")
        else:
            self.subnet_edit.setPlaceholderText("CIDR subnet (e.g. 192.168.0.0/24)")

    def on_full_port_toggle(self, checked: bool):
        self.tcp_ports_edit.setDisabled(checked)
        self.udp_ports_edit.setDisabled(checked)
        if checked:
            self.tcp_ports_edit.setText("-")
            self.udp_ports_edit.setText("-")
        else:
            if self.profile_combo.currentText().lower() in self.profiles:
                self.on_profile_changed(self.profile_combo.currentText())
            else:
                self.tcp_ports_edit.clear()
                self.udp_ports_edit.clear()

    def _build_config_from_ui(self) -> ScanConfig:
        subnet = self.subnet_edit.text().strip()
        tcp_ports = "-" if self.full_port_check.isChecked() else self.tcp_ports_edit.text().strip()
        udp_ports = "-" if self.full_port_check.isChecked() else self.udp_ports_edit.text().strip()
        profile = self.profile_combo.currentText()
        timing = self.timing_combo.currentText()
        scan_type = self.scan_type_combo.currentText()
        discovery_map = {
            "ARP+Ping": "arp_ping",
            "ARP only": "arp",
            "Ping only": "ping",
            "No ping (-Pn)": "noprobe",
        }
        discovery_mode = discovery_map[self.discovery_combo.currentText()]
        cfg = ScanConfig(
            subnet=subnet,
            tcp_ports=tcp_ports,
            udp_ports=udp_ports,
            profile_name=profile.lower(),
            os_scan=self.os_check.isChecked(),
            service_version=self.service_check.isChecked(),
            timing=timing,
            scan_type=scan_type,
            extra_args=self.extra_args_edit.text().strip(),
            exclude=self.exclude_edit.text().strip(),
            retries=self.retries_spin.value(),
            threads=self.threads_spin.value(),
            udp_fallback=self.udp_fallback_check.isChecked(),
            discovery_mode=discovery_mode,
            target_type="host" if self.target_mode_combo.currentText() == "Single host" else "subnet",
            wan_scan=self.wan_check.isChecked(),
            osint_lookup=self.osint_check.isChecked(),
            traceroute=self.traceroute_check.isChecked(),
            aggressive=self.aggressive_check.isChecked(),
            disable_dns=self.dns_check.isChecked(),
            reason_flag=self.reason_check.isChecked(),
        )
        return cfg

    def start_scan(self):
        if self.worker and self.worker.isRunning():
            return
        cfg = self._build_config_from_ui()
        self.cfg = cfg
        self.scan_started = datetime.datetime.now()
        self.hosts = []
        self.host_table.setRowCount(0)
        self.details_text.clear()
        self.topology_view.scene().clear()

        extra_flags = []
        if cfg.target_type == "host":
            extra_flags.append("single-host")
        if cfg.wan_scan:
            extra_flags.append("WAN")
        if cfg.traceroute:
            extra_flags.append("traceroute")
        if cfg.osint_lookup:
            extra_flags.append("OSINT")
        if self.full_port_check.isChecked():
            extra_flags.append("all-ports")
        flag_text = f" [{', '.join(extra_flags)}]" if extra_flags else ""
        self.log(
            f"[+] Starting scan on {cfg.subnet} (profile: {cfg.profile_name}){flag_text} at {self.scan_started.isoformat(timespec='seconds')}"
        )
        self.worker = ScanWorker(cfg)
        self.worker.progress.connect(self.log)
        self.worker.finished.connect(self.on_scan_finished)
        self.worker.start()
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)

    def stop_scan(self):
        if self.worker and self.worker.isRunning():
            self.worker.stop()
            self.worker.terminate()
            self.log("[!] Scan stopped by user.")
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

    def on_scan_finished(self, hosts: list[dict]):
        self.hosts = hosts or []
        finished_at = datetime.datetime.now()
        self.log(
            f"[+] Scan finished, {len(self.hosts)} hosts. Completed at {finished_at.isoformat(timespec='seconds')}"
        )
        if self.scan_started:
            duration = finished_at - self.scan_started
            self.scan_info_label.setText(
                f"Last scan: {self.scan_started.strftime('%Y-%m-%d %H:%M:%S')} ({duration.total_seconds():.1f}s)"
            )
        self._populate_host_table()
        self.topology_view.draw_topology(self.hosts)
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

    def _populate_host_table(self):
        self.host_table.setRowCount(0)
        for host in sorted(self.hosts, key=lambda h: safe_int_ip(h["ip"])):
            row = self.host_table.rowCount()
            self.host_table.insertRow(row)
            vals = [
                host.get("ip"),
                host.get("subnet") or "",
                host.get("mac") or "",
                host.get("os") or "",
                host.get("vendor") or "",
                str(len(host.get("tcp", []))),
                str(len(host.get("udp", []))),
            ]
            for col, v in enumerate(vals):
                item = QtWidgets.QTableWidgetItem(v)
                self.host_table.setItem(row, col, item)

    def on_host_selected(self):
        items = self.host_table.selectedItems()
        if not items:
            return
        row = items[0].row()
        ip = self.host_table.item(row, 0).text()
        host = next((h for h in self.hosts if h.get("ip") == ip), None)
        if not host:
            return
        self._show_host_details(host)

    def _show_host_details(self, host: dict):
        lines = []
        lines.append(f"IP: {host.get('ip')}")
        lines.append(f"Subnet: {host.get('subnet') or '-'}")
        lines.append(f"MAC: {host.get('mac') or '-'}")
        lines.append(f"Hostname: {host.get('hostname') or '-'}")
        lines.append(f"OS: {host.get('os') or '-'}")
        lines.append(f"Vendor: {host.get('vendor') or '-'}")
        if self.scan_started:
            lines.append(f"Scan timestamp: {self.scan_started.strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("")
        lines.append(f"TCP Ports ({len(host.get('tcp', []))}):")
        for e in host.get("tcp", []):
            lines.append(f"  - {e.get('port')} / {e.get('service','')} "
                         f"{e.get('product','')} {e.get('version','')} {e.get('extrainfo','')}")
        lines.append("")
        lines.append(f"UDP Ports ({len(host.get('udp', []))}):")
        for e in host.get("udp", []):
            lines.append(f"  - {e.get('port')} / {e.get('service','')} "
                         f"{e.get('product','')} {e.get('version','')} {e.get('extrainfo','')}")
        if host.get("vuln_notes"):
            lines.append("")
            lines.append("Vulnerability notes:")
            for n in host["vuln_notes"]:
                lines.append(f"  - {n}")

        if host.get("osint"):
            lines.append("")
            lines.append("OSINT (ipinfo.io):")
            for k, v in host.get("osint", {}).items():
                lines.append(f"  {k}: {v}")

        if host.get("traceroute"):
            lines.append("")
            lines.append("Traceroute:")
            for idx, hop in enumerate(host.get("traceroute", []), start=1):
                lines.append(f"  {idx}: {hop}")

        self.details_text.setPlainText("\n".join(lines))

    def copy_host_summary(self):
        text = self.details_text.toPlainText().strip()
        if not text:
            return
        cb = QtWidgets.QApplication.clipboard()
        cb.setText(text)

    def _ensure_hosts(self):
        if not self.hosts:
            QtWidgets.QMessageBox.warning(self, "Zhong", "No hosts to export yet.")
            return False
        return True

    def _build_metadata(self) -> dict:
        return {
            "generated_at": (self.scan_started or datetime.datetime.now()).strftime("%Y-%m-%d %H:%M:%S"),
            "target": self.cfg.subnet if self.cfg else "-",
            "profile": self.cfg.profile_name if self.cfg else "-",
            "mode": "all-ports" if self.full_port_check.isChecked() else "custom-ports",
        }

    def export_json_report(self):
        if not self._ensure_hosts():
            return
        fn, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Save JSON", "zhong_scan.json", "JSON (*.json)")
        if not fn:
            return
        export_json(self.hosts, fn, metadata=self._build_metadata())

    def export_md_report(self):
        if not self._ensure_hosts():
            return
        fn, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Save Markdown", "zhong_scan.md", "Markdown (*.md)")
        if not fn:
            return
        md_text = generate_markdown_report(self.hosts, metadata=self._build_metadata())
        with open(fn, "w", encoding="utf-8") as f:
            f.write(md_text)

    def export_html_report(self):
        if not self._ensure_hosts():
            return
        fn, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Save HTML", "zhong_scan.html", "HTML (*.html)")
        if not fn:
            return
        html_text = generate_html_report(self.hosts, metadata=self._build_metadata())
        with open(fn, "w", encoding="utf-8") as f:
            f.write(html_text)

    def open_html_help(self):
        if HELP_HTML_PATH.exists():
            QtGui.QDesktopServices.openUrl(QtCore.QUrl.fromLocalFile(str(HELP_HTML_PATH)))
        else:
            QtWidgets.QMessageBox.warning(self, "Zhong", "help.html not found.")

    def open_pdf_manual(self):
        pdf = BASE_DIR / "manual.pdf"
        if pdf.exists():
            QtGui.QDesktopServices.openUrl(QtCore.QUrl.fromLocalFile(str(pdf)))
        else:
            QtWidgets.QMessageBox.information(
                self,
                "Zhong",
                "manual.pdf not found. You can generate a PDF by opening help.html in a browser and printing to PDF."
            )


def main():
    import sys
    app = QtWidgets.QApplication(sys.argv)
    win = ZhongMainWindow()
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
