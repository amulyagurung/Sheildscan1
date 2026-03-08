"""
ShieldScan — Main GUI Application
Dark-themed Tkinter interface with:
  • Dashboard tab   — live stats, protection status
  • Scan tab        — quick / full / custom scan with progress
  • Quarantine tab  — manage quarantined files
  • History tab     — past scan results
  • Settings tab    — real-time protection toggle, watched dirs
"""
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import os
import sys
import time
from datetime import datetime

# Ensure src package is importable when running from project root
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src import database as db
from src.engine import ScanEngine
from src.quarantine import QuarantineManager
from src.monitor import FileMonitor

# ── Colour palette ─────────────────────────────────────────────────────────────
BG       = "#1a1a2e"   # dark navy
PANEL    = "#16213e"   # slightly lighter
CARD     = "#0f3460"   # card background
ACCENT   = "#e94560"   # red accent
GREEN    = "#00b4d8"   # teal / safe
YELLOW   = "#ffd166"   # warning
RED      = "#ef233c"   # danger
TEXT     = "#eaeaea"   # primary text
SUBTEXT  = "#a8b2d8"   # secondary text
BORDER   = "#2d3561"   # border colour

FONT_H1  = ("Segoe UI", 18, "bold")
FONT_H2  = ("Segoe UI", 13, "bold")
FONT_H3  = ("Segoe UI", 11, "bold")
FONT_BODY = ("Segoe UI", 10)
FONT_MONO = ("Consolas", 9)
FONT_SMALL = ("Segoe UI", 8)


def severity_color(sev: int) -> str:
    if sev >= 8: return RED
    if sev >= 5: return YELLOW
    if sev >= 1: return "#ffa62b"
    return GREEN


# ── Reusable widgets ───────────────────────────────────────────────────────────

class StatCard(tk.Frame):
    def __init__(self, parent, label, value, color=GREEN, **kw):
        super().__init__(parent, bg=CARD, padx=14, pady=10, **kw)
        tk.Label(self, text=label, bg=CARD, fg=SUBTEXT,
                 font=FONT_SMALL).pack(anchor="w")
        self._val_lbl = tk.Label(self, text=str(value), bg=CARD,
                                  fg=color, font=("Segoe UI", 22, "bold"))
        self._val_lbl.pack(anchor="w")

    def update(self, value, color=None):
        self._val_lbl.config(text=str(value))
        if color:
            self._val_lbl.config(fg=color)


class SectionHeader(tk.Frame):
    def __init__(self, parent, title, **kw):
        super().__init__(parent, bg=PANEL, **kw)
        tk.Frame(self, bg=ACCENT, width=4, height=24).pack(side="left", padx=(0, 8))
        tk.Label(self, text=title, bg=PANEL, fg=TEXT,
                 font=FONT_H2).pack(side="left")


# ── Main App ───────────────────────────────────────────────────────────────────

class ShieldScanApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("ShieldScan — Antivirus & Malware Detection")
        self.geometry("1100x720")
        self.minsize(900, 600)
        self.configure(bg=BG)

        # Core objects
        db.init_db()
        self.engine = ScanEngine()
        self.quarantine_mgr = QuarantineManager()
        self.monitor = FileMonitor(self.engine, self._on_realtime_alert)

        self._scan_running = False
        self._scan_stop = False
        self._current_scan_id = None

        self._build_ui()
        self._refresh_dashboard()

    # ── UI construction ────────────────────────────────────────────────────────

    def _build_ui(self):
        # ── Top header bar ──────────────────────────────────────────────────
        header = tk.Frame(self, bg=PANEL, height=60)
        header.pack(fill="x", side="top")
        header.pack_propagate(False)

        logo_frame = tk.Frame(header, bg=PANEL)
        logo_frame.pack(side="left", padx=20, pady=10)
        tk.Label(logo_frame, text="🛡", bg=PANEL, fg=ACCENT,
                 font=("Segoe UI", 24)).pack(side="left")
        tk.Label(logo_frame, text="ShieldScan", bg=PANEL, fg=TEXT,
                 font=("Segoe UI", 16, "bold")).pack(side="left", padx=6)
        tk.Label(logo_frame, text="v1.0", bg=PANEL, fg=SUBTEXT,
                 font=FONT_SMALL).pack(side="left")

        self._status_lbl = tk.Label(header, text="● Protected", bg=PANEL,
                                     fg=GREEN, font=FONT_H3)
        self._status_lbl.pack(side="right", padx=20)

        # ── Sidebar navigation ───────────────────────────────────────────────
        sidebar = tk.Frame(self, bg=PANEL, width=180)
        sidebar.pack(fill="y", side="left")
        sidebar.pack_propagate(False)

        tk.Label(sidebar, text="NAVIGATION", bg=PANEL, fg=SUBTEXT,
                 font=FONT_SMALL).pack(pady=(20, 5), padx=16, anchor="w")

        self._nav_buttons = []
        nav_items = [
            ("🏠  Dashboard",  self._show_dashboard),
            ("🔍  Scan",       self._show_scan),
            ("🗂  Quarantine", self._show_quarantine),
            ("📋  History",    self._show_history),
            ("⚙   Settings",  self._show_settings),
        ]
        for label, cmd in nav_items:
            btn = tk.Button(sidebar, text=label, bg=PANEL, fg=TEXT,
                            font=FONT_BODY, anchor="w", padx=14,
                            bd=0, activebackground=CARD, activeforeground=ACCENT,
                            cursor="hand2", command=cmd)
            btn.pack(fill="x", pady=1)
            self._nav_buttons.append(btn)

        # Separator
        tk.Frame(sidebar, bg=BORDER, height=1).pack(fill="x", pady=10)
        self._rt_status_lbl = tk.Label(sidebar, text="Real-time: OFF",
                                        bg=PANEL, fg=SUBTEXT, font=FONT_SMALL)
        self._rt_status_lbl.pack(padx=16, anchor="w")

        # ── Content area ─────────────────────────────────────────────────────
        self._content = tk.Frame(self, bg=BG)
        self._content.pack(fill="both", expand=True, side="left")

        # Create all pages
        self._pages = {}
        self._pages["dashboard"]  = self._build_dashboard(self._content)
        self._pages["scan"]       = self._build_scan(self._content)
        self._pages["quarantine"] = self._build_quarantine(self._content)
        self._pages["history"]    = self._build_history(self._content)
        self._pages["settings"]   = self._build_settings(self._content)

        self._show_dashboard()

    def _show_page(self, name: str):
        for p in self._pages.values():
            p.pack_forget()
        self._pages[name].pack(fill="both", expand=True)
        # Highlight active nav button
        nav_map = {
            "dashboard": 0, "scan": 1, "quarantine": 2,
            "history": 3, "settings": 4
        }
        for i, btn in enumerate(self._nav_buttons):
            if i == nav_map.get(name, -1):
                btn.config(bg=CARD, fg=ACCENT)
            else:
                btn.config(bg=PANEL, fg=TEXT)

    def _show_dashboard(self):
        self._refresh_dashboard()
        self._show_page("dashboard")

    def _show_scan(self):
        self._show_page("scan")

    def _show_quarantine(self):
        self._refresh_quarantine()
        self._show_page("quarantine")

    def _show_history(self):
        self._refresh_history()
        self._show_page("history")

    def _show_settings(self):
        self._show_page("settings")

    # ── Dashboard ──────────────────────────────────────────────────────────────

    def _build_dashboard(self, parent) -> tk.Frame:
        page = tk.Frame(parent, bg=BG)

        # Title
        hdr = tk.Frame(page, bg=BG)
        hdr.pack(fill="x", padx=24, pady=(20, 4))
        tk.Label(hdr, text="Dashboard", bg=BG, fg=TEXT,
                 font=FONT_H1).pack(side="left")

        # Protection status banner
        self._banner = tk.Frame(page, bg=GREEN, height=50)
        self._banner.pack(fill="x", padx=24, pady=8)
        self._banner.pack_propagate(False)
        self._banner_lbl = tk.Label(self._banner,
                                     text="✔  Your system is protected",
                                     bg=GREEN, fg="white", font=FONT_H3)
        self._banner_lbl.pack(expand=True)

        # Stats row
        stats_row = tk.Frame(page, bg=BG)
        stats_row.pack(fill="x", padx=24, pady=8)

        self._stat_scans     = StatCard(stats_row, "Total Scans",    "—")
        self._stat_files     = StatCard(stats_row, "Files Scanned",  "—")
        self._stat_threats   = StatCard(stats_row, "Threats Found",  "—", RED)
        self._stat_quarant   = StatCard(stats_row, "Quarantined",    "—", YELLOW)
        self._stat_sigs      = StatCard(stats_row, "Signatures",     str(self.engine.signature_count), GREEN)

        for card in (self._stat_scans, self._stat_files, self._stat_threats,
                     self._stat_quarant, self._stat_sigs):
            card.pack(side="left", padx=4, pady=4, fill="y")

        # Quick scan button
        btn_row = tk.Frame(page, bg=BG)
        btn_row.pack(fill="x", padx=24, pady=12)

        tk.Button(btn_row, text="  ▶  Quick Scan", bg=ACCENT, fg="white",
                  font=FONT_H3, padx=20, pady=10, bd=0, cursor="hand2",
                  activebackground="#c73652",
                  command=self._quick_scan_from_dashboard).pack(side="left", padx=(0,12))

        tk.Button(btn_row, text="  🔍  Full Scan", bg=CARD, fg=TEXT,
                  font=FONT_H3, padx=20, pady=10, bd=0, cursor="hand2",
                  activebackground="#1a3a6e",
                  command=lambda: [self._show_scan(),
                                    self._scan_type_var.set("full")]).pack(side="left")

        # Recent threats section
        SectionHeader(page, "Recent Threats").pack(fill="x", padx=24, pady=(16, 4))

        cols = ("File", "Threat", "Severity", "Time")
        self._dash_tree = ttk.Treeview(page, columns=cols, show="headings",
                                        height=6)
        for c in cols:
            self._dash_tree.heading(c, text=c)
        self._dash_tree.column("File",     width=300)
        self._dash_tree.column("Threat",   width=200)
        self._dash_tree.column("Severity", width=80,  anchor="center")
        self._dash_tree.column("Time",     width=160)
        self._dash_tree.pack(fill="both", expand=True, padx=24, pady=4)
        self._apply_tree_style(self._dash_tree)

        return page

    def _refresh_dashboard(self):
        stats = db.get_stats()
        self._stat_scans.update(stats["total_scans"])
        self._stat_files.update(stats["total_files"])
        self._stat_threats.update(stats["threats_found"],
                                   RED if stats["threats_found"] else GREEN)
        self._stat_quarant.update(stats["quarantined"],
                                   YELLOW if stats["quarantined"] else GREEN)

        # Refresh recent threats table
        if hasattr(self, "_dash_tree"):
            self._dash_tree.delete(*self._dash_tree.get_children())
            with db.get_connection() as conn:
                rows = conn.execute(
                    "SELECT file_path, threat_name, severity, scanned_at"
                    " FROM scan_results WHERE status='threat'"
                    " ORDER BY scanned_at DESC LIMIT 20"
                ).fetchall()
            for r in rows:
                sev = r["severity"]
                tag = "high" if sev >= 8 else ("med" if sev >= 5 else "low")
                self._dash_tree.insert("", "end",
                    values=(os.path.basename(r["file_path"]),
                            r["threat_name"], f"  {sev}/10",
                            r["scanned_at"][:19]),
                    tags=(tag,))
            self._dash_tree.tag_configure("high", foreground=RED)
            self._dash_tree.tag_configure("med",  foreground=YELLOW)
            self._dash_tree.tag_configure("low",  foreground="#ffa62b")

    def _quick_scan_from_dashboard(self):
        self._show_scan()
        self._scan_type_var.set("quick")
        self._start_scan()

    # ── Scan page ──────────────────────────────────────────────────────────────

    def _build_scan(self, parent) -> tk.Frame:
        page = tk.Frame(parent, bg=BG)

        tk.Label(page, text="Scan", bg=BG, fg=TEXT,
                 font=FONT_H1).pack(anchor="w", padx=24, pady=(20, 4))

        # Scan type selector
        type_frame = tk.Frame(page, bg=BG)
        type_frame.pack(fill="x", padx=24, pady=8)

        self._scan_type_var = tk.StringVar(value="quick")
        types = [("Quick Scan", "quick"), ("Full Scan", "full"), ("Custom", "custom")]
        for label, val in types:
            rb = tk.Radiobutton(type_frame, text=label, variable=self._scan_type_var,
                                value=val, bg=BG, fg=TEXT, selectcolor=CARD,
                                activebackground=BG, activeforeground=ACCENT,
                                font=FONT_BODY, cursor="hand2",
                                command=self._on_scan_type_change)
            rb.pack(side="left", padx=12)

        # Custom path selector (hidden by default)
        self._custom_frame = tk.Frame(page, bg=BG)
        self._custom_path_var = tk.StringVar(value=os.path.expanduser("~"))
        tk.Entry(self._custom_frame, textvariable=self._custom_path_var,
                 bg=CARD, fg=TEXT, insertbackground=TEXT, font=FONT_BODY,
                 width=50).pack(side="left", padx=(0, 8))
        tk.Button(self._custom_frame, text="Browse…", bg=CARD, fg=TEXT,
                  font=FONT_BODY, bd=0, cursor="hand2",
                  command=self._browse_scan_dir).pack(side="left")

        # Scan controls
        ctrl_frame = tk.Frame(page, bg=BG)
        ctrl_frame.pack(fill="x", padx=24, pady=10)

        self._scan_btn = tk.Button(ctrl_frame, text="▶  Start Scan",
                                    bg=ACCENT, fg="white", font=FONT_H3,
                                    padx=20, pady=8, bd=0, cursor="hand2",
                                    activebackground="#c73652",
                                    command=self._start_scan)
        self._scan_btn.pack(side="left", padx=(0, 12))

        self._stop_btn = tk.Button(ctrl_frame, text="■  Stop",
                                    bg=CARD, fg=TEXT, font=FONT_H3,
                                    padx=20, pady=8, bd=0, cursor="hand2",
                                    state="disabled", command=self._stop_scan)
        self._stop_btn.pack(side="left")

        # Progress bar
        prog_frame = tk.Frame(page, bg=BG)
        prog_frame.pack(fill="x", padx=24, pady=4)
        self._progress_var = tk.DoubleVar()
        self._progress_bar = ttk.Progressbar(prog_frame, variable=self._progress_var,
                                              mode="indeterminate", length=400)
        self._progress_bar.pack(side="left", padx=(0, 12))
        self._progress_lbl = tk.Label(prog_frame, text="Ready", bg=BG, fg=SUBTEXT,
                                       font=FONT_BODY)
        self._progress_lbl.pack(side="left")

        # Scan summary
        summary_row = tk.Frame(page, bg=BG)
        summary_row.pack(fill="x", padx=24, pady=6)
        self._scan_stat_scanned  = StatCard(summary_row, "Files Scanned", "0")
        self._scan_stat_clean    = StatCard(summary_row, "Clean",         "0", GREEN)
        self._scan_stat_threats  = StatCard(summary_row, "Threats",       "0", RED)
        self._scan_stat_suspect  = StatCard(summary_row, "Suspicious",    "0", YELLOW)
        for c in (self._scan_stat_scanned, self._scan_stat_clean,
                  self._scan_stat_threats, self._scan_stat_suspect):
            c.pack(side="left", padx=4)

        # Results tree
        SectionHeader(page, "Scan Results").pack(fill="x", padx=24, pady=(12, 4))

        cols = ("File", "Status", "Threat", "Sev", "Method", "Time (ms)")
        self._scan_tree = ttk.Treeview(page, columns=cols, show="headings",
                                        height=10)
        self._scan_tree.heading("File",    text="File")
        self._scan_tree.heading("Status",  text="Status")
        self._scan_tree.heading("Threat",  text="Threat")
        self._scan_tree.heading("Sev",     text="Sev")
        self._scan_tree.heading("Method",  text="Method")
        self._scan_tree.heading("Time (ms)", text="Time (ms)")
        self._scan_tree.column("File",    width=300)
        self._scan_tree.column("Status",  width=90,  anchor="center")
        self._scan_tree.column("Threat",  width=180)
        self._scan_tree.column("Sev",     width=40,  anchor="center")
        self._scan_tree.column("Method",  width=100)
        self._scan_tree.column("Time (ms)", width=80, anchor="center")

        vsb = ttk.Scrollbar(page, orient="vertical",
                            command=self._scan_tree.yview)
        self._scan_tree.configure(yscrollcommand=vsb.set)
        self._scan_tree.pack(side="left", fill="both", expand=True, padx=(24, 0))
        vsb.pack(side="left", fill="y", padx=(0, 8))
        self._apply_tree_style(self._scan_tree)

        # Context menu
        menu = tk.Menu(self, tearoff=0, bg=PANEL, fg=TEXT)
        menu.add_command(label="Quarantine Selected",
                         command=self._quarantine_selected)
        self._scan_tree.bind("<Button-3>",
                             lambda e: menu.tk_popup(e.x_root, e.y_root))

        return page

    def _on_scan_type_change(self):
        if self._scan_type_var.get() == "custom":
            self._custom_frame.pack(fill="x", padx=24, pady=4)
        else:
            self._custom_frame.pack_forget()

    def _browse_scan_dir(self):
        d = filedialog.askdirectory(initialdir=self._custom_path_var.get())
        if d:
            self._custom_path_var.set(d)

    def _start_scan(self):
        if self._scan_running:
            return

        scan_type = self._scan_type_var.get()
        if scan_type == "quick":
            scan_paths = [os.path.expanduser("~/Desktop"),
                          os.path.expanduser("~/Downloads"),
                          os.path.expanduser("~/Documents")]
        elif scan_type == "full":
            scan_paths = [os.path.expanduser("~")]
        else:
            path = self._custom_path_var.get()
            if not os.path.isdir(path):
                messagebox.showerror("Error", f"Invalid directory:\n{path}")
                return
            scan_paths = [path]

        # Reset UI
        self._scan_tree.delete(*self._scan_tree.get_children())
        self._scan_running = True
        self._scan_stop = False
        self._scan_btn.config(state="disabled")
        self._stop_btn.config(state="normal")
        self._progress_bar.start(10)
        self._scan_stat_scanned.update("0")
        self._scan_stat_clean.update("0", GREEN)
        self._scan_stat_threats.update("0", RED)
        self._scan_stat_suspect.update("0", YELLOW)

        counters = {"total": 0, "clean": 0, "threats": 0, "suspect": 0}

        def progress_cb(msg):
            self.after(0, lambda: self._progress_lbl.config(text=msg[:80]))

        def scan_worker():
            for scan_path in scan_paths:
                if not os.path.isdir(scan_path):
                    # Try as a single file
                    if os.path.isfile(scan_path):
                        r = self.engine.scan_file(scan_path, progress_cb)
                        self.after(0, self._add_scan_row, r, counters)
                    continue
                for root, dirs, files in os.walk(scan_path):
                    dirs[:] = [d for d in dirs if not d.startswith(".")]
                    for fname in files:
                        if self._scan_stop:
                            break
                        fpath = os.path.join(root, fname)
                        try:
                            if os.path.getsize(fpath) > 50*1024*1024:
                                continue
                        except OSError:
                            continue
                        r = self.engine.scan_file(fpath, progress_cb)
                        self.after(0, self._add_scan_row, r, counters)
                    if self._scan_stop:
                        break

            self.after(0, self._scan_finished)

        threading.Thread(target=scan_worker, daemon=True).start()

    def _add_scan_row(self, result, counters):
        counters["total"] += 1
        if result.status == "threat":
            counters["threats"] += 1
            tag = "threat"
        elif result.status == "suspicious":
            counters["suspect"] += 1
            tag = "suspect"
        elif result.status == "error":
            tag = "error"
        else:
            counters["clean"] += 1
            tag = "clean"

        self._scan_tree.insert("", "end", values=(
            os.path.basename(result.file_path),
            result.status.upper(),
            result.threat_name or "—",
            result.severity or "—",
            result.detection_method or "—",
            f"{result.scan_time_ms:.1f}",
        ), tags=(tag,))

        # Keep newest visible
        children = self._scan_tree.get_children()
        if children:
            self._scan_tree.see(children[-1])

        self._scan_stat_scanned.update(counters["total"])
        self._scan_stat_clean.update(counters["clean"], GREEN)
        self._scan_stat_threats.update(counters["threats"],
                                        RED if counters["threats"] else GREEN)
        self._scan_stat_suspect.update(counters["suspect"],
                                        YELLOW if counters["suspect"] else GREEN)

        self._scan_tree.tag_configure("threat",  foreground=RED)
        self._scan_tree.tag_configure("suspect", foreground=YELLOW)
        self._scan_tree.tag_configure("clean",   foreground=GREEN)
        self._scan_tree.tag_configure("error",   foreground=SUBTEXT)

    def _scan_finished(self):
        self._scan_running = False
        self._scan_btn.config(state="normal")
        self._stop_btn.config(state="disabled")
        self._progress_bar.stop()
        self._progress_var.set(100)
        self._progress_lbl.config(text="Scan complete ✔")
        self._refresh_dashboard()

    def _stop_scan(self):
        self._scan_stop = True
        self._progress_lbl.config(text="Stopping…")

    def _quarantine_selected(self):
        sel = self._scan_tree.selection()
        if not sel:
            return
        item = self._scan_tree.item(sel[0])
        fname = item["values"][0]
        # Find full path from recent scan results
        with db.get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM scan_results WHERE file_path LIKE ? "
                "ORDER BY scanned_at DESC LIMIT 1",
                (f"%{fname}",)
            ).fetchone()
        if not row:
            messagebox.showinfo("Info", "File record not found.")
            return
        if messagebox.askyesno("Quarantine",
                               f"Quarantine:\n{row['file_path']}?"):
            qid = self.quarantine_mgr.quarantine(
                row["file_path"], row["file_hash"],
                row["threat_name"] or "Unknown", row["severity"] or 0
            )
            if qid:
                messagebox.showinfo("Quarantined",
                                    "File quarantined successfully.")
                self._refresh_dashboard()
            else:
                messagebox.showerror("Error",
                                     "Could not quarantine file (permission denied?).")

    # ── Quarantine page ────────────────────────────────────────────────────────

    def _build_quarantine(self, parent) -> tk.Frame:
        page = tk.Frame(parent, bg=BG)
        tk.Label(page, text="Quarantine", bg=BG, fg=TEXT,
                 font=FONT_H1).pack(anchor="w", padx=24, pady=(20, 4))

        tk.Label(page,
                 text="Quarantined files are AES-256-GCM encrypted and isolated "
                      "from the system.",
                 bg=BG, fg=SUBTEXT, font=FONT_BODY).pack(anchor="w", padx=24)

        # Buttons
        btn_row = tk.Frame(page, bg=BG)
        btn_row.pack(fill="x", padx=24, pady=10)
        tk.Button(btn_row, text="♻  Restore Selected", bg=CARD, fg=TEXT,
                  font=FONT_BODY, padx=12, pady=6, bd=0, cursor="hand2",
                  command=self._restore_selected).pack(side="left", padx=(0, 8))
        tk.Button(btn_row, text="🗑  Delete Permanently", bg="#3d0a0a", fg=RED,
                  font=FONT_BODY, padx=12, pady=6, bd=0, cursor="hand2",
                  command=self._delete_quarantine).pack(side="left")
        tk.Button(btn_row, text="↺  Refresh", bg=CARD, fg=SUBTEXT,
                  font=FONT_BODY, padx=12, pady=6, bd=0, cursor="hand2",
                  command=self._refresh_quarantine).pack(side="right")

        # Table
        cols = ("ID", "Original File", "Threat", "Severity", "Quarantined At")
        self._q_tree = ttk.Treeview(page, columns=cols, show="headings",
                                     height=20)
        self._q_tree.heading("ID",             text="ID")
        self._q_tree.heading("Original File",  text="Original File")
        self._q_tree.heading("Threat",         text="Threat")
        self._q_tree.heading("Severity",       text="Severity")
        self._q_tree.heading("Quarantined At", text="Quarantined At")
        self._q_tree.column("ID",             width=40,  anchor="center")
        self._q_tree.column("Original File",  width=350)
        self._q_tree.column("Threat",         width=180)
        self._q_tree.column("Severity",       width=70,  anchor="center")
        self._q_tree.column("Quarantined At", width=160)

        vsb = ttk.Scrollbar(page, orient="vertical", command=self._q_tree.yview)
        self._q_tree.configure(yscrollcommand=vsb.set)
        self._q_tree.pack(side="left", fill="both", expand=True, padx=(24, 0), pady=8)
        vsb.pack(side="left", fill="y", padx=(0, 8))
        self._apply_tree_style(self._q_tree)

        return page

    def _refresh_quarantine(self):
        self._q_tree.delete(*self._q_tree.get_children())
        for r in self.quarantine_mgr.list_quarantined():
            self._q_tree.insert("", "end", values=(
                r["id"],
                os.path.basename(r["original_path"]),
                r["threat_name"],
                f"  {r['severity']}/10",
                r["quarantined_at"][:19],
            ))

    def _restore_selected(self):
        sel = self._q_tree.selection()
        if not sel:
            return
        rid = int(self._q_tree.item(sel[0])["values"][0])
        if messagebox.askyesno("Restore",
                               "Restore this file to its original location?"):
            ok = self.quarantine_mgr.restore(rid)
            if ok:
                messagebox.showinfo("Restored", "File restored successfully.")
            else:
                messagebox.showerror("Error",
                                     "Restore failed. Original path may be unavailable.")
            self._refresh_quarantine()

    def _delete_quarantine(self):
        sel = self._q_tree.selection()
        if not sel:
            return
        rid = int(self._q_tree.item(sel[0])["values"][0])
        if messagebox.askyesno("Delete",
                               "Permanently delete this file? This cannot be undone.",
                               icon="warning"):
            self.quarantine_mgr.delete_permanently(rid)
            self._refresh_quarantine()

    # ── History page ──────────────────────────────────────────────────────────

    def _build_history(self, parent) -> tk.Frame:
        page = tk.Frame(parent, bg=BG)
        tk.Label(page, text="Scan History", bg=BG, fg=TEXT,
                 font=FONT_H1).pack(anchor="w", padx=24, pady=(20, 4))

        cols = ("Scan ID", "Type", "Files", "Threats", "Finished")
        self._hist_tree = ttk.Treeview(page, columns=cols, show="headings",
                                        height=22)
        for c in cols:
            self._hist_tree.heading(c, text=c)
        self._hist_tree.column("Scan ID",  width=280)
        self._hist_tree.column("Type",     width=80,  anchor="center")
        self._hist_tree.column("Files",    width=70,  anchor="center")
        self._hist_tree.column("Threats",  width=70,  anchor="center")
        self._hist_tree.column("Finished", width=160)

        vsb = ttk.Scrollbar(page, orient="vertical",
                            command=self._hist_tree.yview)
        self._hist_tree.configure(yscrollcommand=vsb.set)
        self._hist_tree.pack(side="left", fill="both", expand=True,
                             padx=(24, 0), pady=8)
        vsb.pack(side="left", fill="y", padx=(0, 8))
        self._apply_tree_style(self._hist_tree)

        return page

    def _refresh_history(self):
        self._hist_tree.delete(*self._hist_tree.get_children())
        for r in db.get_recent_scans(50):
            tag = "threats" if r["threats"] else "clean"
            self._hist_tree.insert("", "end", values=(
                r["scan_id"],
                r["scan_type"].upper(),
                r["total"],
                r["threats"],
                r["finished_at"][:19],
            ), tags=(tag,))
        self._hist_tree.tag_configure("threats", foreground=RED)
        self._hist_tree.tag_configure("clean",   foreground=GREEN)

    # ── Settings page ─────────────────────────────────────────────────────────

    def _build_settings(self, parent) -> tk.Frame:
        page = tk.Frame(parent, bg=BG)
        tk.Label(page, text="Settings", bg=BG, fg=TEXT,
                 font=FONT_H1).pack(anchor="w", padx=24, pady=(20, 4))

        # Real-time protection
        SectionHeader(page, "Real-Time Protection").pack(fill="x", padx=24, pady=(12, 4))

        rt_frame = tk.Frame(page, bg=PANEL, padx=16, pady=12)
        rt_frame.pack(fill="x", padx=24, pady=4)

        self._rt_var = tk.BooleanVar(value=False)
        tk.Label(rt_frame, text="Enable real-time file monitoring",
                 bg=PANEL, fg=TEXT, font=FONT_BODY).pack(side="left")
        tk.Checkbutton(rt_frame, variable=self._rt_var, bg=PANEL,
                       fg=TEXT, selectcolor=CARD, activebackground=PANEL,
                       command=self._toggle_realtime).pack(side="left", padx=12)

        # Watched directories
        SectionHeader(page, "Monitored Directories").pack(fill="x", padx=24, pady=(16, 4))

        wd_frame = tk.Frame(page, bg=PANEL, padx=16, pady=12)
        wd_frame.pack(fill="x", padx=24, pady=4)

        self._wd_var = tk.StringVar(value=os.path.expanduser("~/Downloads"))
        tk.Entry(wd_frame, textvariable=self._wd_var, bg=CARD, fg=TEXT,
                 insertbackground=TEXT, font=FONT_BODY, width=50).pack(side="left", padx=(0, 8))
        tk.Button(wd_frame, text="Browse…", bg=CARD, fg=TEXT,
                  font=FONT_BODY, bd=0, cursor="hand2",
                  command=lambda: self._wd_var.set(
                      filedialog.askdirectory() or self._wd_var.get()
                  )).pack(side="left")

        # Database info
        SectionHeader(page, "Database").pack(fill="x", padx=24, pady=(16, 4))
        db_frame = tk.Frame(page, bg=PANEL, padx=16, pady=12)
        db_frame.pack(fill="x", padx=24, pady=4)
        tk.Label(db_frame, text=f"Database: {db.DB_PATH}", bg=PANEL,
                 fg=SUBTEXT, font=FONT_MONO).pack(anchor="w")
        tk.Label(db_frame, text=f"Signatures loaded: {self.engine.signature_count}",
                 bg=PANEL, fg=SUBTEXT, font=FONT_BODY).pack(anchor="w", pady=4)

        # About
        SectionHeader(page, "About").pack(fill="x", padx=24, pady=(16, 4))
        about_frame = tk.Frame(page, bg=PANEL, padx=16, pady=12)
        about_frame.pack(fill="x", padx=24, pady=4)
        about_text = (
            "ShieldScan v1.0  —  Antivirus & Malware Detection Tool\n"
            "Ethical Hacking & Cyber Security Individual Project\n\n"
            "Detection layers: Signature (SHA-256) · Pattern (Aho-Corasick Trie) · "
            "Heuristic · Behavioural\n"
            "Custom data structures: HashTable (FNV-1a) · PatternTrie · PriorityQueue (max-heap)\n"
            "Quarantine encryption: AES-256-GCM"
        )
        tk.Label(about_frame, text=about_text, bg=PANEL, fg=SUBTEXT,
                 font=FONT_BODY, justify="left").pack(anchor="w")

        return page

    def _toggle_realtime(self):
        if self._rt_var.get():
            watch_dir = self._wd_var.get()
            if not os.path.isdir(watch_dir):
                messagebox.showerror("Error", f"Directory not found:\n{watch_dir}")
                self._rt_var.set(False)
                return
            self.monitor.start([watch_dir])
            self._rt_status_lbl.config(text="Real-time: ON", fg=GREEN)
            self._status_lbl.config(text="● Protected + Live", fg=GREEN)
            messagebox.showinfo("Real-Time Protection",
                                f"Now monitoring:\n{watch_dir}")
        else:
            self.monitor.stop()
            self._rt_status_lbl.config(text="Real-time: OFF", fg=SUBTEXT)
            self._status_lbl.config(text="● Protected", fg=GREEN)

    # ── Real-time alert callback ───────────────────────────────────────────────

    def _on_realtime_alert(self, result):
        """Called from monitor thread — must use after() to update GUI."""
        def _show():
            msg = (f"⚠ Threat Detected!\n\n"
                   f"File: {os.path.basename(result.file_path)}\n"
                   f"Threat: {result.threat_name}\n"
                   f"Severity: {result.severity}/10\n\n"
                   f"Quarantine this file?")
            if messagebox.askyesno("Real-Time Alert", msg, icon="warning"):
                self.quarantine_mgr.quarantine(
                    result.file_path, result.file_hash,
                    result.threat_name, result.severity
                )
                self._refresh_dashboard()
        self.after(0, _show)

    # ── Treeview styling ──────────────────────────────────────────────────────

    def _apply_tree_style(self, tree: ttk.Treeview):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview",
                         background=PANEL,
                         foreground=TEXT,
                         fieldbackground=PANEL,
                         rowheight=24,
                         font=FONT_BODY)
        style.configure("Treeview.Heading",
                         background=CARD,
                         foreground=TEXT,
                         font=FONT_H3)
        style.map("Treeview",
                  background=[("selected", CARD)],
                  foreground=[("selected", ACCENT)])

    def on_close(self):
        self.monitor.stop()
        self.destroy()


# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app = ShieldScanApp()
    app.protocol("WM_DELETE_WINDOW", app.on_close)
    app.mainloop()
