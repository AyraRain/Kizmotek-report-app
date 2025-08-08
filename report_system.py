#!/usr/bin/env python3
"""
Report System - Dark mode fixes + Auto-webhook send + customization

- Full single-file Tkinter app
- Dark-mode properly applied to all widgets (restores original on disable)
- Auto-send webhook toggle in Settings
- Customizable Ranks list in Settings
- Editable and reorderable Results buttons in Settings
- Webhook payload includes timestamp that matches saved report timestamp
- Keeps settings, punishment editor, separate report/ban DBs, search box, warnings, etc.
"""

import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import sqlite3
import json
import re
import os
from datetime import datetime

# optional requests for webhook posting
try:
    import requests
except Exception:
    requests = None

# ---------- Files & defaults ----------
SETTINGS_FILE = "settings.json"
REPORT_DB = "report_logs.db"
BAN_DB = "ban_logs.db"

DEFAULT_SETTINGS = {
    "rank": "Department Manager",
    "moderator_id": "299146723979427840",
    "webhook_url": "",
    "auto_send_webhook": True,
    "ranks": [
        "Department Manager",
        "Senior Manager",
        "Moderator",
        "Junior Mod",
    ],
    "results": [
        "NEF",
        "Banned",
        "Forwarded",
    ],
    "punishments": [
        {"name": "Toxicity", "action": "Warn / Tempban"},
        {"name": "Spawn Camping", "action": "Warn / Tempban"},
        {"name": "NSFW", "action": "Kick / Tempban"},
        {"name": "Exploiting", "action": "Permaban"},
        {"name": "Avatar Abuse", "action": "Warn"},
    ],
    "dark_mode": False,
}

# ---------- Settings helpers ----------
def load_settings():
    if not os.path.isfile(SETTINGS_FILE):
        save_settings(dict(DEFAULT_SETTINGS))
        return dict(DEFAULT_SETTINGS)
    try:
        with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
            cfg = json.load(f)
    except Exception:
        cfg = dict(DEFAULT_SETTINGS)
    for k, v in DEFAULT_SETTINGS.items():
        if k not in cfg:
            cfg[k] = v
    # coerce types/sanity
    if not isinstance(cfg.get("ranks"), list) or not cfg["ranks"]:
        cfg["ranks"] = list(DEFAULT_SETTINGS["ranks"])
    if not isinstance(cfg.get("results"), list) or not cfg["results"]:
        cfg["results"] = list(DEFAULT_SETTINGS["results"])
    if not isinstance(cfg.get("punishments"), list):
        cfg["punishments"] = list(DEFAULT_SETTINGS["punishments"])  # shallow copy ok
    if "auto_send_webhook" not in cfg:
        cfg["auto_send_webhook"] = True
    return cfg

def save_settings(cfg):
    with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)

# ---------- Database helpers ----------
def init_databases():
    # reports DB
    conn = sqlite3.connect(REPORT_DB)
    cur = conn.cursor()
    cur.execute(
        """
    CREATE TABLE IF NOT EXISTS reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        rank TEXT,
        reporter TEXT,
        reporter_profile TEXT,
        reported TEXT,
        reported_profile TEXT,
        reason TEXT,
        result TEXT,
        jobid TEXT,
        raw TEXT
    )
    """
    )
    conn.commit()
    conn.close()

    # bans DB
    conn = sqlite3.connect(BAN_DB)
    cur = conn.cursor()
    cur.execute(
        """
    CREATE TABLE IF NOT EXISTS bans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        rank TEXT,
        user TEXT,
        reason TEXT,
        punishment TEXT,
        proof TEXT,
        report_id INTEGER
    )
    """
    )
    conn.commit()
    conn.close()


def add_report_to_db(rep):
    conn = sqlite3.connect(REPORT_DB)
    cur = conn.cursor()
    cur.execute(
        """
    INSERT INTO reports (timestamp, rank, reporter, reporter_profile, reported, reported_profile, reason, result, jobid, raw)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """,
        (
            rep.get("timestamp"),
            rep.get("rank"),
            rep.get("reporter"),
            rep.get("reporter_profile"),
            rep.get("reported"),
            rep.get("reported_profile"),
            rep.get("reason"),
            rep.get("result"),
            rep.get("jobid"),
            rep.get("raw"),
        ),
    )
    conn.commit()
    rowid = cur.lastrowid
    conn.close()
    return rowid


def add_ban_to_db(ban):
    conn = sqlite3.connect(BAN_DB)
    cur = conn.cursor()
    cur.execute(
        """
    INSERT INTO bans (timestamp, rank, user, reason, punishment, proof, report_id)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    """,
        (
            ban.get("timestamp"),
            ban.get("rank"),
            ban.get("user"),
            ban.get("reason"),
            ban.get("punishment"),
            ban.get("proof"),
            ban.get("report_id"),
        ),
    )
    conn.commit()
    rowid = cur.lastrowid
    conn.close()
    return rowid


def find_reports_for_player(player_name_or_id):
    conn = sqlite3.connect(REPORT_DB)
    cur = conn.cursor()
    q = f"%{player_name_or_id}%"
    cur.execute(
        """
    SELECT id, timestamp, reporter, reported, reason, jobid FROM reports
    WHERE reporter LIKE ? OR reported LIKE ? OR reporter_profile LIKE ? OR reported_profile LIKE ?
    ORDER BY id DESC
    """,
        (q, q, q, q),
    )
    rows = cur.fetchall()
    conn.close()
    return rows


def count_reports_for_player(player_name_or_id):
    conn = sqlite3.connect(REPORT_DB)
    cur = conn.cursor()
    q = f"%{player_name_or_id}%"
    cur.execute(
        """
    SELECT COUNT(*) FROM reports
    WHERE reported LIKE ? OR reported_profile LIKE ?
    """,
        (q, q),
    )
    cnt = cur.fetchone()[0]
    conn.close()
    return cnt

# ---------- Parsing helpers ----------
PROFILE_URL_RE = re.compile(r"https?://www\.roblox\.com/users/(\d+)/profile", re.I)
JOBID_RE = re.compile(r"JobID[:\s]*([0-9a-fA-F\-]{8,})", re.I)


def extract_name_before(fulltext, pos):
    snippet = fulltext[max(0, pos - 120) : pos].strip()
    lines = [ln.strip() for ln in snippet.splitlines() if ln.strip()]
    if lines:
        return lines[-1]
    return ""


def parse_raw_report(text):
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    reporter = reporter_profile = reported = reported_profile = ""
    reason_lines = []
    jobid = ""
    mj = JOBID_RE.search(text)
    if mj:
        jobid = mj.group(1)
    profiles = list(PROFILE_URL_RE.finditer(text))
    if profiles:
        if len(profiles) >= 1:
            reporter_profile = profiles[0].group(0)
            reporter = extract_name_before(text, profiles[0].start())
        if len(profiles) >= 2:
            reported_profile = profiles[1].group(0)
            reported = extract_name_before(text, profiles[1].start())
    low = text.lower()
    if "reporter" in low:
        for i, l in enumerate(lines):
            if l.lower().startswith("reporter"):
                if i + 1 < len(lines) and not PROFILE_URL_RE.search(lines[i + 1]):
                    reporter = lines[i + 1]
                for j in range(i + 1, min(i + 6, len(lines))):
                    m = PROFILE_URL_RE.search(lines[j])
                    if m:
                        reporter_profile = m.group(0)
                        break
                break
    if "player being reported" in low or "reported" in low:
        for i, l in enumerate(lines):
            if (
                "player being reported" in l.lower()
                or l.lower().startswith("reported")
                or l.lower().startswith("player")
            ):
                if i + 1 < len(lines) and not PROFILE_URL_RE.search(lines[i + 1]):
                    reported = lines[i + 1]
                for j in range(i + 1, min(i + 6, len(lines))):
                    m = PROFILE_URL_RE.search(lines[j])
                    if m:
                        reported_profile = m.group(0)
                        break
                break
    if not reporter and len(lines) >= 1:
        for l in lines:
            if any(
                x in l.lower()
                for x in (
                    "new report",
                    "report type",
                    "reason",
                    "jobid",
                    "player",
                    "reporter",
                )
            ):
                continue
            reporter = l
            break
    skip_terms = (
        "reporter",
        "player being reported",
        "report type",
        "reason",
        "jobid",
        "new report",
        "player",
        "reported",
    )

    # Prefer capturing explicit Reason section lines until next known header
    reason = ""
    for i, l in enumerate(lines):
        if l.lower().startswith("reason"):
            for j in range(i + 1, len(lines)):
                stop_terms = (
                    "jobid",
                    "result",
                    "reporter",
                    "player being reported",
                    "reported",
                    "new report",
                    "report type",
                    "player",
                )
                lj = lines[j].lower()
                if any(lj.startswith(s) for s in stop_terms):
                    break
                if PROFILE_URL_RE.search(lines[j]):
                    continue
                reason_lines.append(lines[j])
            reason = "\n".join(reason_lines).strip()
            break

    # Fallback heuristic: exclude the name lines that immediately follow headers
    if not reason:
        reason_lines = []
        skip_next_name = False
        for l in lines:
            low = l.lower()
            if any(low.startswith(s) for s in skip_terms):
                skip_next_name = True
                continue
            if skip_next_name:
                # Skip the single line following a header (likely a username)
                skip_next_name = False
                continue
            if PROFILE_URL_RE.search(l):
                continue
            reason_lines.append(l)
        reason = "\n".join(reason_lines).strip()

    return {
        "reporter": reporter,
        "reporter_profile": reporter_profile,
        "reported": reported,
        "reported_profile": reported_profile,
        "reason": reason,
        "jobid": jobid,
    }


# ---------- UI class ----------
class ReportApp:
    def __init__(self, master):
        self.master = master
        master.title("Report System")
        master.geometry("760x880")
        master.minsize(720, 600)

        # load settings & init DBs
        self.cfg = load_settings()
        init_databases()

        # state
        self.current_punishment = None
        self.current_result = ""
        self.widget_registry = {
            "frames": [],
            "labels": [],
            "buttons": [],
            "entries": [],
            "text": [],
            "listboxes": [],
            "combos": [],
            "others": [],
        }
        self._orig_styles = {}

        # build UI
        self._build_ui()
        # capture original styles BEFORE any theming
        self.capture_default_styles()
        # apply theme recursively to ensure no stray areas
        self.apply_theme_recursive()
        # attach close/save
        self.master.protocol("WM_DELETE_WINDOW", self.quit_and_save)

    # ----- style capture -----
    def _record_widget_defaults(self, widget):
        if widget in self._orig_styles:
            return
        defaults = {}
        for opt in (
            "bg",
            "fg",
            "insertbackground",
            "selectbackground",
            "selectforeground",
            "activebackground",
            "activeforeground",
            "highlightbackground",
            "highlightcolor",
            "relief",
        ):
            try:
                defaults[opt] = widget.cget(opt)
            except Exception:
                pass
        try:
            # ttk supports style option
            style_val = widget.cget("style")
            if style_val is not None:
                defaults["style"] = style_val
        except Exception:
            pass
        self._orig_styles[widget] = defaults

    def capture_default_styles(self):
        def walk(w):
            self._record_widget_defaults(w)
            for c in w.winfo_children():
                walk(c)
        walk(self.master)

    def _register(self, widget, wtype):
        try:
            self.widget_registry[wtype].append(widget)
        except Exception:
            self.widget_registry["others"].append(widget)
        # record defaults at registration time
        self._record_widget_defaults(widget)

    def _build_ui(self):
        # Top frame
        top_frame = tk.Frame(self.master)
        top_frame.pack(fill=tk.X, padx=10, pady=6)
        self._register(top_frame, "frames")

        lbl_rank = tk.Label(top_frame, text="Rank:")
        lbl_rank.pack(side=tk.LEFT)
        self._register(lbl_rank, "labels")

        self.rank_var = tk.StringVar(value=self.cfg.get("rank"))
        self.rank_combo = ttk.Combobox(
            top_frame,
            values=self.cfg.get("ranks", DEFAULT_SETTINGS["ranks"]),
            textvariable=self.rank_var,
            state="readonly",
            width=26,
        )
        self.rank_combo.pack(side=tk.LEFT, padx=6)
        self._register(self.rank_combo, "combos")

        btn_settings = tk.Button(top_frame, text="Settings", command=self.open_settings)
        btn_settings.pack(side=tk.RIGHT)
        self._register(btn_settings, "buttons")

        # Punishment frame
        pun_frame = tk.LabelFrame(self.master, text="Select Punishment")
        pun_frame.pack(fill=tk.X, padx=10, pady=6)
        self._register(pun_frame, "frames")
        self.pun_inner = tk.Frame(pun_frame)
        self.pun_inner.pack(fill=tk.X, padx=6, pady=4)
        self._register(self.pun_inner, "frames")
        self._render_punishment_buttons()

        # Result buttons area
        result_outer = tk.Frame(self.master)
        result_outer.pack(fill=tk.X, padx=10, pady=4)
        self._register(result_outer, "frames")
        lbl_result = tk.Label(result_outer, text="Select Report Result:")
        lbl_result.pack(side=tk.LEFT)
        self._register(lbl_result, "labels")
        self.result_frame = tk.Frame(result_outer)
        self.result_frame.pack(side=tk.LEFT, padx=8)
        self._register(self.result_frame, "frames")
        self.result_buttons = {}
        self._render_result_buttons()

        # Paste area
        paste_label = tk.Label(self.master, text="Paste Report Info Here:")
        paste_label.pack(anchor=tk.W, padx=10)
        self._register(paste_label, "labels")

        self.paste_text = tk.Text(self.master, height=10, wrap=tk.WORD)
        self.paste_text.pack(fill=tk.BOTH, padx=10, pady=4)
        self._register(self.paste_text, "text")

        # Buttons row (Generate only; Send removed — auto-send optional)
        btn_frame = tk.Frame(self.master)
        btn_frame.pack(fill=tk.X, padx=10, pady=4)
        self._register(btn_frame, "frames")
        gen_btn = tk.Button(btn_frame, text="Generate Report", command=self.generate_report, width=16)
        gen_btn.pack(side=tk.LEFT, padx=4)
        self._register(gen_btn, "buttons")

        open_log_btn = tk.Button(btn_frame, text="Open Report Log", command=self.open_report_log)
        open_log_btn.pack(side=tk.RIGHT, padx=4)
        self._register(open_log_btn, "buttons")
        open_ban_log_btn = tk.Button(btn_frame, text="Open Ban Log", command=self.open_ban_log)
        open_ban_log_btn.pack(side=tk.RIGHT, padx=4)
        self._register(open_ban_log_btn, "buttons")

        # Spacer area
        spacer = tk.Frame(self.master, height=6)
        spacer.pack(fill=tk.X, padx=10, pady=2)
        self._register(spacer, "frames")

        # Output areas: Report and Ban
        rep_label = tk.Label(self.master, text="Report Log Output:")
        rep_label.pack(anchor=tk.W, padx=10, pady=(8, 0))
        self._register(rep_label, "labels")
        self.report_output = tk.Text(self.master, height=8, wrap=tk.WORD)
        self.report_output.pack(fill=tk.BOTH, padx=10, pady=4)
        self._register(self.report_output, "text")

        ban_label = tk.Label(self.master, text="Punishment Log Output:")
        ban_label.pack(anchor=tk.W, padx=10, pady=(8, 0))
        self._register(ban_label, "labels")
        self.ban_output = tk.Text(self.master, height=6, wrap=tk.WORD)
        self.ban_output.pack(fill=tk.BOTH, padx=10, pady=4)
        self._register(self.ban_output, "text")

        # Search bar + results
        search_frame = tk.Frame(self.master)
        search_frame.pack(fill=tk.X, padx=10, pady=6)
        self._register(search_frame, "frames")
        self.search_var = tk.StringVar()
        self.search_entry = tk.Entry(search_frame, textvariable=self.search_var)
        self.search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self._register(self.search_entry, "entries")
        search_btn = tk.Button(
            search_frame, text="Search", command=self.search_reports_small, width=12
        )
        search_btn.pack(side=tk.LEFT, padx=6)
        self._register(search_btn, "buttons")

        sr_label = tk.Label(self.master, text="Search Results:")
        sr_label.pack(anchor=tk.W, padx=10)
        self._register(sr_label, "labels")
        self.search_results = tk.Text(self.master, height=6, wrap=tk.WORD)
        self.search_results.pack(fill=tk.BOTH, padx=10, pady=4)
        self._register(self.search_results, "text")

    def _render_punishment_buttons(self):
        for w in self.pun_inner.winfo_children():
            w.destroy()
        self.pun_buttons = []
        for p in self.cfg.get("punishments", []):
            name = p.get("name")
            b = tk.Button(
                self.pun_inner, text=name, command=lambda nm=name: self.on_punishment_click(nm)
            )
            b.pack(side=tk.LEFT, padx=4, pady=2)
            self.pun_buttons.append(b)
            self._register(b, "buttons")
        # re-apply theme to new widgets
        self.capture_default_styles()
        self.apply_theme_recursive()

    def _render_result_buttons(self):
        for w in self.result_frame.winfo_children():
            w.destroy()
        self.result_buttons = {}
        for r in self.cfg.get("results", DEFAULT_SETTINGS["results"]):
            b = tk.Button(
                self.result_frame, text=r, width=10, command=lambda rr=r: self.set_result(rr)
            )
            b.pack(side=tk.LEFT, padx=4)
            self._register(b, "buttons")
            self.result_buttons[r] = b
        # maintain selection state
        if self.current_result not in self.result_buttons:
            self.current_result = ""
        else:
            self.set_result(self.current_result)
        # re-apply theme to new widgets
        self.capture_default_styles()
        self.apply_theme_recursive()

    def on_punishment_click(self, name):
        self.current_punishment = name
        reported_name = ""
        curr_rep = self.report_output.get("1.0", tk.END)
        m = re.search(r"^Reported:\s*(.+)$", curr_rep, re.MULTILINE)
        if m:
            reported_name = m.group(1).strip()
        rank_line = f"{self.rank_var.get()}: <@{self.cfg.get('moderator_id')}>"
        ban_template = f"""{rank_line}
User: {reported_name}
Reason: 
Punishment: {name}
Proof: 
"""
        self.ban_output.delete("1.0", tk.END)
        self.ban_output.insert(tk.END, ban_template)

    def set_result(self, result):
        self.current_result = result
        for r, btn in self.result_buttons.items():
            try:
                if r == result:
                    btn.configure(relief=tk.SUNKEN)
                else:
                    btn.configure(relief=tk.RAISED)
            except Exception:
                pass

    def generate_report(self):
        raw = self.paste_text.get("1.0", tk.END).strip()
        if not raw:
            messagebox.showinfo(
                "No Input", "Please paste the report text into the input area first."
            )
            return
        parsed = parse_raw_report(raw)
        rank_line = f"{self.rank_var.get()}: <@{self.cfg.get('moderator_id')}>"
        reporter = parsed.get("reporter") or ""
        reported = parsed.get("reported") or ""
        reason = parsed.get("reason") or ""
        jobid = parsed.get("jobid") or ""
        result = self.current_result or ""

        cnt = count_reports_for_player(reported or parsed.get("reported_profile") or "")
        if cnt > 0:
            prev = find_reports_for_player(reported)
            last_entries = prev[:3]
            msg = f"{reported} has been reported {cnt} time(s) before.\n\nLast entries:\n"
            for r in last_entries:
                msg += f"- {r[1]} | Reporter: {r[2]} | Reason: {r[4]}\n"
            messagebox.showwarning("Previously Reported", msg)

        report_formatted = f"""{rank_line}
Reporter: {reporter}
Reported: {reported}
Reason:
{reason}
Result: {result}
JobID: {jobid}
"""
        self.report_output.delete("1.0", tk.END)
        self.report_output.insert(tk.END, report_formatted)

        punishment = self.current_punishment or ""
        ban_formatted = f"""{rank_line}
User: {reported}
Reason: {punishment if punishment else ''}
Punishment: {punishment if punishment else ''}
Proof: 
"""
        self.ban_output.delete("1.0", tk.END)
        self.ban_output.insert(tk.END, ban_formatted)

        timestamp = datetime.utcnow().isoformat() + "Z"
        rep = {
            "timestamp": timestamp,
            "rank": self.rank_var.get(),
            "reporter": reporter,
            "reporter_profile": parsed.get("reporter_profile"),
            "reported": reported,
            "reported_profile": parsed.get("reported_profile"),
            "reason": reason,
            "result": result,
            "jobid": jobid,
            "raw": raw,
        }
        report_id = add_report_to_db(rep)

        ban = {
            "timestamp": timestamp,
            "rank": self.rank_var.get(),
            "user": reported,
            "reason": reason,
            "punishment": punishment or "",
            "proof": "",
            "report_id": report_id,
        }
        add_ban_to_db(ban)

        self.paste_text.delete("1.0", tk.END)

        webhook_url = self.cfg.get("webhook_url", "").strip()
        should_auto_send = bool(self.cfg.get("auto_send_webhook", True))
        if webhook_url and should_auto_send:
            self._auto_send_webhook(webhook_url, report_formatted, ban_formatted, timestamp)
        else:
            if not webhook_url:
                messagebox.showinfo(
                    "Saved",
                    "Report saved locally. (No webhook configured — set one in Settings)",
                )
            else:
                messagebox.showinfo(
                    "Saved",
                    "Report saved locally. (Auto-send is disabled in Settings)",
                )

    def _auto_send_webhook(self, url, report_text, ban_text, timestamp_iso):
        if not requests:
            messagebox.showwarning(
                "Webhook not sent",
                "requests library not installed. Install with:\n\npip install requests\n\nReport saved locally but not sent.",
            )
            return
        payload = {
            "username": self.rank_var.get(),
            "embeds": [
                {
                    "title": "Report Log",
                    "description": f"```{report_text}```",
                    "timestamp": timestamp_iso,
                },
                {
                    "title": "Punishment Log",
                    "description": f"```{ban_text}```",
                    "timestamp": timestamp_iso,
                },
            ],
        }
        try:
            r = requests.post(url, json=payload, timeout=10)
            if r.status_code in (200, 204):
                messagebox.showinfo(
                    "Sent", "Report & Punishment sent to webhook and saved locally."
                )
            else:
                messagebox.showwarning(
                    "Webhook error", f"HTTP {r.status_code}: {r.text}\nReport saved locally."
                )
        except Exception as e:
            messagebox.showwarning(
                "Send failed", f"Webhook send failed: {e}\nReport saved locally."
            )

    def open_report_log(self):
        w = tk.Toplevel(self.master)
        w.title("Report Log")
        w.geometry("900x600")
        txt = tk.Text(w)
        txt.pack(fill=tk.BOTH, expand=True)
        conn = sqlite3.connect(REPORT_DB)
        cur = conn.cursor()
        cur.execute(
            "SELECT id, timestamp, rank, reporter, reported, reason, result, jobid FROM reports ORDER BY id DESC LIMIT 1000"
        )
        rows = cur.fetchall()
        conn.close()
        display = []
        for r in rows:
            display.append(
                f"ID:{r[0]} | {r[1]} | {r[2]} | Reporter: {r[3]} | Reported: {r[4]} | Result: {r[6]} | JobID: {r[7]}\nReason: {r[5]}\n\n"
            )
        txt.insert(tk.END, "".join(display))

    def open_ban_log(self):
        w = tk.Toplevel(self.master)
        w.title("Ban Log Backup")
        w.geometry("900x600")
        txt = tk.Text(w)
        txt.pack(fill=tk.BOTH, expand=True)
        conn = sqlite3.connect(BAN_DB)
        cur = conn.cursor()
        cur.execute(
            "SELECT id, timestamp, rank, user, reason, punishment, proof, report_id FROM bans ORDER BY id DESC LIMIT 1000"
        )
        rows = cur.fetchall()
        conn.close()
        display = []
        for r in rows:
            display.append(
                f"ID:{r[0]} | {r[1]} | {r[2]} | User: {r[3]} | Punishment: {r[5]} | ReportID: {r[7]}\nReason: {r[4]}\nProof: {r[6]}\n\n"
            )
        txt.insert(tk.END, "".join(display))

    def search_reports_small(self):
        key = self.search_var.get().strip()
        if not key:
            messagebox.showinfo("Input", "Enter a player name or id to search.")
            return
        rows = find_reports_for_player(key)
        if not rows:
            self.search_results.delete("1.0", tk.END)
            self.search_results.insert(tk.END, "No previous reports found.")
            return
        out_lines = []
        for r in rows[:200]:
            out_lines.append(
                f"{r[1]} | Reporter: {r[2]} | Reported: {r[3]} | JobID: {r[5]}\nReason: {r[4]}\n\n"
            )
        self.search_results.delete("1.0", tk.END)
        self.search_results.insert(tk.END, "".join(out_lines))

    # ---------- Settings window ----------
    def open_settings(self):
        w = tk.Toplevel(self.master)
        w.title("Settings")
        w.geometry("620x820")
        frm = tk.Frame(w, padx=8, pady=8)
        frm.pack(fill=tk.BOTH, expand=True)

        # Rank controls
        lbl = tk.Label(frm, text="Select Rank:")
        lbl.pack(anchor=tk.W)
        rank_var = tk.StringVar(value=self.cfg.get("rank"))
        rank_cb = ttk.Combobox(
            frm,
            values=self.cfg.get("ranks", DEFAULT_SETTINGS["ranks"]),
            textvariable=rank_var,
            state="readonly",
        )
        rank_cb.pack(fill=tk.X, pady=4)
        tk.Button(
            frm, text="Update Rank", command=lambda: self._update_rank(rank_var.get())
        ).pack(pady=4)

        # Ranks management
        tk.Label(frm, text="Manage Ranks:").pack(anchor=tk.W, pady=(8, 0))
        self.ranks_listbox = tk.Listbox(frm, height=6)
        self.ranks_listbox.pack(fill=tk.X, pady=4)
        self._refresh_ranks_listbox()
        rb_frame = tk.Frame(frm)
        rb_frame.pack(fill=tk.X, pady=4)
        tk.Button(rb_frame, text="Add", command=self.add_rank).pack(side=tk.LEFT, padx=4)
        tk.Button(rb_frame, text="Edit", command=self.edit_rank).pack(side=tk.LEFT, padx=4)
        tk.Button(rb_frame, text="Delete", command=self.delete_rank).pack(
            side=tk.LEFT, padx=4
        )
        tk.Button(rb_frame, text="Up", command=lambda: self.move_rank(-1)).pack(
            side=tk.LEFT, padx=4
        )
        tk.Button(rb_frame, text="Down", command=lambda: self.move_rank(1)).pack(
            side=tk.LEFT, padx=4
        )

        # Webhook URL + auto-send
        tk.Label(frm, text="Webhook URL:").pack(anchor=tk.W, pady=4)
        wh_var = tk.StringVar(value=self.cfg.get("webhook_url", ""))
        wh_entry = tk.Entry(frm, textvariable=wh_var)
        wh_entry.pack(fill=tk.X)
        tk.Button(
            frm, text="Update Webhook", command=lambda: self._update_webhook(wh_var.get())
        ).pack(pady=4)

        auto_var = tk.BooleanVar(value=bool(self.cfg.get("auto_send_webhook", True)))
        auto_cb = tk.Checkbutton(frm, text="Auto-send to Webhook", variable=auto_var)
        auto_cb.pack(anchor=tk.W, pady=(0, 6))

        # Dark mode toggle (moved up for visibility)
        dark_var = tk.BooleanVar(value=self.cfg.get("dark_mode", False))
        dark_cb = tk.Checkbutton(frm, text="Dark Mode", variable=dark_var)
        dark_cb.pack(anchor=tk.W, pady=6)
        
        # Moderator ID
        tk.Label(frm, text="Moderator ID:").pack(anchor=tk.W, pady=4)
        mod_var = tk.StringVar(value=self.cfg.get("moderator_id", ""))
        tk.Entry(frm, textvariable=mod_var).pack(fill=tk.X)
        tk.Button(
            frm, text="Update Moderator ID", command=lambda: self._update_modid(mod_var.get())
        ).pack(pady=4)

        # Punishment management
        tk.Label(frm, text="Manage Punishments:").pack(anchor=tk.W, pady=(8, 0))
        self.pun_listbox = tk.Listbox(frm, height=6)
        self.pun_listbox.pack(fill=tk.X, pady=4)
        self._refresh_pun_listbox()
        pb_frame = tk.Frame(frm)
        pb_frame.pack(fill=tk.X, pady=4)
        tk.Button(pb_frame, text="Add", command=self.add_punishment).pack(
            side=tk.LEFT, padx=4
        )
        tk.Button(pb_frame, text="Edit", command=self.edit_punishment).pack(
            side=tk.LEFT, padx=4
        )
        tk.Button(pb_frame, text="Delete", command=self.delete_punishment).pack(
            side=tk.LEFT, padx=4
        )
        tk.Button(pb_frame, text="Up", command=lambda: self.move_punishment(-1)).pack(
            side=tk.LEFT, padx=4
        )
        tk.Button(pb_frame, text="Down", command=lambda: self.move_punishment(1)).pack(
            side=tk.LEFT, padx=4
        )

        # Results management
        tk.Label(frm, text="Manage Results Buttons:").pack(anchor=tk.W, pady=(8, 0))
        self.results_listbox = tk.Listbox(frm, height=6)
        self.results_listbox.pack(fill=tk.X, pady=4)
        self._refresh_results_listbox()
        res_frame = tk.Frame(frm)
        res_frame.pack(fill=tk.X, pady=4)
        tk.Button(res_frame, text="Add", command=self.add_result).pack(
            side=tk.LEFT, padx=4
        )
        tk.Button(res_frame, text="Edit", command=self.edit_result).pack(
            side=tk.LEFT, padx=4
        )
        tk.Button(res_frame, text="Delete", command=self.delete_result).pack(
            side=tk.LEFT, padx=4
        )
        tk.Button(res_frame, text="Up", command=lambda: self.move_result(-1)).pack(
            side=tk.LEFT, padx=4
        )
        tk.Button(res_frame, text="Down", command=lambda: self.move_result(1)).pack(
            side=tk.LEFT, padx=4
        )

        def do_save_and_close():
            self.cfg["dark_mode"] = bool(dark_var.get())
            self.cfg["auto_send_webhook"] = bool(auto_var.get())
            save_settings(self.cfg)
            self.apply_theme_recursive()
            w.destroy()

        tk.Button(frm, text="Save and Close", command=do_save_and_close).pack(pady=12)

    def _update_rank(self, val):
        self.cfg["rank"] = val
        self.rank_var.set(val)
        save_settings(self.cfg)
        messagebox.showinfo("Saved", "Rank updated.")

    def _update_webhook(self, val):
        self.cfg["webhook_url"] = val.strip()
        save_settings(self.cfg)
        messagebox.showinfo("Saved", "Webhook updated.")

    def _update_modid(self, val):
        self.cfg["moderator_id"] = val.strip()
        save_settings(self.cfg)
        messagebox.showinfo("Saved", "Moderator ID updated.")

    # ----- Ranks mgmt -----
    def _refresh_ranks_listbox(self):
        self.ranks_listbox.delete(0, tk.END)
        for r in self.cfg.get("ranks", []):
            self.ranks_listbox.insert(tk.END, r)

    def add_rank(self):
        name = simpledialog.askstring("Add Rank", "Rank name:", parent=self.master)
        if not name:
            return
        self.cfg.setdefault("ranks", []).append(name)
        save_settings(self.cfg)
        self._refresh_ranks_listbox()
        self.rank_combo.configure(values=self.cfg["ranks"])

    def edit_rank(self):
        sel = self.ranks_listbox.curselection()
        if not sel:
            messagebox.showinfo("Select", "Select a rank to edit.")
            return
        idx = sel[0]
        cur = self.cfg["ranks"][idx]
        name = simpledialog.askstring(
            "Edit Rank", "Rank name:", initialvalue=cur, parent=self.master
        )
        if not name:
            return
        self.cfg["ranks"][idx] = name
        save_settings(self.cfg)
        self._refresh_ranks_listbox()
        self.rank_combo.configure(values=self.cfg["ranks"])

    def delete_rank(self):
        sel = self.ranks_listbox.curselection()
        if not sel:
            messagebox.showinfo("Select", "Select a rank to delete.")
            return
        idx = sel[0]
        if messagebox.askyesno("Confirm", "Delete selected rank?"):
            del self.cfg["ranks"][idx]
            save_settings(self.cfg)
            self._refresh_ranks_listbox()
            self.rank_combo.configure(values=self.cfg.get("ranks", []))

    def move_rank(self, delta):
        sel = self.ranks_listbox.curselection()
        if not sel:
            return
        idx = sel[0]
        new = idx + delta
        if new < 0 or new >= len(self.cfg["ranks"]):
            return
        items = self.cfg["ranks"]
        items[idx], items[new] = items[new], items[idx]
        self.cfg["ranks"] = items
        save_settings(self.cfg)
        self._refresh_ranks_listbox()
        self.rank_combo.configure(values=self.cfg["ranks"]) 

    # ----- Punishments mgmt -----
    def _refresh_pun_listbox(self):
        self.pun_listbox.delete(0, tk.END)
        for p in self.cfg.get("punishments", []):
            self.pun_listbox.insert(tk.END, f"{p.get('name')} -> {p.get('action')}")

    def add_punishment(self):
        name = simpledialog.askstring(
            "Punishment name", "Name (button text):", parent=self.master
        )
        if not name:
            return
        action = simpledialog.askstring(
            "Punishment action", "Action (description):", parent=self.master
        )
        if action is None:
            action = ""
        self.cfg.setdefault("punishments", []).append({"name": name, "action": action})
        save_settings(self.cfg)
        self._refresh_pun_listbox()
        self._render_punishment_buttons()

    def edit_punishment(self):
        sel = self.pun_listbox.curselection()
        if not sel:
            messagebox.showinfo("Select", "Select an item to edit.")
            return
        idx = sel[0]
        p = self.cfg["punishments"][idx]
        name = simpledialog.askstring(
            "Punishment name",
            "Name (button text):",
            initialvalue=p.get("name"),
            parent=self.master,
        )
        if name is None:
            return
        action = simpledialog.askstring(
            "Punishment action",
            "Action (description):",
            initialvalue=p.get("action"),
            parent=self.master,
        )
        if action is None:
            action = ""
        self.cfg["punishments"][idx] = {"name": name, "action": action}
        save_settings(self.cfg)
        self._refresh_pun_listbox()
        self._render_punishment_buttons()

    def delete_punishment(self):
        sel = self.pun_listbox.curselection()
        if not sel:
            messagebox.showinfo("Select", "Select an item to delete.")
            return
        idx = sel[0]
        if messagebox.askyesno("Confirm", "Delete selected punishment?"):
            del self.cfg["punishments"][idx]
            save_settings(self.cfg)
            self._refresh_pun_listbox()
            self._render_punishment_buttons()

    def move_punishment(self, delta):
        sel = self.pun_listbox.curselection()
        if not sel:
            return
        idx = sel[0]
        new = idx + delta
        if new < 0 or new >= len(self.cfg["punishments"]):
            return
        items = self.cfg["punishments"]
        items[idx], items[new] = items[new], items[idx]
        self.cfg["punishments"] = items
        save_settings(self.cfg)
        self._refresh_pun_listbox()
        self._render_punishment_buttons()

    # ----- Results mgmt -----
    def _refresh_results_listbox(self):
        self.results_listbox.delete(0, tk.END)
        for r in self.cfg.get("results", []):
            self.results_listbox.insert(tk.END, r)

    def add_result(self):
        name = simpledialog.askstring("Add Result", "Result label:", parent=self.master)
        if not name:
            return
        self.cfg.setdefault("results", []).append(name)
        save_settings(self.cfg)
        self._refresh_results_listbox()
        self._render_result_buttons()

    def edit_result(self):
        sel = self.results_listbox.curselection()
        if not sel:
            messagebox.showinfo("Select", "Select a result to edit.")
            return
        idx = sel[0]
        cur = self.cfg["results"][idx]
        name = simpledialog.askstring(
            "Edit Result", "Result label:", initialvalue=cur, parent=self.master
        )
        if not name:
            return
        self.cfg["results"][idx] = name
        save_settings(self.cfg)
        self._refresh_results_listbox()
        self._render_result_buttons()

    def delete_result(self):
        sel = self.results_listbox.curselection()
        if not sel:
            messagebox.showinfo("Select", "Select a result to delete.")
            return
        idx = sel[0]
        if messagebox.askyesno("Confirm", "Delete selected result?"):
            del self.cfg["results"][idx]
            save_settings(self.cfg)
            self._refresh_results_listbox()
            self._render_result_buttons()

    def move_result(self, delta):
        sel = self.results_listbox.curselection()
        if not sel:
            return
        idx = sel[0]
        new = idx + delta
        if new < 0 or new >= len(self.cfg["results"]):
            return
        items = self.cfg["results"]
        items[idx], items[new] = items[new], items[idx]
        self.cfg["results"] = items
        save_settings(self.cfg)
        self._refresh_results_listbox()
        self._render_result_buttons()

    # ---------- Theme application (recursive) ----------
    def apply_theme_recursive(self):
        dark = self.cfg.get("dark_mode", False)
        if dark:
            bg = "#2b2b2b"
            fg = "#FFFFFF"
            entry_bg = "#222222"
            text_bg = "#1e1e1e"
            btn_bg = "#333333"
            listbox_bg = "#1f1f1f"
        else:
            bg = None
            fg = None
            entry_bg = None
            text_bg = None
            btn_bg = None
            listbox_bg = None

        try:
            if dark:
                self.master.configure(bg=bg)
            else:
                # restore root window background
                orig = self._orig_styles.get(self.master, {}).get("bg")
                if orig is not None:
                    self.master.configure(bg=orig)
        except Exception:
            pass

        def restore_defaults(c):
            defaults = self._orig_styles.get(c, {})
            to_apply = {}
            for key, val in defaults.items():
                if key == "style":
                    continue
                to_apply[key] = val
            if to_apply:
                try:
                    c.configure(**to_apply)
                except Exception:
                    pass
            if "style" in defaults:
                try:
                    c.configure(style=defaults["style"])
                except Exception:
                    pass

        def walk(w):
            children = w.winfo_children()
            for c in children:
                try:
                    if dark:
                        if isinstance(c, (tk.Frame, tk.LabelFrame)):
                            c.configure(bg=bg)
                        if isinstance(c, tk.Label):
                            c.configure(bg=bg, fg=fg)
                        if isinstance(c, tk.Button):
                            try:
                                c.configure(
                                    bg=btn_bg,
                                    fg=fg,
                                    activebackground=btn_bg,
                                    activeforeground=fg,
                                )
                            except Exception:
                                pass
                        if isinstance(c, tk.Entry):
                            try:
                                c.configure(bg=entry_bg, fg=fg, insertbackground=fg)
                            except Exception:
                                pass
                        if isinstance(c, tk.Text):
                            try:
                                c.configure(bg=text_bg, fg=fg, insertbackground=fg)
                            except Exception:
                                pass
                        if isinstance(c, tk.Listbox):
                            try:
                                c.configure(
                                    bg=listbox_bg,
                                    fg=fg,
                                    selectbackground=btn_bg or "#444444",
                                    selectforeground=fg,
                                )
                            except Exception:
                                pass
                        if isinstance(c, ttk.Combobox):
                            style = ttk.Style()
                            try:
                                style_name = "Dark.TCombobox"
                                style.configure(
                                    style_name,
                                    fieldbackground=entry_bg,
                                    background=entry_bg,
                                    foreground=fg,
                                )
                                c.configure(style=style_name)
                            except Exception:
                                pass
                        if isinstance(c, tk.Checkbutton):
                            try:
                                c.configure(bg=bg, fg=fg, selectcolor=bg, activeforeground=fg)
                            except Exception:
                                pass
                    else:
                        restore_defaults(c)
                    walk(c)
                except Exception:
                    try:
                        walk(c)
                    except Exception:
                        pass
        walk(self.master)

    # ---------- Save on exit ----------
    def quit_and_save(self):
        save_settings(self.cfg)
        self.master.quit()

    # ---------- Shutdown wrapper ----------
    def quit_and_exit(self):
        self.quit_and_save()
        self.master.destroy()


# ---------- Main ----------
def main():
    init_databases()
    root = tk.Tk()
    app = ReportApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()