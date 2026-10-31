#!/usr/bin/env python3
"""
SOC Log Analyzer
Automated detection of SSH brute force, password spraying and likely account
compromise from Linux SSH authentication logs (auth.log).

Pipeline:  auth.log -> Parser (regex -> Event) -> Detection -> Reports

Python standard library only. Use only on logs you own or are authorized
to analyze.
"""
import argparse
import csv
import html
import json
import os
import re
import sys
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime

# ---------------------------------------------------------------------------
# 1. PARSER
# ---------------------------------------------------------------------------

FAILED_RE = re.compile(
    r"Failed (?P<method>password|publickey) for (?P<invalid>invalid user )?"
    r"(?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+) port \d+"
)
ACCEPTED_RE = re.compile(
    r"Accepted (?P<method>password|publickey) for "
    r"(?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+) port \d+"
)
# Classic syslog timestamp: "Oct 27 03:14:22" (no year)
SYSLOG_TS_RE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})"
)
# ISO timestamp: "2026-10-27T03:14:22" (or with a space instead of T)
ISO_TS_RE = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2})[T ](?P<time>\d{2}:\d{2}:\d{2})"
)


@dataclass
class Event:
    """One SSH login event (either a failure or a success)."""
    ts: datetime
    kind: str      # "failed" or "accepted"
    user: str
    ip: str
    method: str    # "password" or "publickey"


def parse_timestamp(line, year):
    """Return a datetime from the start of a log line, or None."""
    try:
        m = ISO_TS_RE.match(line)
        if m:
            return datetime.strptime(
                m.group("date") + " " + m.group("time"), "%Y-%m-%d %H:%M:%S")
        m = SYSLOG_TS_RE.match(line)
        if m:
            text = "%d %s %s %s" % (year, m.group("mon"), m.group("day"),
                                    m.group("time"))
            return datetime.strptime(text, "%Y %b %d %H:%M:%S")
    except ValueError:
        return None
    return None


def parse_line(line, year):
    """Turn one log line into an Event. Non-SSH-login lines return None."""
    ts = parse_timestamp(line, year)
    if ts is None:
        return None
    m = FAILED_RE.search(line)
    if m:
        return Event(ts, "failed", m.group("user"), m.group("ip"),
                     m.group("method"))
    m = ACCEPTED_RE.search(line)
    if m:
        return Event(ts, "accepted", m.group("user"), m.group("ip"),
                     m.group("method"))
    return None


def parse_file(path, year):
    """Read a log file and return all events sorted by time.

    Syslog timestamps have no year. `year` is the year of the FIRST line.
    If the clock jumps back by more than ~6 months (Dec -> Jan), the year is
    advanced by one so events stay in the correct order. ISO timestamps carry
    their own year and are never adjusted.
    """
    events = []
    cur_year, last_ts = year, None
    with open(path, "r", errors="replace") as fh:
        for raw in fh:
            line = raw.rstrip("\n")
            if not ISO_TS_RE.match(line):
                ts = parse_timestamp(line, cur_year)
                if ts is not None:
                    if last_ts is not None and (last_ts - ts).days > 180:
                        cur_year += 1                      # Dec -> Jan rollover
                        ts = parse_timestamp(line, cur_year)
                    last_ts = ts
            ev = parse_line(line, cur_year)
            if ev is not None:
                events.append(ev)
    events.sort(key=lambda e: e.ts)
    return events


# ---------------------------------------------------------------------------
# 2. DETECTIONS
# ---------------------------------------------------------------------------

DEFAULT_CFG = {
    "bf_threshold": 10,   # failures needed for brute force
    "bf_max_users": 2,    # brute force = few usernames
    "spray_users": 5,     # distinct usernames needed for spraying
    "spray_max_avg": 3,   # spraying = few tries per user on average
    "success_after": 5,   # failures before a success => likely compromise
    "window": 60,         # sliding window in seconds
}

SEVERITY_ORDER = {"High": 0, "Medium": 1, "Low": 2}


def max_in_window(timestamps, window_seconds):
    """Most events that happened inside any sliding window (timestamps sorted)."""
    dq, best = deque(), 0
    for t in timestamps:
        dq.append(t)
        while (t - dq[0]).total_seconds() > window_seconds:
            dq.popleft()
        best = max(best, len(dq))
    return best


def fmt_time(dt):
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def analyze(events, cfg=None):
    """Apply detection rules. Returns (findings, stats).

    Event ordering is stable: timestamps are sorted, and original input order is
    retained for equal timestamps. This makes success-after-failure correlation
    deterministic even when multiple events share the same second.
    """
    cfg = dict(DEFAULT_CFG, **(cfg or {}))
    for key in ("bf_threshold", "bf_max_users", "spray_users", "success_after", "window"):
        value = cfg.get(key)
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            raise ValueError("Configuration value %s must be a positive integer" % key)
    if not isinstance(cfg.get("spray_max_avg"), (int, float)) or cfg["spray_max_avg"] <= 0:
        raise ValueError("Configuration value spray_max_avg must be positive")

    indexed_events = sorted(enumerate(events), key=lambda pair: (pair[1].ts, pair[0]))
    failed_by_ip = defaultdict(list)
    accepted = []
    for position, (original_index, e) in enumerate(indexed_events):
        record = (position, e)
        if e.kind == "failed":
            failed_by_ip[e.ip].append(record)
        elif e.kind == "accepted":
            accepted.append(record)

    findings = []

    # --- Brute force and password spraying (per source IP) ---
    for ip, fail_records in failed_by_ip.items():
        fails = [record[1] for record in fail_records]
        per_user = defaultdict(int)
        for f in fails:
            per_user[f.user] += 1
        n_fail = len(fails)
        n_users = len(per_user)
        peak = max_in_window([f.ts for f in fails], cfg["window"])
        first, last = fails[0].ts, fails[-1].ts

        if n_fail >= cfg["bf_threshold"] and n_users <= cfg["bf_max_users"]:
            findings.append({
                "severity": "High",
                "type": "SSH brute force",
                "ip": ip,
                "user": ", ".join(sorted(per_user)),
                "detail": "%d failed logins against %d user(s); "
                          "peak %d attempts in %ds"
                          % (n_fail, n_users, peak, cfg["window"]),
                "mitre": "T1110.001 Password Guessing",
                "count": n_fail,
                "first_seen": fmt_time(first),
                "last_seen": fmt_time(last),
            })
        elif (n_users >= cfg["spray_users"]
              and n_fail / n_users <= cfg["spray_max_avg"]):
            findings.append({
                "severity": "Medium",
                "type": "Password spraying",
                "ip": ip,
                "user": "%d different users" % n_users,
                "detail": "%d failed logins across %d users (avg %.1f per user)"
                          % (n_fail, n_users, n_fail / n_users),
                "mitre": "T1110.003 Password Spraying",
                "count": n_fail,
                "first_seen": fmt_time(first),
                "last_seen": fmt_time(last),
            })
        elif n_fail >= cfg["bf_threshold"]:
            # Gap-filler (not in the original spec): many failures from one IP
            # that fit neither rule, e.g. 3-4 usernames, or 5+ usernames with
            # more than `spray_max_avg` tries each. Still a credential attack.
            findings.append({
                "severity": "Medium",
                "type": "Multi-user brute force",
                "ip": ip,
                "user": "%d different users" % n_users,
                "detail": "%d failed logins across %d users (avg %.1f per user); "
                          "peak %d attempts in %ds"
                          % (n_fail, n_users, n_fail / n_users, peak,
                             cfg["window"]),
                "mitre": "T1110 Brute Force",
                "count": n_fail,
                "first_seen": fmt_time(first),
                "last_seen": fmt_time(last),
            })

    # --- Success after failures (correlation) ---
    reported = set()
    for success_position, e in accepted:
        key = (e.ip, e.user)
        if key in reported:
            continue
        # Earlier in stable event order, same IP and username only.
        before = [f for position, f in failed_by_ip.get(e.ip, [])
                  if f.user == e.user and position < success_position]
        if len(before) >= cfg["success_after"]:
            reported.add(key)
            findings.append({
                "severity": "High",
                "type": "Success after failures",
                "ip": e.ip,
                "user": e.user,
                "detail": "%d failed logins, then successful %s login"
                          % (len(before), e.method),
                "mitre": "T1110 Brute Force -> T1078 Valid Accounts",
                "count": len(before),
                "first_seen": fmt_time(before[0].ts),
                "last_seen": fmt_time(e.ts),
            })

    # High first, then Medium (sort is stable, so detection order is kept)
    findings.sort(key=lambda f: SEVERITY_ORDER[f["severity"]])

    stats = {
        "failed_logins": sum(len(v) for v in failed_by_ip.values()),
        "successful_logins": len(accepted),
        "unique_source_ips": len({e.ip for e in events}),
        "findings": len(findings),
    }
    return findings, stats


# ---------------------------------------------------------------------------
# 3. REPORTS
# ---------------------------------------------------------------------------

def defang_ip(ip):
    return ip.replace(".", "[.]")


def prepare(findings, defang):
    """Return a copy of findings; IPs are defanged when requested."""
    out = []
    for f in findings:
        g = dict(f)
        if defang:
            g["ip"] = defang_ip(g["ip"])
        out.append(g)
    return out


def print_console(findings, stats):
    print("=" * 66)
    print(" SOC LOG ANALYZER - SSH authentication log report")
    print("=" * 66)
    print(" Failed logins     : %d" % stats["failed_logins"])
    print(" Successful logins : %d" % stats["successful_logins"])
    print(" Unique source IPs : %d" % stats["unique_source_ips"])
    print(" FINDINGS: %d" % stats["findings"])
    print("-" * 66)
    for i, f in enumerate(findings, 1):
        print(" [%d] %-6s %s" % (i, f["severity"].upper(), f["type"]))
        print("     IP     : %-18s User : %s" % (f["ip"], f["user"]))
        print("     Detail : %s" % f["detail"])
        print("     MITRE  : %s" % f["mitre"])
    if not findings:
        print(" No suspicious activity detected with the current thresholds.")


def write_json(path, findings, stats):
    with open(path, "w") as fh:
        json.dump({"summary": stats, "findings": findings}, fh, indent=2)


CSV_FIELDS = ["severity", "type", "ip", "user", "detail", "mitre",
              "count", "first_seen", "last_seen"]


def write_csv(path, findings):
    with open(path, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=CSV_FIELDS)
        w.writeheader()
        for f in findings:
            w.writerow({k: f.get(k, "") for k in CSV_FIELDS})


def write_html(path, findings, stats):
    esc = html.escape
    colors = {"High": "#c62828", "Medium": "#ef6c00", "Low": "#2e7d32"}
    rows = []
    for f in findings:
        color = colors.get(f["severity"], "#555")
        rows.append(
            "<tr><td><span class='sev' style='background:%s'>%s</span></td>"
            "<td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td>"
            "<td>%s</td></tr>" % (
                color, esc(str(f["severity"])), esc(str(f["type"])),
                esc(str(f["ip"])), esc(str(f["user"])), esc(str(f["detail"])),
                esc(str(f["mitre"])),
                esc("%s to %s" % (f["first_seen"], f["last_seen"]))))
    body = "\n".join(rows) or "<tr><td colspan='7'>No findings.</td></tr>"
    doc = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>SOC Log Analyzer Report</title>
<style>
 body{font-family:Segoe UI,Arial,sans-serif;margin:30px;background:#f5f7fa;color:#222}
 h1{margin-bottom:4px}
 .cards{display:flex;gap:14px;margin:18px 0}
 .card{background:#fff;border-radius:8px;padding:14px 22px;box-shadow:0 1px 3px #0002}
 .card b{display:block;font-size:26px}
 table{border-collapse:collapse;width:100%%;background:#fff;box-shadow:0 1px 3px #0002}
 th,td{padding:10px 12px;border-bottom:1px solid #e3e7ec;text-align:left;font-size:14px}
 th{background:#263238;color:#fff}
 .sev{color:#fff;padding:3px 10px;border-radius:12px;font-size:12px;font-weight:bold}
 footer{margin-top:20px;font-size:12px;color:#666}
</style></head><body>
<h1>SOC Log Analyzer Report</h1>
<div>SSH brute force, password spraying and account compromise detection</div>
<div class="cards">
 <div class="card"><b>%d</b>Failed logins</div>
 <div class="card"><b>%d</b>Successful logins</div>
 <div class="card"><b>%d</b>Unique source IPs</div>
 <div class="card"><b>%d</b>Findings</div>
</div>
<table>
<tr><th>Severity</th><th>Type</th><th>IP</th><th>User</th><th>Detail</th><th>MITRE ATT&amp;CK</th><th>Time range</th></tr>
%s
</table>
<footer>Use this tool only on logs you own or are authorized to analyze.</footer>
</body></html>
""" % (stats["failed_logins"], stats["successful_logins"],
       stats["unique_source_ips"], stats["findings"], body)
    with open(path, "w") as fh:
        fh.write(doc)


def write_blocklist(path, findings):
    """Unique attacker IPs from the findings, one per line (never defanged)."""
    seen, ips = set(), []
    for f in findings:
        if f["ip"] not in seen:
            seen.add(f["ip"])
            ips.append(f["ip"])
    with open(path, "w") as fh:
        for ip in ips:
            fh.write(ip + "\n")


# ---------------------------------------------------------------------------
# 4. CLI
# ---------------------------------------------------------------------------

def build_parser():
    p = argparse.ArgumentParser(
        description="Detect SSH brute force, password spraying and likely "
                    "account compromise in a Linux auth.log. "
                    "Use only on logs you are authorized to analyze.")
    p.add_argument("logfile", help="path to the SSH auth.log file")
    p.add_argument("--output-dir", metavar="DIR",
                   help="write report.json, findings.csv, report.html, "
                        "blocklist.txt here")
    p.add_argument("--year", type=int, default=datetime.now().year,
                   help="year for syslog timestamps (default: current year)")
    p.add_argument("--bf-threshold", type=int, default=10,
                   help="failed logins needed to flag brute force (default 10)")
    p.add_argument("--spray-users", type=int, default=5,
                   help="different usernames needed to flag spraying (default 5)")
    p.add_argument("--success-after", type=int, default=5,
                   help="failures before a success to flag a likely "
                        "compromise (default 5)")
    p.add_argument("--window", type=int, default=60,
                   help="sliding window in seconds for burst rate (default 60)")
    p.add_argument("--defang", action="store_true",
                   help="show IPs as 1[.]2[.]3[.]4 in the output")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    if not os.path.isfile(args.logfile):
        print("Error: file not found: %s" % args.logfile, file=sys.stderr)
        return 2

    cfg = {
        "bf_threshold": args.bf_threshold,
        "spray_users": args.spray_users,
        "success_after": args.success_after,
        "window": args.window,
    }
    if any(value <= 0 for value in cfg.values()):
        print("Error: detection thresholds and window must be positive integers.", file=sys.stderr)
        return 2
    events = parse_file(args.logfile, args.year)
    findings, stats = analyze(events, cfg)
    shown = prepare(findings, args.defang)

    print_console(shown, stats)

    if args.output_dir:
        os.makedirs(args.output_dir, exist_ok=True)
        write_json(os.path.join(args.output_dir, "report.json"), shown, stats)
        write_csv(os.path.join(args.output_dir, "findings.csv"), shown)
        write_html(os.path.join(args.output_dir, "report.html"), shown, stats)
        write_blocklist(os.path.join(args.output_dir, "blocklist.txt"), findings)
        print("\nReports saved in: %s" % args.output_dir)

    # Exit code 1 when a High finding exists (useful for scripts/automation)
    return 1 if any(f["severity"] == "High" for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
