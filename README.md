# SOC Log Analyzer — SSH Attack Detection Tool and Web Dashboard

A Python security project that analyzes Linux SSH authentication logs from the command line or in a browser. It detects SSH brute force, password spraying, and successful logins after repeated failures, and writes JSON, CSV, HTML, and candidate-blocklist reports with severity, evidence, and MITRE ATT&CK mapping.

> **Authorization:** Use this tool only on logs you own or are authorized to analyze. Findings are indicators for analyst review, not proof of compromise.

## Architecture

```
 auth.log            Parser                    Detection                       Reports
 (SSH log)  --->  regex -> Event objects ---> group by source IP:  --->  console / JSON / CSV
                  (time, kind, user,           - brute force                HTML / blocklist
                   ip, method)                 - password spraying
                                               - multi-user brute force
                                               - success after failures
                                               - burst rate (evidence)
                                                      |
                                   CLI (log_analyzer.py)  and  Flask dashboard (app.py)
```

1. **Parse** — regular expressions turn SSH `Failed` / `Accepted` lines into `Event` objects. Classic syslog timestamps and ISO timestamps are supported; everything else is ignored.
2. **Detect** — events are grouped by source IP. The tool counts failures, distinct usernames, and the peak attempts inside a sliding window, then applies the rules.
3. **Report** — printed on screen and saved as `report.json`, `findings.csv`, `report.html`, `blocklist.txt`. The CLI exits with `1` when a High finding exists, so it works in scripts.

## Detection rules

| Detection | Default logic | Severity | MITRE ATT&CK |
|---|---|---|---|
| SSH brute force | 10+ failed logins from one IP against 1-2 usernames | High | T1110.001 Password Guessing |
| Password spraying | 5+ distinct usernames from one IP, average 3 or fewer tries per user | Medium | T1110.003 Password Spraying |
| Success after failures | 5+ earlier failures, then a success, for the same IP and username | High | T1110 -> T1078 |
| Multi-user brute force *(added beyond the original spec)* | 10+ failures from one IP that fit neither rule above (for example 3-4 usernames, or 5+ usernames with many tries each) | Medium | T1110 Brute Force |
| Burst rate | Peak failed attempts in a 60-second sliding window, shown as evidence | — | — |

**Why the extra rule?** With only the first two rules, 60 failures across 3 usernames, or 120 failures across 6 usernames, matched nothing. That is still a credential attack, so it is reported as Medium.

**Why only failures *before* the success count:** failures after a legitimate login do not show how the password was obtained. Order is decided by event position after a stable time sort, so several events in the same second stay deterministic.

**Deliberate non-detections:** a user who mistypes twice and then logs in, and a scanner with only 3 failures, are not flagged.

## Project structure

```text
soc-log-analyzer/
├── log_analyzer.py        parser, detections, reports, CLI
├── generate_sample_log.py fictional 236-line auth.log generator
├── app.py                 Flask web API and dashboard backend
├── templates/index.html   dashboard page
├── static/css, static/js  dashboard styling and logic
├── test_log_analyzer.py   17 detection/parser tests
├── test_web_app.py        13 web/API tests
├── requirements.txt       Flask (+ gunicorn on Linux/macOS)
├── render.yaml            optional Render deployment config
├── sample/                sample auth.log and sample/output reports
├── docs/                  put your screenshots here
├── README.md
└── PROJECT_GUIDE.md       resume entry and interview preparation
```

## Quick start

The command-line analyzer needs **only the Python standard library** (Python 3.8+). Flask is needed only for the web dashboard.

**Linux / macOS**

```bash
python3 generate_sample_log.py sample/auth.log
python3 log_analyzer.py sample/auth.log --year 2026 --output-dir sample/output
python3 -m unittest -v
```

**Windows (Command Prompt)**

```cmd
python generate_sample_log.py sample/auth.log
python log_analyzer.py sample/auth.log --year 2026 --output-dir sample/output
python -m unittest -v
```

### Web dashboard

```bash
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
python -m pip install -r requirements.txt
python app.py                      # open http://127.0.0.1:5000
```

The dashboard loads a clearly labelled fictional sample by default; upload your own `.log` or `.txt` file (max 5 MB) to analyze it.

## CLI options

| Option | Meaning | Default |
|---|---|---|
| `--output-dir out` | Write report.json, findings.csv, report.html, blocklist.txt | console only |
| `--year 2026` | Year of the **first line** (syslog lines have no year) | current year |
| `--bf-threshold 10` | Failed logins needed to flag brute force | 10 |
| `--spray-users 5` | Different usernames needed to flag spraying | 5 |
| `--success-after 5` | Failures before a success to flag a likely compromise | 5 |
| `--window 60` | Sliding window (seconds) for the burst rate | 60 |
| `--defang` | Show IPs as `1[.]2[.]3[.]4` (`blocklist.txt` stays raw) | off |

Exit codes: `1` = a High finding exists, `0` = no High finding, `2` = invalid input or configuration. A nonzero exit for a High finding is intentional (automation), not a crash.

**Year handling:** pass the year of the first log line. If the log crosses New Year (Dec -> Jan), the year advances automatically. ISO timestamps carry their own year.

## Sample output

```
 Failed logins     : 201
 Successful logins : 14
 Unique source IPs : 4
 FINDINGS: 3
 [1] HIGH   SSH brute force
     IP     : 192.168.56.10      User : ubuntu
     Detail : 180 failed logins against 1 user(s); peak 81 attempts in 60s
     MITRE  : T1110.001 Password Guessing
 [2] HIGH   Success after failures
     IP     : 192.168.56.10      User : ubuntu
     Detail : 180 failed logins, then successful password login
     MITRE  : T1110 Brute Force -> T1078 Valid Accounts
 [3] MEDIUM Password spraying
     IP     : 203.0.113.77       User : 8 different users
     Detail : 16 failed logins across 8 users (avg 2.0 per user)
     MITRE  : T1110.003 Password Spraying
```

### Screenshots

Add your own after running the project (save them in `docs/`):

| Console output | Dashboard | HTML report |
|---|---|---|
| `docs/console.png` | `docs/dashboard.png` | `docs/report.png` |

## Lab test: Kali attacking Ubuntu (your own VMs only)

Use two virtual machines on a host-only network that you own, for example Kali `192.168.56.10` and Ubuntu `192.168.56.30`.

1. **Victim (Ubuntu):** install SSH and make sure logs reach `/var/log/auth.log`.
   ```bash
   sudo apt update && sudo apt install -y openssh-server rsyslog
   sudo systemctl enable --now ssh rsyslog
   ```
   Note the time when the attack starts and ends.
2. **Attacker (Kali), brute force one user:**
   ```bash
   hydra -l ubuntu -P /usr/share/wordlists/rockyou.txt -t 4 ssh://192.168.56.30
   ```
3. **Attacker (Kali), password spraying (one password, many users):**
   ```bash
   hydra -L users.txt -p 'Summer2026!' -t 2 ssh://192.168.56.30
   ```
4. **Optional:** log in normally once with the correct password to create a "success after failures" case.
5. **Collect the log:** `scp ubuntu@192.168.56.30:/var/log/auth.log .` (if the file does not exist, try `sudo journalctl -u ssh --no-pager > auth.log`).
6. **Analyze:** `python3 log_analyzer.py auth.log --year 2026 --output-dir out`
7. **Compare** the findings with your attack start/end times, tune thresholds, and write down any false positives or missed detections in your repository.

## Web API

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/` | Dashboard |
| GET | `/health` | Health check |
| GET | `/api/sample?year=2026` | Analyze the bundled fictional sample |
| POST | `/api/analyze` | Analyze an uploaded `.log`/`.txt` (`multipart/form-data`, field `file`, optional `year`) |
| GET | `/api/reports/<id>/json` · `/csv` · `/blocklist` | Download a report |
| GET | `/reports/<id>` | View the HTML report |

Invalid input returns JSON errors: `400` bad year/empty/binary file, `413` too large, `415` unsupported type, `404` unknown or expired report.

## Testing

```bash
python -m unittest -v
```

30 tests: 17 for the parser and detections (including the two detection-gap cases, year rollover, same-second ordering, and threshold validation) and 13 for the web API (upload validation, report downloads, security headers, HTML escaping of hostile usernames, report expiry and cap). Web tests are skipped if Flask is not installed.

## Security and operations

- Uploaded logs are never executed. They are written to a temporary file and deleted after parsing.
- Uploads are limited to 5 MB (`MAX_UPLOAD_BYTES`), text only, `.log` or `.txt`.
- The dashboard uses `textContent` only (no `innerHTML`); HTML reports escape every value.
- Responses carry `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, and a Content-Security-Policy.
- Reports live in a temporary server folder, are deleted after `REPORT_TTL_SECONDS` (default 3600), and only the newest `MAX_REPORTS` (default 100) are kept.
- Report lookup is held in process memory, so run **one** gunicorn worker (`render.yaml` already does: `--workers 1 --threads 4`).
- Chart.js is loaded from a CDN (no integrity hash). For a stricter deployment, download it into `static/js/` and change the `<script>` tag; the CSP then no longer needs `cdn.jsdelivr.net`. If the CDN is blocked, the rest of the app still works.
- This is a portfolio/demo tool. Before exposing it publicly, add authentication and rate limiting, and never upload confidential logs to a public demo.
- Flask's built-in server (`python app.py`) is for local development only.

## Deployment (Render, optional)

1. Push the project to GitHub without private logs or secrets.
2. Create a Render Web Service from the repository; `render.yaml` supplies the build and start commands.
3. Open `/health` and the dashboard URL to verify.

Hosted instances may restart and clear temporary reports.

## Limitations

- Only SSH `Failed`/`Accepted` messages are parsed; other log formats and services are ignored.
- Fixed thresholds can give false positives, and low-and-slow attacks that stay under them are missed.
- Detection is per source IP, so an attack spread across many IPs (distributed) is not correlated.
- Syslog timestamps have no year, so `--year` must match the first line. A log spanning more than a year is not supported, and `Feb 29` lines are skipped when the chosen year is not a leap year.
- No GeoIP or IP reputation lookups; the web dashboard uses default thresholds only.

## Future work

Blocklist / iptables command generator (print only, never auto-run), GeoIP country column, AbuseIPDB reputation, Windows Security events 4624/4625, alerts via Slack/Telegram/email, live `tail -f` monitoring, detection of sudo abuse, `useradd`, and root login attempts, and an IP allowlist.

## Legal

Use this tool only on logs you own or are authorized to analyze.
