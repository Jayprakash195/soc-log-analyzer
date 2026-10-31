#!/usr/bin/env python3
"""
Generate a fictional, reproducible SSH auth.log for practice.

Usage: python3 generate_sample_log.py sample/auth.log

Contents (236 lines):
  - Hydra-style brute force: 180 failures for "ubuntu" from 192.168.56.10
    (peak 81 attempts in 60s), then one successful password login
  - Password spraying: 203.0.113.77, 8 users x 2 failures = 16
  - Scanner: 198.51.100.23, only 3 failures (below threshold)
  - Legit user "devops" from 10.0.0.25: 2 mistypes then login, plus 12
    more normal logins (13 successes)
  - 21 noise lines (sudo, cron, session, disconnect) the parser must ignore
Totals when analyzed: 201 failed, 14 successful, 4 unique IPs.
"""
import os
import random
import sys
from datetime import datetime, timedelta

HOST = "ubuntu-srv"
DAY = datetime(2026, 10, 27)
TOTAL_LINES = 236


def at(h, m, s=0):
    return DAY + timedelta(hours=h, minutes=m, seconds=s)


def main(out_path):
    rng = random.Random(42)   # seeded => same file every time
    items = []                # (datetime, text)

    def sshd(ts, msg):
        items.append((ts, "%s %s sshd[%d]: %s" % (
            ts.strftime("%b %d %H:%M:%S"), HOST, rng.randint(1000, 30000), msg)))

    def failed(ts, user, ip, invalid=False):
        who = ("invalid user " + user) if invalid else user
        sshd(ts, "Failed password for %s from %s port %d ssh2"
             % (who, ip, rng.randint(1024, 65535)))

    def accepted(ts, user, ip):
        sshd(ts, "Accepted password for %s from %s port %d ssh2"
             % (user, ip, rng.randint(1024, 65535)))

    # 1) Hydra brute force: 3 bursts with pauses (>60s) between them.
    #    Burst of 81 attempts in 61 s (20 seconds with 2 tries, 41 with 1),
    #    twice, then a final burst of 18 => 81 + 81 + 18 = 180. Peak = 81.
    attacker = "192.168.56.10"
    t = at(3, 14, 22)
    for burst_size in (81, 81, 18):
        if burst_size == 81:
            for sec in range(61):
                for _ in range(2 if (sec % 3 == 0 and sec < 60) else 1):
                    failed(t + timedelta(seconds=sec), "ubuntu", attacker)
            t += timedelta(seconds=61 + 120)
        else:
            for sec in range(18):
                failed(t + timedelta(seconds=sec), "ubuntu", attacker)
            t += timedelta(seconds=18)
    success_ts = t + timedelta(seconds=30)
    accepted(success_ts, "ubuntu", attacker)

    # 2) Password spraying: 8 users, 2 failures each, slow
    spray_ip = "203.0.113.77"
    users = ["admin", "root", "test", "oracle", "postgres", "user",
             "guest", "ftpuser"]
    ts = at(2, 10, 5)
    for u in users:
        for _ in range(2):
            failed(ts, u, spray_ip, invalid=(u != "root"))
            ts += timedelta(seconds=rng.randint(20, 45))

    # 3) Scanner with only 3 failures (below threshold)
    scanner = "198.51.100.23"
    for i, u in enumerate(["admin", "pi", "support"]):
        failed(at(5, 30, 10 + i * 4), u, scanner, invalid=True)

    # 4) Legit user devops: 2 mistypes, then login; 12 more normal logins
    devops_ip = "10.0.0.25"
    failed(at(7, 59, 12), "devops", devops_ip)
    failed(at(7, 59, 31), "devops", devops_ip)
    accepted(at(8, 0, 4), "devops", devops_ip)
    for i in range(12):
        accepted(at(9 + i, rng.randint(0, 59), rng.randint(0, 59)),
                 "devops", devops_ip)

    # 5) Noise lines the parser must ignore
    n_events = len(items)
    templates = [
        lambda ts: "%s %s sudo:   devops : TTY=pts/0 ; PWD=/home/devops ; USER=root ; COMMAND=/usr/bin/apt update",
        lambda ts: "%s %s CRON[%d]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)",
        lambda ts: "%s %s CRON[%d]: pam_unix(cron:session): session closed for user root",
        lambda ts: "%s %s sshd[%d]: pam_unix(sshd:session): session opened for user devops(uid=1001) by (uid=0)",
        lambda ts: "%s %s sshd[%d]: pam_unix(sshd:session): session closed for user devops",
        lambda ts: "%s %s systemd-logind[612]: New session %d of user devops.",
        lambda ts: "%s %s sshd[%d]: Received disconnect from 10.0.0.25 port 50122:11: disconnected by user",
    ]
    noise_needed = TOTAL_LINES - n_events
    for i in range(noise_needed):
        ts = at(rng.randint(0, 23), rng.randint(0, 59), rng.randint(0, 59))
        tpl = templates[i % len(templates)]
        text = tpl(ts)
        n = text.count("%")
        stamp = ts.strftime("%b %d %H:%M:%S")
        if n == 3:
            items.append((ts, text % (stamp, HOST, rng.randint(1000, 30000))))
        else:
            items.append((ts, text % (stamp, HOST)))

    # Sort by time (stable) and write
    items.sort(key=lambda x: x[0])
    assert len(items) == TOTAL_LINES, len(items)
    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    with open(out_path, "w") as fh:
        for _, line in items:
            fh.write(line + "\n")
    print("Wrote %d lines to %s" % (len(items), out_path))


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "sample/auth.log")
