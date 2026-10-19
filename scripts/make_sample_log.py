#!/usr/bin/env python3
"""Generate the bundled synthetic auth.log.

Deterministic (fixed seed), uses documentation IP ranges (RFC 5737) for external
sources and RFC 1918 ranges internally, generic usernames, no real data.

Usage: python scripts/make_sample_log.py [OUTPUT]
"""

from __future__ import annotations

import random
import sys
from datetime import datetime, timedelta
from pathlib import Path

OUT = Path(__file__).resolve().parents[1] / "src/logsentinel/data/sample_auth.log"
HOST = "bastion-01"
STAFF = {"alice": "10.0.1.20", "bob": "10.0.1.77", "carol": "10.0.1.31",
         "dave": "192.168.10.14", "erin": "192.168.10.22", "frank": "10.0.1.45"}
UIDS = {u: 1001 + i for i, u in enumerate(STAFF)} | {"root": 0}
SPRAY_USERS = ["admin", "test", "oracle", "postgres", "ubuntu", "pi", "deploy", "git", "user", "guest",
               "ftp", "www-data"]
COMMANDS = ["/usr/bin/apt update", "/usr/bin/systemctl restart nginx", "/usr/bin/journalctl -u ssh",
            "/usr/bin/tail -n 100 /var/log/syslog", "/usr/bin/docker ps", "/usr/bin/less /etc/nginx/nginx.conf"]

rng = random.Random(7)
lines: list[tuple[datetime, str]] = []
_pid = 1000


def pid() -> int:
    global _pid
    _pid += rng.randint(1, 9)
    return _pid


def at(day: int, h: int, m: int = 0, s: int = 0) -> datetime:
    return datetime(2026, 10, day, h, m, s)


def stamp(t: datetime) -> str:
    return f"{t:%Y-%m-%dT%H:%M:%S}.{rng.randint(0, 999999):06d}+03:00"


def emit(t: datetime, proc: str, msg: str, with_pid: bool = True) -> None:
    p = f"{proc}[{pid()}]" if with_pid else proc
    lines.append((t, f"{stamp(t)} {HOST} {p}: {msg}"))


def ssh_fail(t: datetime, user: str, ip: str, invalid: bool = False) -> None:
    who = f"invalid user {user}" if invalid else user
    emit(t, "sshd", f"Failed password for {who} from {ip} port {rng.randint(1024, 65535)} ssh2")


def ssh_ok(t: datetime, user: str, ip: str, method: str = "publickey") -> None:
    p, port = pid(), rng.randint(1024, 65535)
    suffix = ""
    if method == "publickey":
        suffix = ": ED25519 SHA256:" + "".join(rng.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=43))
    lines.append((t, f"{stamp(t)} {HOST} sshd[{p}]: Accepted {method} for {user} from {ip} port {port} ssh2{suffix}"))
    t2 = t + timedelta(milliseconds=40)
    lines.append((t2, f"{stamp(t2)} {HOST} sshd[{p}]: pam_unix(sshd:session): session opened for user "
                      f"{user}(uid={UIDS.get(user, 1099)}) by (uid=0)"))
    t3 = t + timedelta(milliseconds=90)
    emit(t3, "systemd-logind", f"New session {rng.randint(100, 999)} of user {user}.")


def sudo(t: datetime, user: str, cmd: str) -> None:
    emit(t, "sudo", f"    {user} : TTY=pts/{rng.randint(0, 3)} ; PWD=/home/{user} ; USER=root ; COMMAND={cmd}",
         with_pid=False)


def sudo_fail(t: datetime, user: str) -> None:
    emit(t, "sudo", f"    {user} : 3 incorrect password attempts ; TTY=pts/1 ; PWD=/home/{user} ; "
                    "USER=root ; COMMAND=/bin/bash", with_pid=False)


def minutes(t: datetime, lo: float, hi: float) -> datetime:
    return t + timedelta(seconds=rng.uniform(lo * 60, hi * 60))


# Background: hourly cron, staff working Thu 15 and Fri 16 Oct 2026 (Sat 17 is the weekend)
for day in (15, 16, 17):
    for hour in range(24):
        emit(at(day, hour, 17, 1), "CRON", "pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)")
for day in (15, 16):
    for user, ip in STAFF.items():
        for _ in range(rng.randint(2, 4)):
            t = at(day, rng.randint(8, 17), rng.randint(0, 59), rng.randint(0, 59))
            if rng.random() < 0.15:  # a typo before a successful password login
                ssh_fail(t - timedelta(seconds=rng.randint(8, 40)), user, ip)
                ssh_ok(t, user, ip, "password")
            else:
                ssh_ok(t, user, ip)
            if rng.random() < 0.5:
                for _ in range(rng.randint(1, 2)):
                    sudo(minutes(t, 1, 12), user, rng.choice(COMMANDS))

# A. Brute force against root from 203.0.113.45, Thu 03:12 (140 attempts, two usernames)
t = at(15, 3, 12, 4)
for i in range(140):
    ssh_fail(t, "root", "203.0.113.45") if rng.random() < 0.8 else ssh_fail(t, "admin", "203.0.113.45", invalid=True)
    if i % 6 == 5:
        emit(t + timedelta(milliseconds=300), "sshd",
             f"Connection closed by authenticating user root 203.0.113.45 port {rng.randint(1024, 65535)} [preauth]")
    t += timedelta(seconds=rng.randint(2, 4))

# B. Password spray from 198.51.100.23, Fri 10:00-12:30, 12 usernames x 3 attempts
for user in SPRAY_USERS:
    for _ in range(3):
        ssh_fail(minutes(at(16, 10), 0, 150), user, "198.51.100.23", invalid=True)

# C. Internal: bob fails six times then gets in with a password, Fri 14:02-14:10
t = at(16, 14, 2, 10)
for _ in range(6):
    ssh_fail(t, "bob", "10.0.1.77")
    t = minutes(t, 1, 1.6)
ssh_ok(at(16, 14, 10, 12), "bob", "10.0.1.77", "password")

# D. External compromise: dave from 203.0.113.9, Sat 02:11-02:17, then sensitive sudo
for mm, ss in ((11, 4), (12, 40), (14, 12), (15, 55)):
    ssh_fail(at(17, 2, mm, ss), "dave", "203.0.113.9")
ssh_ok(at(17, 2, 17, 21), "dave", "203.0.113.9", "password")
sudo(at(17, 2, 19, 3), "dave", "/usr/bin/cat /etc/shadow")
sudo(at(17, 2, 23, 48), "dave", "/usr/bin/tar czf /tmp/.cache.tgz /home /etc")

# E. Root key login from the VPN range at 04:40 on Saturday
ssh_ok(at(17, 4, 40, 7), "root", "192.168.10.5")

# F. Erin working remotely from an unknown external address on Thursday
ssh_ok(at(15, 11, 30, 44), "erin", "198.51.100.77")
sudo(at(15, 11, 34, 2), "erin", "/usr/bin/journalctl -u ssh")

# G. Carol mistypes her sudo password on Friday; Alice does some weekend work
sudo_fail(at(16, 15, 2, 33), "carol")
ssh_ok(at(17, 10, 30, 15), "alice", "10.0.1.20")
sudo(at(17, 10, 41, 50), "alice", "/usr/bin/apt update")

out = Path(sys.argv[1]) if len(sys.argv) > 1 else OUT
lines.sort(key=lambda x: x[0])
out.write_text("\n".join(line for _, line in lines) + "\n", encoding="utf-8")
print(f"wrote {len(lines)} lines to {out}")
