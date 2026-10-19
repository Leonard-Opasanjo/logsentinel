# LogSentinel incident report

- Source: `sample_auth.log`
- Generated: 2026-10-19 12:25 UTC
- Lines read: 467 (auth events 280, unparsed 0, other 187)
- Period: 2026-10-15 03:12 to 2026-10-17 10:41 (host clock)

## Summary

| Severity | Findings |
|---|---|
| critical | 2 |
| high | 3 |
| medium | 3 |
| low | 2 |

## Findings

### LS-001 · CRITICAL · Login for bob from 10.0.1.77 after 6 failures

- Rule: `success_after_failures`
- Source IP: `10.0.1.77` · User: `bob`
- First seen: 2026-10-16 14:02:10 · Last seen: 2026-10-16 14:10:12 · Events: 7

password login for bob succeeded at 2026-10-16 14:10:12 after 6 failed attempts from the same source within 30 minutes (usernames tried: bob).

**Recommendation:** Treat as a possible account compromise: contact the user, review what the session ran (sudo entries, shell history), rotate the credential and consider isolating the host.

**Analyst notes:** _none_

Evidence (7 of 7 lines):

```text
380: 2026-10-16T14:02:10.367452+03:00 bastion-01 sshd[2869]: Failed password for bob from 10.0.1.77 port 56939 ssh2
381: 2026-10-16T14:03:41.350672+03:00 bastion-01 sshd[2876]: Failed password for bob from 10.0.1.77 port 47927 ssh2
382: 2026-10-16T14:04:43.926587+03:00 bastion-01 sshd[2882]: Failed password for bob from 10.0.1.77 port 23123 ssh2
383: 2026-10-16T14:06:19.385126+03:00 bastion-01 sshd[2891]: Failed password for bob from 10.0.1.77 port 32577 ssh2
384: 2026-10-16T14:07:51.366200+03:00 bastion-01 sshd[2895]: Failed password for bob from 10.0.1.77 port 54056 ssh2
385: 2026-10-16T14:08:56.931938+03:00 bastion-01 sshd[2896]: Failed password for bob from 10.0.1.77 port 14482 ssh2
386: 2026-10-16T14:10:12.467159+03:00 bastion-01 sshd[2904]: Accepted password for bob from 10.0.1.77 port 27564 ssh2
```

### LS-002 · CRITICAL · Login for dave from 203.0.113.9 after 4 failures

- Rule: `success_after_failures`
- Source IP: `203.0.113.9` · User: `dave`
- First seen: 2026-10-17 02:11:04 · Last seen: 2026-10-17 02:17:21 · Events: 5

password login for dave succeeded at 2026-10-17 02:17:21 after 4 failed attempts from the same source within 30 minutes (usernames tried: dave).

**Recommendation:** Treat as a possible account compromise: contact the user, review what the session ran (sudo entries, shell history), rotate the credential and consider isolating the host.

**Analyst notes:** _none_

Evidence (5 of 5 lines):

```text
430: 2026-10-17T02:11:04.150800+03:00 bastion-01 sshd[2911]: Failed password for dave from 203.0.113.9 port 12094 ssh2
431: 2026-10-17T02:12:40.264364+03:00 bastion-01 sshd[2916]: Failed password for dave from 203.0.113.9 port 20782 ssh2
432: 2026-10-17T02:14:12.690864+03:00 bastion-01 sshd[2925]: Failed password for dave from 203.0.113.9 port 48646 ssh2
433: 2026-10-17T02:15:55.077070+03:00 bastion-01 sshd[2931]: Failed password for dave from 203.0.113.9 port 62459 ssh2
435: 2026-10-17T02:17:21.969700+03:00 bastion-01 sshd[2935]: Accepted password for dave from 203.0.113.9 port 39254 ssh2
```

### LS-003 · HIGH · 140 failed logins from 203.0.113.45

- Rule: `brute_force`
- Source IP: `203.0.113.45` · User: `admin, root`
- First seen: 2026-10-15 03:12:04 · Last seen: 2026-10-15 03:19:09 · Events: 140

140 failed logins, at least 20 within 10 minutes. Usernames: admin, root.

**Recommendation:** Block the source, check whether any login from it later succeeded, rate-limit SSH (fail2ban, MaxAuthTries) and disable password authentication.

**Analyst notes:** _none_

Evidence (10 of 140 lines):

```text
4: 2026-10-15T03:12:04.861083+03:00 bastion-01 sshd[1820]: Failed password for root from 203.0.113.45 port 14294 ssh2
5: 2026-10-15T03:12:08.281734+03:00 bastion-01 sshd[1828]: Failed password for root from 203.0.113.45 port 57140 ssh2
6: 2026-10-15T03:12:12.433097+03:00 bastion-01 sshd[1831]: Failed password for root from 203.0.113.45 port 60970 ssh2
7: 2026-10-15T03:12:14.614292+03:00 bastion-01 sshd[1840]: Failed password for root from 203.0.113.45 port 51203 ssh2
8: 2026-10-15T03:12:16.438210+03:00 bastion-01 sshd[1843]: Failed password for root from 203.0.113.45 port 64118 ssh2
9: 2026-10-15T03:12:19.397999+03:00 bastion-01 sshd[1845]: Failed password for invalid user admin from 203.0.113.45 port 40826 ssh2
11: 2026-10-15T03:12:22.370098+03:00 bastion-01 sshd[1858]: Failed password for root from 203.0.113.45 port 24133 ssh2
12: 2026-10-15T03:12:25.679688+03:00 bastion-01 sshd[1865]: Failed password for root from 203.0.113.45 port 40045 ssh2
13: 2026-10-15T03:12:28.399165+03:00 bastion-01 sshd[1873]: Failed password for root from 203.0.113.45 port 49899 ssh2
14: 2026-10-15T03:12:31.841956+03:00 bastion-01 sshd[1878]: Failed password for root from 203.0.113.45 port 36208 ssh2
```

### LS-004 · HIGH · 36 failed logins from 198.51.100.23

- Rule: `password_spray`
- Source IP: `198.51.100.23` · User: `admin, deploy, ftp, git, guest (+7 more)`
- First seen: 2026-10-16 10:00:53 · Last seen: 2026-10-16 12:29:35 · Events: 36

36 failed logins spread over 12 different usernames. Usernames: admin, deploy, ftp, git, guest (+7 more).

**Recommendation:** Block the source at the firewall or with fail2ban, check whether any targeted account shares a weak password, and move SSH to key-based authentication.

**Analyst notes:** _none_

Evidence (10 of 36 lines):

```text
316: 2026-10-16T10:00:53.349993+03:00 bastion-01 sshd[2822]: Failed password for invalid user user from 198.51.100.23 port 38979 ssh2
317: 2026-10-16T10:05:07.914759+03:00 bastion-01 sshd[2851]: Failed password for invalid user ftp from 198.51.100.23 port 37765 ssh2
318: 2026-10-16T10:09:31.596598+03:00 bastion-01 sshd[2846]: Failed password for invalid user guest from 198.51.100.23 port 18198 ssh2
320: 2026-10-16T10:21:38.564588+03:00 bastion-01 sshd[2756]: Failed password for invalid user ubuntu from 198.51.100.23 port 58394 ssh2
321: 2026-10-16T10:25:27.347465+03:00 bastion-01 sshd[2808]: Failed password for invalid user git from 198.51.100.23 port 24681 ssh2
322: 2026-10-16T10:29:53.380539+03:00 bastion-01 sshd[2853]: Failed password for invalid user ftp from 198.51.100.23 port 28958 ssh2
323: 2026-10-16T10:33:59.918844+03:00 bastion-01 sshd[2830]: Failed password for invalid user user from 198.51.100.23 port 17325 ssh2
324: 2026-10-16T10:34:22.079569+03:00 bastion-01 sshd[2795]: Failed password for invalid user deploy from 198.51.100.23 port 63802 ssh2
325: 2026-10-16T10:38:20.538109+03:00 bastion-01 sshd[2705]: Failed password for invalid user test from 198.51.100.23 port 16706 ssh2
326: 2026-10-16T10:53:09.022317+03:00 bastion-01 sshd[2731]: Failed password for invalid user oracle from 198.51.100.23 port 46501 ssh2
```

### LS-005 · HIGH · 1 off-hours login(s) for root from 192.168.10.5

- Rule: `off_hours_login`
- Source IP: `192.168.10.5` · User: `root`
- First seen: 2026-10-17 04:40:07 · Last seen: 2026-10-17 04:40:07 · Events: 1

Successful logins outside 07:00-19:00 on weekdays. Times: Sat 04:40.

**Recommendation:** Confirm the activity with the user or a change ticket. Root logins at night deserve a direct check of what was run.

**Analyst notes:** _none_

Evidence (1 of 1 lines):

```text
442: 2026-10-17T04:40:07.626887+03:00 bastion-01 sshd[2945]: Accepted publickey for root from 192.168.10.5 port 48288 ssh2: ED25519 SHA256:5cr6jjafjzhohv5xh08vc35megt5x7hl0xoymcobwmr
```

### LS-006 · MEDIUM · 1 login(s) for erin from untrusted 198.51.100.77

- Rule: `untrusted_source`
- Source IP: `198.51.100.77` · User: `erin`
- First seen: 2026-10-15 11:30:44 · Last seen: 2026-10-15 11:30:44 · Events: 1

Source is outside the trusted networks (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16).

**Recommendation:** Verify the source belongs to the user (VPN, home, travel). Unknown external sources with a successful login warrant credential rotation.

**Analyst notes:** _none_

Evidence (1 of 1 lines):

```text
194: 2026-10-15T11:30:44.140659+03:00 bastion-01 sshd[2954]: Accepted publickey for erin from 198.51.100.77 port 2710 ssh2: ED25519 SHA256:7u9cw0ldff1d3ptvtxvl0jz11l19qks7earx1n9i1db
```

### LS-007 · MEDIUM · 7 failed logins from 10.0.1.77

- Rule: `repeated_failures`
- Source IP: `10.0.1.77` · User: `bob`
- First seen: 2026-10-16 14:02:10 · Last seen: 2026-10-16 15:57:45 · Events: 7

7 failed logins, at least 5 within 10 minutes. Usernames: bob.

**Recommendation:** Confirm with the account owner if the source is internal; otherwise treat it as reconnaissance and block it.

**Analyst notes:** _none_

Evidence (7 of 7 lines):

```text
380: 2026-10-16T14:02:10.367452+03:00 bastion-01 sshd[2869]: Failed password for bob from 10.0.1.77 port 56939 ssh2
381: 2026-10-16T14:03:41.350672+03:00 bastion-01 sshd[2876]: Failed password for bob from 10.0.1.77 port 47927 ssh2
382: 2026-10-16T14:04:43.926587+03:00 bastion-01 sshd[2882]: Failed password for bob from 10.0.1.77 port 23123 ssh2
383: 2026-10-16T14:06:19.385126+03:00 bastion-01 sshd[2891]: Failed password for bob from 10.0.1.77 port 32577 ssh2
384: 2026-10-16T14:07:51.366200+03:00 bastion-01 sshd[2895]: Failed password for bob from 10.0.1.77 port 54056 ssh2
385: 2026-10-16T14:08:56.931938+03:00 bastion-01 sshd[2896]: Failed password for bob from 10.0.1.77 port 14482 ssh2
404: 2026-10-16T15:57:45.544441+03:00 bastion-01 sshd[1628]: Failed password for bob from 10.0.1.77 port 11564 ssh2
```

### LS-008 · MEDIUM · 1 login(s) for dave from untrusted 203.0.113.9

- Rule: `untrusted_source`
- Source IP: `203.0.113.9` · User: `dave`
- First seen: 2026-10-17 02:17:21 · Last seen: 2026-10-17 02:17:21 · Events: 1

Source is outside the trusted networks (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16).

**Recommendation:** Verify the source belongs to the user (VPN, home, travel). Unknown external sources with a successful login warrant credential rotation.

**Analyst notes:** _none_

Evidence (1 of 1 lines):

```text
435: 2026-10-17T02:17:21.969700+03:00 bastion-01 sshd[2935]: Accepted password for dave from 203.0.113.9 port 39254 ssh2
```

### LS-009 · LOW · 1 off-hours login(s) for dave from 203.0.113.9

- Rule: `off_hours_login`
- Source IP: `203.0.113.9` · User: `dave`
- First seen: 2026-10-17 02:17:21 · Last seen: 2026-10-17 02:17:21 · Events: 1

Successful logins outside 07:00-19:00 on weekdays. Times: Sat 02:17.

**Recommendation:** Confirm the activity with the user or a change ticket. Root logins at night deserve a direct check of what was run.

**Analyst notes:** _none_

Evidence (1 of 1 lines):

```text
435: 2026-10-17T02:17:21.969700+03:00 bastion-01 sshd[2935]: Accepted password for dave from 203.0.113.9 port 39254 ssh2
```

### LS-010 · LOW · 1 off-hours login(s) for alice from 10.0.1.20

- Rule: `off_hours_login`
- Source IP: `10.0.1.20` · User: `alice`
- First seen: 2026-10-17 10:30:15 · Last seen: 2026-10-17 10:30:15 · Events: 1

Successful logins outside 07:00-19:00 on weekdays. Times: Sat 10:30.

**Recommendation:** Confirm the activity with the user or a change ticket. Root logins at night deserve a direct check of what was run.

**Analyst notes:** _none_

Evidence (1 of 1 lines):

```text
451: 2026-10-17T10:30:15.904994+03:00 bastion-01 sshd[2966]: Accepted publickey for alice from 10.0.1.20 port 18005 ssh2: ED25519 SHA256:7nfg07fb2i9rwm2ql6d0cxo5cuo78wijjpih1xk9huf
```

## Timeline (hourly)

| Hour | accepted | failed | sudo | sudo_failed |
|---|---|---|---|---|
| 2026-10-15 03:00 | 0 | 140 | 0 | 0 |
| 2026-10-15 08:00 | 2 | 0 | 1 | 0 |
| 2026-10-15 10:00 | 2 | 0 | 1 | 0 |
| 2026-10-15 11:00 | 2 | 0 | 3 | 0 |
| 2026-10-15 12:00 | 2 | 0 | 3 | 0 |
| 2026-10-15 13:00 | 1 | 0 | 1 | 0 |
| 2026-10-15 14:00 | 4 | 2 | 4 | 0 |
| 2026-10-15 15:00 | 2 | 0 | 3 | 0 |
| 2026-10-15 16:00 | 4 | 1 | 3 | 0 |
| 2026-10-15 17:00 | 3 | 0 | 1 | 0 |
| 2026-10-15 18:00 | 0 | 0 | 1 | 0 |
| 2026-10-16 08:00 | 5 | 2 | 3 | 0 |
| 2026-10-16 09:00 | 2 | 0 | 2 | 0 |
| 2026-10-16 10:00 | 0 | 13 | 0 | 0 |
| 2026-10-16 11:00 | 3 | 12 | 3 | 0 |
| 2026-10-16 12:00 | 2 | 11 | 2 | 0 |
| 2026-10-16 13:00 | 1 | 1 | 0 | 0 |
| 2026-10-16 14:00 | 2 | 6 | 1 | 0 |
| 2026-10-16 15:00 | 3 | 1 | 2 | 1 |
| 2026-10-16 16:00 | 2 | 0 | 1 | 0 |
| 2026-10-16 17:00 | 1 | 0 | 2 | 0 |
| 2026-10-17 02:00 | 1 | 4 | 2 | 0 |
| 2026-10-17 04:00 | 1 | 0 | 0 | 0 |
| 2026-10-17 10:00 | 1 | 0 | 1 | 0 |

## Detection settings

| Setting | Value |
|---|---|
| fail_threshold | 5 |
| brute_threshold | 20 |
| spray_users | 5 |
| window_minutes | 10 |
| lookback_minutes | 30 |
| success_min_failures | 3 |
| business_hours | (7, 19) |
| trusted_networks | ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16') |
