# Security policy

## Supported versions

Only the latest release on `main` receives fixes.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting for this repository:
<https://github.com/Leonard-Opasanjo/logsentinel/security/advisories/new>.
Please include the log line or file that triggers the problem and the command or dashboard action you ran.
You should hear back within seven days.

## Threat model

LogSentinel reads log files that an attacker can influence. Anyone who can attempt an SSH login can put a chosen
username into `auth.log`. The parser and the reports are therefore written to treat every byte of the log as hostile:

- Lines are truncated at 4 KiB and files are refused above 50 MB, including after gzip decompression.
- Undecodable bytes are replaced; nothing from a log is evaluated, formatted as a template or passed to a shell.
- Log-derived values are sanitised before being placed in the Markdown report, and evidence blocks strip backticks
  so a crafted line cannot close the code fence.
- The dashboard renders log-derived values through Streamlit components, which escape HTML.
- The tool makes no outbound network connections.

Out of scope, by design:

- The dashboard has no authentication. It is a local analyst tool that binds to `localhost`. Exposing it to a
  network without a reverse proxy that handles login is a deployment mistake, not a vulnerability in this project.
- Thresholds can be set so that an attack is not reported. Detection logic is heuristic; a missed detection is a
  feature request unless the rule fails to fire on the documented trigger.

Anything that lets a log line crash the parser, run code, exfiltrate data, break the report structure or escape the
Streamlit sandbox is in scope and welcome.
