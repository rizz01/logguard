# LogGuard: SSH Brute-Force Detection and Risk Reporting

![tests](https://github.com/rizz01/logguard/actions/workflows/tests.yml/badge.svg)

A small, dependency-free Python command-line tool that reads Linux SSH authentication logs and
web-server access logs and reports suspicious activity. It was built as a mini project after a Cyber Security &
Ethical Hacking internship, to practise **monitoring and detection**, **scripting and automation**,
and **security documentation**.

## What it detects

| Rule | Meaning | Severity |
|---|---|---|
| Brute force | `N` failed logins from one IP inside a sliding time window | MEDIUM (HIGH at 3x the threshold) |
| Password spraying | 5 or more different usernames tried from one IP | MEDIUM |
| Success after failures | A successful login from an IP that had already failed (SSH logs) | HIGH |
| Web scanning | 5 or more different URLs returning 401/403/404 to one IP (web logs) | MEDIUM |

## Quick start

Requires Python 3.8+ and no third-party packages.

```bash
git clone https://github.com/rizz01/logguard.git
cd logguard
python -m logguard samples/auth.log --year 2026
```

Example output:

```text
SEVERITY IP                 FAILS  PEAK  USERS  FIRST SEEN
HIGH     203.0.113.45          24    24      3  2026-08-12 09:05:00
          - 24 failures within 60s (threshold 5)
HIGH     203.0.113.99           9     9      1  2026-08-12 09:12:00
          - 9 failures within 60s (threshold 5)
          - successful login after failed attempts: investigate this account
MEDIUM   198.51.100.7           6     1      6  2026-08-12 09:20:00
          - 6 different usernames tried (possible password spraying)
```

## Options

```text
logguard LOGFILE [--type ssh|web] [-t THRESHOLD] [-w WINDOW_SECONDS] [-y YEAR] [-f text|json|md|csv] [-o OUTPUT]
```

```bash
# Markdown report for documentation
python -m logguard samples/auth.log -y 2026 -f md -o report.md

# Web server access log (nginx / Apache combined format)
python -m logguard samples/access.log --type web

# CSV for Excel
python -m logguard samples/auth.log -y 2026 -f csv -o alerts.csv

# Stricter detection on a real server log
python -m logguard /var/log/auth.log -t 3 -w 30
```

The exit code is `1` when alerts are found and `0` when clean, so the tool works in scripts and cron jobs.
Syslog lines carry no year, so pass `--year` for older logs.

## Reading the results

- **FAILS**: total failed attempts from that IP. **PEAK**: most failures inside one time window. **USERS**: different usernames (SSH) or URLs (web) tried.
- **HIGH** needs urgent review, especially when a successful login follows failures. **MEDIUM** is suspicious but may be a misconfigured client or a scan.
- Exit code `1` means alerts were found, `0` means clean, `2` means a usage or file error.

## Run the tests

```bash
python -m unittest discover -s tests -v
```

## Project layout

```text
logguard/
  parser.py     extracts events from SSH syslog and web access logs
  detector.py   sliding-window rules and severity scoring
  report.py     text, JSON, Markdown and CSV output
  cli.py        argument handling
samples/             synthetic auth.log and access.log (reserved documentation IPs only)
tests/             unit tests
```

## Ethical use

LogGuard is a **defensive, read-only** tool. It only analyses log files you already have and sends no
network traffic. Only analyse logs from systems you own or are authorized to review.

## Limitations and ideas

- SSH: OpenSSH password and public-key messages only. Web: combined log format; 401/403/404 responses.
- IPv4 and simple IPv6 addresses; no geolocation or reputation lookups.
- Ideas: `fail2ban`-style block-list export, live log following, geolocation lookups.

## License

MIT, see [LICENSE](LICENSE).
