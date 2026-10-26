# Hermes security watch

Read-only security reports and new-advisory alerts for [Hermes Agent](https://github.com/NousResearch/hermes-agent) installs.

It suggests updates. It does not apply them, edit config, rotate credentials, or print secrets.

## Install

```bash
hermes skills tap add Jpalmer95/hermes-security-watch
hermes skills install Jpalmer95/hermes-security-watch
```

Or clone this repo and symlink `SKILL.md`'s directory into `~/.hermes/skills/security/hermes-security-watch`.

## Report

```bash
python3 scripts/security_watch.py report
python3 scripts/security_watch.py report --out ~/.hermes/security-watch/latest-report.md
```

The report uses:

- `hermes --version` and `hermes security audit` (OSV.dev)
- Hermes's built-in compromised-package catalog
- Published GitHub security advisories for NousResearch/hermes-agent
- Recent CISA Known Exploited Vulnerabilities that match a typical Hermes host stack
- Local posture checks (approvals, allow-all, redaction, API server, root, SSH password auth)
- Distro security-update count when `apt-check` exists

## Alerts

```bash
python3 scripts/security_watch.py baseline   # remember current items; no backlog alert
```

Schedule `scripts/cron_watch.py` with no arguments. Hermes cron runs a script path, not a command line. Empty stdout means nothing new.

On a terminal session, cron output is not delivered back into the chat unless `deliver` is a gateway channel such as `all` or Telegram.

## Safety

Names, one-line impact, and patch suggestions only. No exploit steps. Do not pip-upgrade the Hermes venv; use `hermes update`, then re-run the report.

## Tests

```bash
python3 -m unittest tests/test_security_watch.py
```

License: Apache-2.0. Copyright 2026 Jonathan Korstad.
