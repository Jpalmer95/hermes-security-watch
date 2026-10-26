---
name: hermes-security-watch
description: "Use when securing Hermes or checking new advisories. Reports gaps and alerts; never auto-patches."
version: 1.0.0
author: Jonathan Korstad
license: Apache-2.0
metadata:
  hermes:
    tags: [hermes, security, advisories, supply-chain, report, watch]
    related_skills: [hermes-agent, hermes-config-maintenance, cron-watch-jobs]
---

# Hermes security watch

Produce a read-only security report for a Hermes install, and alert only when
new high-signal items appear. Consumers get suggestions. This skill does not
apply patches.

## When to use

- The user wants a security report, hardening suggestions, or a list of updates they should consider.
- The user wants to be notified of new Hermes advisories or new large-scale exploited vulns that may affect their host.
- Before or after `hermes update`, to see whether supply-chain findings moved.

Not this skill: applying the update, editing `config.yaml`, rotating keys, pentesting a site, or writing exploit steps. Config repair is `hermes-config-maintenance`. Stuck updates are a separate diagnosis, not a patch run.

## Procedure

1. Run the collector. Do not invent findings, counts, or fixed versions.

```bash
python3 <skill-dir>/scripts/security_watch.py report
```

Write a copy when the user wants a file:

```bash
python3 <skill-dir>/scripts/security_watch.py report --out "$HERMES_HOME/security-watch/latest-report.md"
```

`<skill-dir>` is the directory that contains this `SKILL.md`. `$HERMES_HOME` defaults to `~/.hermes`.

2. Summarize the script output. Lead with act-now items, then what was verified by the script, then what was left as a decision. If `source_errors` is non-empty, say which source failed. Do not fill the gap from memory.

3. Stop unless the user explicitly asks, in this turn, to apply a named suggestion. Suggestions are not approval. Never `pip install` or `pip upgrade` inside the Hermes venv. The sanctioned Hermes update is `hermes update`, and it restarts the gateway.

## What the report covers

- `hermes --version` update status.
- `hermes security audit --json` (OSV.dev) for the Hermes venv, plugin requirements, and pinned MCP servers. Exit code 1 means findings, not a crash.
- The built-in compromised-package catalog (`hermes_cli/security_advisories.py`), including acked ids.
- Published GitHub security advisories for `NousResearch/hermes-agent` (often empty).
- CISA Known Exploited Vulnerabilities added in the lookback window (default 21 days) whose vendor/product matches a typical Hermes host stack. These are not confirmed local hits.
- Posture: approvals off, cron/unattended auto-approve, allow-all gateway flags, secret redaction off, private URL fetches on, API server reachable without a key, root, SSH password auth.
- Distro security-update count via `apt-check` when that binary exists. It does not install them.

It does not scan every installed distro package, editor extension, or the public CVE firehose.

## Watch and notify

Baseline first so the first alert is not the historical backlog:

```bash
python3 <skill-dir>/scripts/security_watch.py baseline
```

Cron cannot take script arguments. Point `script` at `scripts/cron_watch.py` (no-arg watch). Empty stdout is a silent success. A new high/critical OSV id, compromised-package hit, Hermes GHSA, relevant KEV id, update-available transition, increased distro security count, or new posture finding prints an alert and exits 0.

CLI sessions have no live cron delivery. `deliver` must be a gateway channel (`all`, or `telegram:...`). `origin` only saves output locally. Do not promise the user they will see it in this chat.

Do not write the state file during a preview you intend to treat as day-1 news. `report` does not update the snapshot. `baseline` and `watch` do.

Prefer `no_agent: true` for the cron. The script text is the alert. An agent cron can hallucinate findings the collector did not return.

## Rules

- Never print `.env` values, tokens, allowlist ids, or API keys. The collector keeps booleans and key names only. If a subprocess fails, do not paste its stderr into the report — config and `.env` lines can land there.
- Never include exploit steps, payloads, or reproduction. KEV `shortDescription` is dropped on purpose. OSV summaries stay one truncated line, which is all Hermes itself prints.
- `hermes doctor --ack <id>` only after the user has actually handled that advisory.
- Config writes go through `hermes config set`, and only when asked. `patch` / `write_file` refuse `config.yaml` on purpose.
- Profiles are separate. A suggestion for `primary` does not fix `default`.
- Do not treat a successful `hermes update` as proof the findings are gone. Re-run the report.
- If `hermes --version` already says up to date, do not lead with `hermes update` as the fix for remaining OSV pins. Those are current-release pins. Track them upstream. A local unpin can break the agent.
- A remaining finding after update is an upstream pin. Track it. Do not hot-patch the venv.

## Pitfalls

- `hermes security audit` can take a couple of minutes. Timeout is a degraded source, not "no vulnerabilities".
- GitHub advisory API unauthenticated rate limits. An error is a degraded source, not "no advisories".
- CISA KEV matches are stack-relevant, not proof the package is installed. Say that.
- `allow_lazy_installs: true` and `approvals.cron_mode: deny` are shipped defaults. Do not report them as misconfigurations. The collector does not.
- Secret redaction defaults off. The report lists it as hardening, not as a broken install.
- First `watch` with no snapshot prints an armed line and does not dump history. That line is delivered if cron has not been baselined yet.
