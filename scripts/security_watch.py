#!/usr/bin/env python3
"""Read-only Hermes security report and new-advisory watch.

Collects local Hermes posture, the built-in compromised-package catalog,
`hermes security audit` (OSV.dev), published NousResearch/hermes-agent
advisories, and recent CISA KEV entries that match a typical Hermes host
stack. Prints suggestions. Never applies patches, edits config, rotates
credentials, or prints secret values.

Watch mode alerts only on items that were not in the last saved snapshot.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

USER_AGENT = "hermes-security-watch"
GHSA_URL = (
    "https://api.github.com/repos/NousResearch/hermes-agent/security-advisories"
    "?per_page=20&state=published"
)
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
SEVERITY_RANK = {"UNKNOWN": 0, "LOW": 1, "MODERATE": 2, "HIGH": 3, "CRITICAL": 4}
RELEVANT_PRODUCT = re.compile(
    r"\b(?:openssl|openssh|sudo|glibc|docker|containerd|kubernetes|nginx|"
    r"python|node\.?js|npm|systemd|curl|linux kernel|hermes|git)\b",
    re.I,
)
TRUTHY = {"1", "true", "yes", "on"}
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}
STATE_VERSION = 1


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def hermes_home() -> Path:
    return Path(os.environ.get("HERMES_HOME") or (Path.home() / ".hermes"))


def default_state_path() -> Path:
    return hermes_home() / "security-watch" / "state.json"


def severity_of(value: Any) -> str:
    sev = str(value or "UNKNOWN").upper()
    return "MODERATE" if sev == "MEDIUM" else sev


def meets(severity: str, minimum: str) -> bool:
    return SEVERITY_RANK.get(severity_of(severity), 0) >= SEVERITY_RANK.get(severity_of(minimum), 3)


def venv_suggestion(update_status: str) -> str:
    """What to tell the user about Hermes-venv findings. Never a pip upgrade."""
    if update_status == "available":
        return "Suggested, not applied: `hermes update`, then re-run this report. Do not pip-upgrade the Hermes venv."
    if update_status == "current":
        return "Hermes reports up to date, so these are current-release pins. Do not pip-upgrade the Hermes venv. Track them upstream; a local unpin can break the agent."
    if update_status == "ahead":
        return "This checkout is newer than the selected stable release. Do not pip-upgrade the Hermes venv. Re-check after you choose a channel."
    return "Could not confirm whether Hermes is behind. Check `hermes --version` before updating. Do not pip-upgrade the Hermes venv."


def one_line(text: Any, limit: int = 140) -> str:
    return " ".join(str(text or "").split())[:limit]


def parse_json_blob(text: str) -> Any:
    start = text.find("{")
    list_start = text.find("[")
    if start < 0 or (list_start >= 0 and list_start < start):
        start = list_start
    if start < 0:
        raise ValueError("no json in response")
    return json.loads(text[start:])


def fetch_bytes(url: str, timeout: int = 25, max_bytes: int = 8_000_000) -> bytes:
    if not url.startswith("https://"):
        raise RuntimeError("refusing non-https URL")
    req = urllib.request.Request(
        url,
        headers={"User-Agent": USER_AGENT, "Accept": "application/vnd.github+json, application/json"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = resp.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise RuntimeError("response exceeded size cap")
    return data


def run_cmd(argv: list[str], timeout: int) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)


def parse_version_text(text: str) -> dict[str, str]:
    info = {
        "version_line": "",
        "install_dir": "",
        "install_method": "",
        "update_status": "unknown",
        "update_detail": "",
    }
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("Hermes Agent"):
            info["version_line"] = stripped
        elif stripped.startswith("Install directory:"):
            info["install_dir"] = stripped.split(":", 1)[1].strip()
        elif stripped.startswith("Install method:"):
            info["install_method"] = stripped.split(":", 1)[1].strip()
        elif "Update available" in stripped:
            info["update_status"] = "available"
            info["update_detail"] = stripped
        elif stripped in {"Up to date", "✓ Up to date"} or stripped.startswith("Up to date"):
            info["update_status"] = "current"
            info["update_detail"] = stripped
        elif "Newer than stable" in stripped:
            info["update_status"] = "ahead"
            info["update_detail"] = stripped
    return info


def hermes_python(install_dir: str) -> str | None:
    if not install_dir:
        return None
    root = Path(install_dir)
    for rel in ("venv/bin/python", ".venv/bin/python"):
        candidate = root / rel
        if candidate.is_file():
            return str(candidate)
    return None


def parse_env_policy(text: str) -> dict[str, Any]:
    """Booleans and key names only. Never return secret values."""
    allow_all: list[str] = []
    platforms: list[str] = []
    api_key_set = False
    api_enabled = False
    api_host_public = False
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, val = line.split("=", 1)
        key = key.strip().removeprefix("export ").strip()
        val = val.strip().strip("'\"")
        if not key:
            continue
        truthy = val.lower() in TRUTHY
        if key.endswith("_ALLOW_ALL_USERS") and truthy:
            allow_all.append(key)
        if key == "API_SERVER_KEY" and val:
            api_key_set = True
        if key == "API_SERVER_ENABLED" and truthy:
            api_enabled = True
        if key == "API_SERVER_HOST" and val and val.lower() not in LOOPBACK_HOSTS:
            api_host_public = True
        if val and (key.endswith("_BOT_TOKEN") or key in {"SLACK_BOT_TOKEN", "SLACK_APP_TOKEN", "DISCORD_BOT_TOKEN"}):
            platforms.append(key.split("_", 1)[0].lower())
    return {
        "allow_all_users": allow_all,
        "platforms_with_token": sorted(set(platforms)),
        "api_server_key_set": api_key_set,
        "api_server_enabled": api_enabled,
        "api_server_host_public": api_host_public,
    }


def host_is_public(host: Any) -> bool:
    if not isinstance(host, str) or not host.strip():
        return False
    return host.strip().lower() not in LOOPBACK_HOSTS


def config_subset(cfg: dict) -> dict[str, Any]:
    """Keep posture fields only. Drop hosts, keys, allowlist ids, and tokens."""
    if not isinstance(cfg, dict):
        return {}
    approvals = cfg.get("approvals") if isinstance(cfg.get("approvals"), dict) else {}
    security = cfg.get("security") if isinstance(cfg.get("security"), dict) else {}
    privacy = cfg.get("privacy") if isinstance(cfg.get("privacy"), dict) else {}
    gateway = cfg.get("gateway") if isinstance(cfg.get("gateway"), dict) else {}
    platforms = cfg.get("platforms") if isinstance(cfg.get("platforms"), dict) else {}
    api = platforms.get("api_server") if isinstance(platforms.get("api_server"), dict) else {}
    extra = api.get("extra") if isinstance(api.get("extra"), dict) else {}
    return {
        "approvals": {
            "mode": approvals.get("mode"),
            "cron_mode": approvals.get("cron_mode"),
            "single_query_mode": approvals.get("single_query_mode"),
            "unattended_mode": approvals.get("unattended_mode"),
        },
        "security": {
            "redact_secrets": security.get("redact_secrets"),
            "allow_private_urls": security.get("allow_private_urls"),
        },
        "privacy": {"redact_pii": privacy.get("redact_pii")},
        "allow_all_users": cfg.get("allow_all_users") is True or gateway.get("allow_all_users") is True,
        "api_server": {
            "enabled": api.get("enabled") is True,
            "host_public": host_is_public(extra.get("host")),
            "key_present": bool(str(extra.get("key") or "").strip()),
        },
    }


def profile_flag(profile: str) -> str:
    return "" if profile == "default" else f" -p {profile}"


def posture_findings(profile: str, cfg: dict, env_policy: dict) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []

    def add(fid: str, severity: str, kind: str, title: str, suggestion: str) -> None:
        findings.append({
            "id": f"{profile}:{fid}",
            "profile": profile,
            "severity": severity,
            "kind": kind,
            "title": title,
            "suggestion": suggestion,
        })

    flag = profile_flag(profile)
    mode = str((cfg.get("approvals") or {}).get("mode") or "").lower()
    if mode == "off":
        add(
            "approvals-off", "high", "finding",
            "Dangerous-command approval is off",
            f"Suggested, not applied: hermes{flag} config set approvals.mode smart",
        )
    for key, label in (
        ("cron_mode", "cron"),
        ("single_query_mode", "one-shot chat -q"),
        ("unattended_mode", "unattended webhook/API"),
    ):
        value = str((cfg.get("approvals") or {}).get(key) or "").lower()
        if value == "approve":
            add(
                f"approvals-{key}", "medium", "finding",
                f"{label} sessions auto-approve dangerous commands",
                f"Suggested, not applied: hermes{flag} config set approvals.{key} deny",
            )
    if cfg.get("allow_all_users") is True or env_policy.get("allow_all_users"):
        add(
            "allow-all-users", "high", "finding",
            "A gateway allow-all flag is on",
            "Suggested, not applied: set allow_all_users false and remove *_ALLOW_ALL_USERS=true from that profile .env, then restart the gateway. This report does not edit .env.",
        )
    secrets = (cfg.get("security") or {}).get("redact_secrets")
    if secrets is False:
        add(
            "redact-secrets", "low", "suggestion",
            "Tool-output secret redaction is off",
            f"Hardening, not applied: hermes{flag} config set security.redact_secrets true  (takes effect in a new session)",
        )
    if (cfg.get("security") or {}).get("allow_private_urls") is True:
        add(
            "private-urls", "medium", "suggestion",
            "Private-network URL fetches are allowed",
            f"Review: hermes{flag} config set security.allow_private_urls false unless this agent must reach LAN services. Prompt-injected URLs can then hit the local network.",
        )
    api = cfg.get("api_server") or {}
    env_open = bool(env_policy.get("api_server_enabled") and env_policy.get("api_server_host_public") and not env_policy.get("api_server_key_set"))
    cfg_open = bool(api.get("enabled") and api.get("host_public") and not api.get("key_present"))
    if env_open or cfg_open:
        add(
            "api-server-open", "high", "finding",
            "API server looks network-reachable without a key",
            "Suggested, not applied: set a long random API_SERVER_KEY in that profile's .env, or bind the host to loopback. This report does not generate or print a key.",
        )
    return findings


def ssh_password_auth(text: str) -> str:
    """Return enabled, disabled, or unknown. Does not echo config lines."""
    if not text.strip():
        return "unknown"
    directives: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = re.match(r"(?i)^PasswordAuthentication\s+(\w+)", stripped)
        if match:
            directives.append(match.group(1).lower())
    if directives and directives[-1] == "no":
        return "disabled"
    return "enabled"


def host_findings(is_root: bool, ssh_state: str) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    if is_root:
        findings.append({
            "id": "host:root",
            "profile": "host",
            "severity": "high",
            "kind": "finding",
            "title": "Hermes is running as root",
            "suggestion": "Suggested, not applied: run Hermes as an unprivileged user. A prompt injection would otherwise be a full host compromise.",
        })
    if ssh_state == "enabled":
        findings.append({
            "id": "host:ssh-password",
            "profile": "host",
            "severity": "medium",
            "kind": "finding",
            "title": "SSH password authentication is enabled",
            "suggestion": "Suggested, not applied: set PasswordAuthentication no in sshd_config and use keys. This report does not edit sshd.",
        })
    return findings


def normalize_audit(payload: dict) -> list[dict[str, Any]]:
    findings = []
    for item in payload.get("findings") or []:
        if not isinstance(item, dict):
            continue
        findings.append({
            "package": item.get("package"),
            "version": item.get("version"),
            "source": item.get("source") or "unknown",
            "vuln_id": item.get("vuln_id"),
            "severity": severity_of(item.get("severity")),
            "summary": one_line(item.get("summary")),
            "fixed_in": [str(v) for v in (item.get("fixed_versions") or [])[:3]],
        })
    findings.sort(key=lambda f: (-SEVERITY_RANK.get(f["severity"], 0), str(f["package"]), str(f["vuln_id"])))
    return findings


def audit_counts(findings: list[dict]) -> dict[str, int]:
    counts = {name: 0 for name in ("CRITICAL", "HIGH", "MODERATE", "LOW", "UNKNOWN")}
    for item in findings:
        counts[item["severity"]] = counts.get(item["severity"], 0) + 1
    return counts


def parse_apt_check(text: str) -> dict[str, int] | None:
    match = re.search(r"(\d+);(\d+)", text or "")
    if not match:
        return None
    return {"pending": int(match.group(1)), "security": int(match.group(2))}


def kev_public(entry: dict) -> dict[str, str]:
    return {
        "cve": str(entry.get("cveID") or ""),
        "vendor": str(entry.get("vendorProject") or ""),
        "product": str(entry.get("product") or ""),
        "name": one_line(entry.get("vulnerabilityName"), 120),
        "date_added": str(entry.get("dateAdded") or ""),
        "ransomware": str(entry.get("knownRansomwareCampaignUse") or ""),
    }


def filter_kev(catalog: dict, today: date, lookback_days: int) -> list[dict[str, str]]:
    items = []
    for entry in catalog.get("vulnerabilities") or []:
        if not isinstance(entry, dict):
            continue
        added = str(entry.get("dateAdded") or "")
        try:
            added_on = date.fromisoformat(added)
        except ValueError:
            continue
        age = (today - added_on).days
        if age < 0 or age > lookback_days:
            continue
        blob = f"{entry.get('vendorProject', '')} {entry.get('product', '')}"
        if not RELEVANT_PRODUCT.search(blob):
            continue
        items.append(kev_public(entry))
    items.sort(key=lambda item: item["date_added"], reverse=True)
    return items


def ghsa_public(item: dict) -> dict[str, str]:
    return {
        "id": str(item.get("ghsa_id") or item.get("id") or ""),
        "severity": severity_of(item.get("severity")),
        "summary": one_line(item.get("summary"), 160),
        "published": str(item.get("published_at") or "")[:10],
        "url": str(item.get("html_url") or ""),
    }


def load_state(path: Path) -> dict | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def save_state(path: Path, state: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(tmp, 0o600)
    tmp.replace(path)
    os.chmod(path, 0o600)


def snapshot_from(data: dict, min_severity: str) -> dict:
    audit = data.get("audit") or {}
    actionable = [f for f in audit.get("findings") or [] if meets(f.get("severity", ""), min_severity) and f.get("vuln_id")]
    return {
        "version": STATE_VERSION,
        "updated_at": data.get("generated_at") or utc_now(),
        "osv_ids": sorted({f["vuln_id"] for f in actionable}),
        "hermes_ghsa": sorted({item["id"] for item in (data.get("advisories") or {}).get("items") or [] if item.get("id")}),
        "kev_ids": sorted({item["cve"] for item in (data.get("kev") or {}).get("items") or [] if item.get("cve")}),
        "compromised": sorted(
            f"{hit.get('id')}@{hit.get('installed_version')}"
            for hit in (data.get("compromised") or {}).get("hits") or []
            if hit.get("id") and not hit.get("acked")
        ),
        "posture_ids": sorted(item["id"] for item in data.get("posture") or [] if item.get("kind") == "finding"),
        "update_status": (data.get("hermes") or {}).get("update_status") or "unknown",
        "distro_security": ((data.get("distro") or {}) or {}).get("security"),
        "source_errors": data.get("source_errors") or {},
    }


def decide_watch(data: dict, previous: dict | None, min_severity: str) -> tuple[str, dict]:
    """Return (alert text, new state). Empty alert means stay silent."""
    state = snapshot_from(data, min_severity)
    if not previous:
        tracked = len(state["osv_ids"]) + len(state["hermes_ghsa"]) + len(state["kev_ids"]) + len(state["compromised"])
        degraded = ", ".join(sorted((data.get("source_errors") or {}))) or "none"
        return (
            "Hermes security watch armed. "
            f"Tracking {tracked} item(s) at or above {min_severity}. "
            f"Degraded sources: {degraded}. "
            "Later runs alert only on new items. Nothing was changed.",
            state,
        )

    lines: list[str] = []
    seen_osv = set(previous.get("osv_ids") or [])
    for finding in data.get("audit", {}).get("findings") or []:
        if not meets(finding.get("severity", ""), min_severity):
            continue
        vid = finding.get("vuln_id")
        if not vid or vid in seen_osv:
            continue
        fixed = ", ".join(finding.get("fixed_in") or []) or "no fixed version listed"
        lines.append(
            f"- {finding.get('severity')} {finding.get('source')} {finding.get('package')}=={finding.get('version')} {vid} — {finding.get('summary') or 'no summary'} — fixed in: {fixed}"
        )
        lines.append("  " + venv_suggestion((data.get("hermes") or {}).get("update_status") or "unknown"))

    seen_hit = set(previous.get("compromised") or [])
    for hit in (data.get("compromised") or {}).get("hits") or []:
        key = f"{hit.get('id')}@{hit.get('installed_version')}"
        if hit.get("acked") or key in seen_hit:
            continue
        lines.append(f"- COMPROMISED {hit.get('package')}=={hit.get('installed_version')} {hit.get('id')} — {hit.get('title')}")
        for step in hit.get("remediation") or []:
            lines.append(f"  Suggested, not applied: {step}")

    seen_ghsa = set(previous.get("hermes_ghsa") or [])
    for item in (data.get("advisories") or {}).get("items") or []:
        if not item.get("id") or item["id"] in seen_ghsa:
            continue
        lines.append(f"- HERMES ADVISORY {item.get('severity')} {item.get('id')} — {item.get('summary')} — {item.get('url')}")
        lines.append("  Suggestion: read the advisory and run `hermes update` if your version is in range. Nothing was changed.")

    seen_kev = set(previous.get("kev_ids") or [])
    for item in (data.get("kev") or {}).get("items") or []:
        if not item.get("cve") or item["cve"] in seen_kev:
            continue
        lines.append(
            f"- KEV {item['cve']} {item['vendor']} {item['product']} (added {item['date_added']}) — {item['name']}"
        )
        lines.append("  Suggestion: if this host runs that product, patch via the vendor or distro. Not a confirmed local hit. No exploit steps included.")

    if previous.get("update_status") != "available" and (data.get("hermes") or {}).get("update_status") == "available":
        detail = (data.get("hermes") or {}).get("update_detail") or "Update available"
        lines.append(f"- HERMES UPDATE {detail}")
        lines.append("  Suggestion: `hermes update` when you can accept a gateway restart. Not applied.")

    prev_distro = previous.get("distro_security")
    distro = ((data.get("distro") or {}) or {}).get("security")
    if isinstance(distro, int) and distro > 0 and (not isinstance(prev_distro, int) or distro > prev_distro):
        lines.append(f"- DISTRO {distro} security update(s) pending (was {prev_distro if prev_distro is not None else 'unknown'}).")
        lines.append("  Suggestion: review with the distro package manager. This watch does not install them.")

    seen_posture = set(previous.get("posture_ids") or [])
    for item in data.get("posture") or []:
        if item.get("kind") != "finding" or item.get("id") in seen_posture:
            continue
        lines.append(f"- POSTURE {item.get('severity')} {item.get('title')} ({item.get('profile')})")
        lines.append(f"  {item.get('suggestion')}")

    prev_errors = previous.get("source_errors") or {}
    for name, message in sorted((data.get("source_errors") or {}).items()):
        if prev_errors.get(name) == message:
            continue
        lines.append(f"- SOURCE {name} failed: {one_line(message, 180)}")
        lines.append("  The watch kept the previous snapshot for that source. Nothing was changed.")

    if not lines:
        return "", state
    header = f"Hermes security watch: {sum(1 for line in lines if line.startswith('- '))} new item(s). Nothing was changed.\n"
    return header + "\n".join(lines) + f"\n\nFull report: python3 {Path(__file__).resolve()} report\n", state


def render_report(data: dict, min_severity: str) -> str:
    hermes = data.get("hermes") or {}
    audit = data.get("audit") or {}
    findings = audit.get("findings") or []
    counts = audit_counts(findings)
    listed = [f for f in findings if meets(f.get("severity", ""), min_severity)]
    lines = [
        "# Hermes security report",
        "",
        "Read-only. Nothing was patched, configured, or rotated.",
        f"Generated: {data.get('generated_at')}",
        "",
        "## Summary",
        "",
        f"- Hermes: {hermes.get('version_line') or 'unknown'} — update status: {hermes.get('update_status')} {hermes.get('update_detail') or ''}".rstrip(),
        f"- Compromised-package hits: {len((data.get('compromised') or {}).get('hits') or [])}",
        f"- OSV findings: {len(findings)} (critical {counts.get('CRITICAL', 0)}, high {counts.get('HIGH', 0)}, moderate {counts.get('MODERATE', 0)}, low {counts.get('LOW', 0)}, unknown {counts.get('UNKNOWN', 0)})",
        f"- Published Hermes GitHub advisories: {len((data.get('advisories') or {}).get('items') or [])}",
        f"- Recent relevant CISA KEV entries: {len((data.get('kev') or {}).get('items') or [])}",
        f"- Posture findings: {sum(1 for item in data.get('posture') or [] if item.get('kind') == 'finding')}",
    ]
    distro = data.get("distro") or {}
    if distro.get("security") is not None:
        lines.append(f"- Distro security updates pending: {distro.get('security')} (total pending {distro.get('pending')})")
    if data.get("source_errors"):
        lines.append("- Degraded sources: " + ", ".join(sorted(data["source_errors"])))
    lines.extend(["", "## Act on these", ""])
    actions = _actions(data, listed)
    if not actions:
        lines.append("No act-now item from the sources that succeeded.")
    else:
        lines.extend(f"- {item}" for item in actions)
    lines.extend(["", f"## Supply chain at or above {min_severity}", ""])
    if not listed:
        lines.append("No findings at this threshold.")
    else:
        shown = listed[:40]
        for finding in shown:
            fixed = ", ".join(finding.get("fixed_in") or []) or "none listed"
            lines.append(
                f"- {finding['severity']} {finding['source']} {finding['package']}=={finding['version']} {finding['vuln_id']} — {finding['summary'] or 'no summary'} — fixed in: {fixed}"
            )
        if len(listed) > len(shown):
            lines.append(f"- {len(listed) - len(shown)} more at this threshold omitted")
        lines.append("")
        lines.append(venv_suggestion((data.get("hermes") or {}).get("update_status") or "unknown"))
    hidden = len(findings) - len(listed)
    if hidden:
        lines.append(f"{hidden} moderate/low/unknown finding(s) were counted above and not listed. Re-run with --min-severity moderate to list them.")
    lines.extend(["", "## Hermes published advisories", ""])
    advisories = (data.get("advisories") or {}).get("items") or []
    if not advisories:
        lines.append("No published GitHub security advisories for NousResearch/hermes-agent (or the feed was empty).")
    else:
        for item in advisories:
            lines.append(f"- {item.get('severity')} {item.get('id')} ({item.get('published')}) — {item.get('summary')} — {item.get('url')}")
        lines.append("Suggestion: read the advisory and update if your version is in range. Not applied.")
    lines.extend(["", "## Large-scale exploited vulns (CISA KEV, filtered)", ""])
    lines.append("These match a typical Hermes host stack (OpenSSH, OpenSSL, Python, container tools, and similar). They are not confirmed installed here. Names only — no exploit steps.")
    kev_items = (data.get("kev") or {}).get("items") or []
    if not kev_items:
        lines.append("No matching KEV entries in the lookback window.")
    else:
        for item in kev_items[:15]:
            lines.append(f"- {item['cve']} {item['vendor']} {item['product']} added {item['date_added']} — {item['name']}")
        lines.append("Suggestion: if the product is installed, patch via the vendor or distro. This report does not install packages.")
    lines.extend(["", "## Posture", ""])
    posture = data.get("posture") or []
    if not posture:
        lines.append("No posture findings or hardening suggestions from the checks that ran.")
    else:
        for item in posture:
            lines.append(f"- [{item.get('kind')}] {item.get('severity')} {item.get('profile')}: {item.get('title')}")
            lines.append(f"  {item.get('suggestion')}")
    lines.extend([
        "",
        "## What this did not do",
        "",
        "- Did not run `hermes update`, distro upgrades, or pip installs.",
        "- Did not edit config.yaml, .env, or sshd.",
        "- Did not print tokens, allowlist ids, or API keys.",
        "- Did not scan the whole host or the public internet for every CVE.",
        "- Did not include exploit steps, payloads, or reproduction detail.",
        "",
        "## Watch",
        "",
        f"python3 {Path(__file__).resolve()} baseline",
        f"python3 {Path(__file__).resolve()} watch",
        "Cron must call scripts/cron_watch.py with no arguments. On a CLI session, deliver the job to a gateway channel (deliver=all or telegram). origin delivery is not shown in this chat.",
        "",
    ])
    return "\n".join(lines)


def _actions(data: dict, listed: list[dict]) -> list[str]:
    actions: list[str] = []
    hermes = data.get("hermes") or {}
    if hermes.get("update_status") == "available":
        actions.append(f"Hermes is behind. Suggested, not applied: `hermes update` ({hermes.get('update_detail') or 'update available'}). That restarts the gateway.")
    for hit in (data.get("compromised") or {}).get("hits") or []:
        if hit.get("acked"):
            continue
        actions.append(f"Compromised package still installed: {hit.get('package')}=={hit.get('installed_version')} ({hit.get('id')}). Follow `hermes doctor` remediation. Not applied.")
    if listed:
        packages = sorted({f"{f['source']} {f['package']}=={f['version']}" for f in listed})
        actions.append(
            f"{len(listed)} OSV finding(s) at the report threshold across {len(packages)} component(s). "
            + venv_suggestion(hermes.get("update_status") or "unknown")
        )
    for item in data.get("posture") or []:
        if item.get("kind") == "finding" and item.get("severity") in {"high", "critical"}:
            actions.append(f"{item.get('title')}: {item.get('suggestion')}")
    distro = (data.get("distro") or {}) or {}
    if isinstance(distro.get("security"), int) and distro["security"] > 0:
        actions.append(f"{distro['security']} distro security update(s) pending. Review with the package manager. Not installed by this report.")
    return actions


def _source_error(name: str, exc: BaseException) -> str:
    return f"{name}: {one_line(exc, 180)}"


def collect_version() -> dict[str, str]:
    try:
        proc = run_cmd(["hermes", "--version"], 60)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"update_status": "unknown", "error": _source_error("version", exc)}
    info = parse_version_text(proc.stdout or "")
    if proc.returncode != 0 and not info["version_line"]:
        info["error"] = one_line(proc.stderr or proc.stdout or "hermes --version failed", 180)
    return info


def collect_audit() -> dict[str, Any]:
    try:
        proc = run_cmd(["hermes", "security", "audit", "--json", "--fail-on", "low"], 150)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"findings": [], "error": _source_error("audit", exc)}
    if proc.returncode not in (0, 1):
        return {"findings": [], "error": one_line(proc.stderr or proc.stdout or "audit failed", 180)}
    try:
        payload = parse_json_blob(proc.stdout or "")
    except (ValueError, json.JSONDecodeError) as exc:
        return {"findings": [], "error": _source_error("audit", exc)}
    if not isinstance(payload, dict):
        return {"findings": [], "error": "audit JSON was not an object"}
    return {
        "findings": normalize_audit(payload),
        "components": payload.get("total_components_scanned"),
        "error": None,
    }


def collect_compromised(install_dir: str, python: str | None) -> dict[str, Any]:
    if not python or not install_dir:
        return {"hits": [], "catalog": [], "error": "Hermes install python not found; skipped compromised-package catalog"}
    snippet = r"""
import json, sys
sys.path.insert(0, sys.argv[1])
from hermes_cli.security_advisories import ADVISORIES, detect_compromised, get_acked_ids
acked = set(get_acked_ids())
hits = []
for hit in detect_compromised():
    hits.append({
        "id": hit.advisory.id,
        "title": hit.advisory.title,
        "severity": hit.advisory.severity,
        "package": hit.package,
        "installed_version": hit.installed_version,
        "url": hit.advisory.url,
        "acked": hit.advisory.id in acked,
        "remediation": [step.replace("{hermes_home}", "$HERMES_HOME") for step in hit.advisory.remediation],
    })
catalog = [{"id": a.id, "title": a.title, "severity": a.severity, "published": a.published} for a in ADVISORIES]
print(json.dumps({"hits": hits, "catalog": catalog}))
"""
    try:
        proc = run_cmd([python, "-c", snippet, install_dir], 60)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"hits": [], "catalog": [], "error": _source_error("compromised", exc)}
    if proc.returncode != 0:
        return {"hits": [], "catalog": [], "error": "compromised catalog check failed"}
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return {"hits": [], "catalog": [], "error": "compromised catalog returned non-json"}
    return {"hits": payload.get("hits") or [], "catalog": payload.get("catalog") or [], "error": None}


def collect_advisories() -> dict[str, Any]:
    try:
        payload = json.loads(fetch_bytes(GHSA_URL, timeout=20).decode("utf-8", "replace"))
    except (OSError, urllib.error.URLError, TimeoutError, json.JSONDecodeError, RuntimeError) as exc:
        return {"items": [], "error": _source_error("hermes-advisories", exc)}
    if isinstance(payload, dict):
        return {"items": [], "error": one_line(payload.get("message") or "unexpected advisory payload", 180)}
    if not isinstance(payload, list):
        return {"items": [], "error": "unexpected advisory payload"}
    return {"items": [ghsa_public(item) for item in payload if isinstance(item, dict)], "error": None}


def collect_kev(today: date, lookback_days: int) -> dict[str, Any]:
    try:
        payload = json.loads(fetch_bytes(KEV_URL, timeout=30).decode("utf-8", "replace"))
    except (OSError, urllib.error.URLError, TimeoutError, json.JSONDecodeError, RuntimeError) as exc:
        return {"items": [], "error": _source_error("kev", exc)}
    if not isinstance(payload, dict):
        return {"items": [], "error": "unexpected KEV payload"}
    return {
        "items": filter_kev(payload, today, lookback_days),
        "catalog_version": payload.get("catalogVersion"),
        "error": None,
    }


def _read_capped(path: Path, limit: int = 1_000_000) -> str:
    data = path.read_bytes()[:limit]
    return data.decode("utf-8", "replace")


def collect_posture(home: Path, python: str | None) -> dict[str, Any]:
    paths = [("default", home / "config.yaml")]
    profiles = home / "profiles"
    if profiles.is_dir():
        for profile_dir in sorted(p for p in profiles.iterdir() if p.is_dir()):
            cfg_path = profile_dir / "config.yaml"
            if cfg_path.is_file():
                paths.append((profile_dir.name, cfg_path))
    subsets: dict[str, dict] = {}
    error = None
    existing = [(name, path) for name, path in paths if path.is_file()]
    if python and existing:
        snippet = r"""
import json, sys
from pathlib import Path
try:
    import yaml
except ImportError:
    print(json.dumps({"error": "no yaml"}))
    raise SystemExit(0)

def host_public(host):
    return isinstance(host, str) and host.strip().lower() not in {"127.0.0.1", "localhost", "::1"} and bool(host.strip())

def subset(cfg):
    if not isinstance(cfg, dict):
        return {}
    approvals = cfg.get("approvals") if isinstance(cfg.get("approvals"), dict) else {}
    security = cfg.get("security") if isinstance(cfg.get("security"), dict) else {}
    privacy = cfg.get("privacy") if isinstance(cfg.get("privacy"), dict) else {}
    gateway = cfg.get("gateway") if isinstance(cfg.get("gateway"), dict) else {}
    platforms = cfg.get("platforms") if isinstance(cfg.get("platforms"), dict) else {}
    api = platforms.get("api_server") if isinstance(platforms.get("api_server"), dict) else {}
    extra = api.get("extra") if isinstance(api.get("extra"), dict) else {}
    return {
        "approvals": {
            "mode": approvals.get("mode"),
            "cron_mode": approvals.get("cron_mode"),
            "single_query_mode": approvals.get("single_query_mode"),
            "unattended_mode": approvals.get("unattended_mode"),
        },
        "security": {
            "redact_secrets": security.get("redact_secrets"),
            "allow_private_urls": security.get("allow_private_urls"),
        },
        "privacy": {"redact_pii": privacy.get("redact_pii")},
        "allow_all_users": cfg.get("allow_all_users") is True or gateway.get("allow_all_users") is True,
        "api_server": {
            "enabled": api.get("enabled") is True,
            "host_public": host_public(extra.get("host")),
            "key_present": bool(str(extra.get("key") or "").strip()),
        },
    }

out = {}
for name, raw in json.loads(sys.stdin.read()):
    try:
        cfg = yaml.safe_load(Path(raw).read_text(encoding="utf-8"))
    except Exception:
        out[name] = {"error": "config parse failed"}
        continue
    out[name] = subset(cfg if isinstance(cfg, dict) else {})
print(json.dumps(out))
"""
        try:
            proc = subprocess.run(
                [python, "-c", snippet],
                input=json.dumps([[name, str(path)] for name, path in existing]),
                capture_output=True, text=True, timeout=60, check=False,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                parsed = json.loads(proc.stdout)
                if isinstance(parsed, dict) and parsed.get("error") == "no yaml":
                    error = "config posture skipped: PyYAML missing from Hermes python"
                elif isinstance(parsed, dict):
                    subsets = parsed
            else:
                error = "config posture skipped: parser failed"
        except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
            error = "config posture skipped: parser failed"
    else:
        error = "config posture skipped: Hermes python not found"
    findings: list[dict[str, str]] = []
    for name, _path in existing:
        cfg = subsets.get(name) or {}
        if cfg.get("error"):
            continue
        env_path = home / ".env" if name == "default" else home / "profiles" / name / ".env"
        policy = {"allow_all_users": [], "api_server_key_set": False, "api_server_enabled": False, "api_server_host_public": False}
        if env_path.is_file():
            try:
                policy = parse_env_policy(_read_capped(env_path))
            except OSError:
                policy = policy
        findings.extend(posture_findings(name, cfg, policy))
    return {"findings": findings, "error": error}


def collect_host() -> list[dict[str, str]]:
    ssh_state = "unknown"
    chunks = []
    ssh_path = Path("/etc/ssh/sshd_config")
    if ssh_path.is_file():
        try:
            chunks.append(_read_capped(ssh_path, 200_000))
        except OSError:
            chunks.append("")
    dropin = Path("/etc/ssh/sshd_config.d")
    if dropin.is_dir():
        for conf in sorted(dropin.glob("*.conf")):
            try:
                chunks.append(_read_capped(conf, 100_000))
            except OSError:
                continue
    if chunks:
        ssh_state = ssh_password_auth("\n".join(chunks))
    is_root = False
    getuid = getattr(os, "geteuid", None)
    if getuid is not None:
        try:
            is_root = getuid() == 0
        except OSError:
            is_root = False
    return host_findings(is_root, ssh_state)


def collect_distro() -> dict[str, Any] | None:
    binary = Path("/usr/lib/update-notifier/apt-check")
    if not binary.is_file():
        return None
    try:
        proc = run_cmd([str(binary)], 40)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"error": _source_error("distro", exc)}
    parsed = parse_apt_check((proc.stderr or "") + "\n" + (proc.stdout or ""))
    if not parsed:
        return {"error": "apt-check returned no count"}
    return parsed


def collect(lookback_days: int, today: date | None = None) -> dict[str, Any]:
    today = today or datetime.now(timezone.utc).date()
    version = collect_version()
    python = hermes_python(version.get("install_dir") or "")
    home = hermes_home()
    with ThreadPoolExecutor(max_workers=5) as pool:
        audit_f = pool.submit(collect_audit)
        comp_f = pool.submit(collect_compromised, version.get("install_dir") or "", python)
        adv_f = pool.submit(collect_advisories)
        kev_f = pool.submit(collect_kev, today, lookback_days)
        posture_f = pool.submit(collect_posture, home, python)
        audit = audit_f.result()
        compromised = comp_f.result()
        advisories = adv_f.result()
        kev = kev_f.result()
        posture = posture_f.result()
    errors = {}
    for name, payload in (
        ("version", version),
        ("audit", audit),
        ("compromised", compromised),
        ("advisories", advisories),
        ("kev", kev),
        ("posture", posture),
    ):
        if isinstance(payload, dict) and payload.get("error"):
            errors[name] = payload["error"]
    distro = collect_distro()
    if isinstance(distro, dict) and distro.get("error"):
        errors["distro"] = distro["error"]
    posture_items = list(posture.get("findings") or []) + collect_host()
    return {
        "generated_at": utc_now(),
        "hermes": version,
        "audit": audit,
        "compromised": compromised,
        "advisories": advisories,
        "kev": kev,
        "posture": posture_items,
        "distro": distro,
        "source_errors": errors,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Read-only Hermes security report and advisory watch")
    parser.add_argument("mode", nargs="?", default="report", choices=["report", "watch", "baseline"])
    parser.add_argument("--out", help="Write the report to this path (report mode)")
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON (report mode)")
    parser.add_argument("--state", help="Snapshot path (default: $HERMES_HOME/security-watch/state.json)")
    parser.add_argument("--min-severity", default="high", choices=["low", "moderate", "high", "critical"])
    parser.add_argument("--lookback-days", type=int, default=21)
    parser.add_argument("--heartbeat", action="store_true", help="Watch mode: print a one-line heartbeat when nothing is new")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.lookback_days < 1 or args.lookback_days > 365:
        print("lookback-days must be between 1 and 365", file=sys.stderr)
        return 2
    data = collect(args.lookback_days)
    state_path = Path(args.state) if args.state else default_state_path()
    if args.mode == "report":
        if args.json:
            text = json.dumps(data, indent=2, sort_keys=True)
        else:
            text = render_report(data, args.min_severity)
        if args.out:
            out = Path(args.out)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(text + ("\n" if not text.endswith("\n") else ""), encoding="utf-8")
            print(f"Wrote {out}")
        else:
            print(text)
        return 0
    previous = load_state(state_path)
    if args.mode == "baseline":
        state = snapshot_from(data, args.min_severity)
        try:
            save_state(state_path, state)
        except OSError as exc:
            print(f"could not save state: {one_line(exc)}", file=sys.stderr)
            return 1
        print(f"Baseline saved to {state_path}. Later watch runs alert only on new items. Nothing was changed.")
        return 0
    alert, state = decide_watch(data, previous, args.min_severity)
    try:
        save_state(state_path, state)
    except OSError as exc:
        print(f"could not save state: {one_line(exc)}", file=sys.stderr)
        return 1
    if alert:
        print(alert.rstrip())
    elif args.heartbeat:
        print("Hermes security watch: no new items.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
