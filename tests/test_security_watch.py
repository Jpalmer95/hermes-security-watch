#!/usr/bin/env python3
"""Stdlib tests for the read-only security watch. No network."""

from __future__ import annotations

import json
import sys
import unittest
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "skills" / "hermes-security-watch" / "scripts"))

import security_watch as sw  # noqa: E402


class EnvPolicyTests(unittest.TestCase):
    def test_never_returns_secret_values(self):
        text = "\n".join([
            "TELEGRAM_BOT_TOKEN=123456:secret-value",
            "API_SERVER_KEY=super-secret",
            "API_SERVER_HOST=0.0.0.0",
            "API_SERVER_ENABLED=true",
            "GATEWAY_ALLOW_ALL_USERS=true",
            "TELEGRAM_ALLOWED_USERS=111,222",
            "# comment TOKEN=not-a-real-key",
        ])
        policy = sw.parse_env_policy(text)
        blob = json.dumps(policy)
        self.assertNotIn("secret-value", blob)
        self.assertNotIn("super-secret", blob)
        self.assertNotIn("111,222", blob)
        self.assertIn("GATEWAY_ALLOW_ALL_USERS", policy["allow_all_users"])
        self.assertTrue(policy["api_server_key_set"])
        self.assertTrue(policy["api_server_host_public"])
        self.assertEqual(policy["platforms_with_token"], ["telegram"])


class PostureTests(unittest.TestCase):
    def test_off_approvals_are_findings_redaction_is_suggestion(self):
        findings = sw.posture_findings("default", {
            "approvals": {"mode": "off", "cron_mode": "approve"},
            "security": {"redact_secrets": False, "allow_private_urls": False},
            "allow_all_users": False,
            "api_server": {"enabled": False, "host_public": False, "key_present": False},
        }, {"allow_all_users": [], "api_server_enabled": False, "api_server_host_public": False, "api_server_key_set": False})
        by_id = {item["id"]: item for item in findings}
        self.assertEqual(by_id["default:approvals-off"]["kind"], "finding")
        self.assertEqual(by_id["default:redact-secrets"]["kind"], "suggestion")
        self.assertIn("not applied", by_id["default:approvals-off"]["suggestion"])
        self.assertNotIn("pip install", json.dumps(findings))

    def test_open_api_server_is_high(self):
        findings = sw.posture_findings("default", {
            "approvals": {"mode": "smart"},
            "security": {},
            "api_server": {"enabled": True, "host_public": True, "key_present": False},
        }, {})
        self.assertTrue(any(item["id"] == "default:api-server-open" for item in findings))


class FeedTests(unittest.TestCase):
    def test_kev_filter_drops_unrelated_and_attack_text(self):
        catalog = {"vulnerabilities": [
            {
                "cveID": "CVE-1", "vendorProject": "OpenSSL", "product": "OpenSSL",
                "dateAdded": "2026-10-20", "vulnerabilityName": "OpenSSL decoder bug",
                "shortDescription": "send this payload to exploit the decoder",
                "knownRansomwareCampaignUse": "Unknown",
            },
            {
                "cveID": "CVE-2", "vendorProject": "Arista", "product": "VeloCloud Orchestrator",
                "dateAdded": "2026-10-23", "vulnerabilityName": "unrelated",
                "shortDescription": "sql injection details",
            },
            {
                "cveID": "CVE-3", "vendorProject": "OpenSSH", "product": "OpenSSH",
                "dateAdded": "2025-01-01", "vulnerabilityName": "old",
            },
        ]}
        items = sw.filter_kev(catalog, date(2026, 10, 26), 21)
        self.assertEqual([item["cve"] for item in items], ["CVE-1"])
        self.assertNotIn("shortDescription", items[0])
        self.assertNotIn("payload", json.dumps(items))

    def test_version_parser(self):
        text = "\n".join([
            "Hermes Agent v0.22.5 (2026.9.24)",
            "Install directory: /tmp/hermes-agent",
            "Install method: git",
            "Update available: 2 commits behind — run 'hermes update'",
        ])
        info = sw.parse_version_text(text)
        self.assertEqual(info["install_dir"], "/tmp/hermes-agent")
        self.assertEqual(info["update_status"], "available")

    def test_audit_normalizes_medium_and_truncates(self):
        findings = sw.normalize_audit({"findings": [{
            "package": "urllib3", "version": "2.7.0", "source": "venv",
            "vuln_id": "GHSA-test", "severity": "MEDIUM",
            "summary": "line1\nline2 " + ("x" * 200),
            "fixed_versions": ["2.8.0", "2.8.1", "2.9.0", "2.9.1"],
        }]})
        self.assertEqual(findings[0]["severity"], "MODERATE")
        self.assertEqual(len(findings[0]["fixed_in"]), 3)
        self.assertLessEqual(len(findings[0]["summary"]), 140)
        self.assertNotIn("\n", findings[0]["summary"])

    def test_apt_check(self):
        self.assertEqual(sw.parse_apt_check("12;3\n"), {"pending": 12, "security": 3})


class WatchTests(unittest.TestCase):
    def _data(self):
        return {
            "generated_at": "2026-10-26T00:00:00+00:00",
            "hermes": {"update_status": "current", "update_detail": "Up to date", "version_line": "Hermes Agent v1"},
            "audit": {"findings": [{
                "package": "pyjwt", "version": "2.13.0", "source": "venv",
                "vuln_id": "GHSA-old", "severity": "HIGH", "summary": "auth bug", "fixed_in": ["2.15.0"],
            }, {
                "package": "idna", "version": "3.10", "source": "venv",
                "vuln_id": "GHSA-unk", "severity": "UNKNOWN", "summary": "unscored", "fixed_in": [],
            }], "error": None},
            "compromised": {"hits": [], "error": None},
            "advisories": {"items": [], "error": None},
            "kev": {"items": [], "error": None},
            "posture": [],
            "distro": {"security": 0, "pending": 1},
            "source_errors": {},
        }

    def test_first_watch_baselines_without_dumping_findings(self):
        alert, state = sw.decide_watch(self._data(), None, "high")
        self.assertIn("armed", alert)
        self.assertNotIn("GHSA-old", alert)
        self.assertEqual(state["osv_ids"], ["GHSA-old"])

    def test_second_watch_is_silent_until_a_new_high_appears(self):
        data = self._data()
        _, state = sw.decide_watch(data, None, "high")
        alert, _ = sw.decide_watch(data, state, "high")
        self.assertEqual(alert, "")
        data["audit"]["findings"].append({
            "package": "urllib3", "version": "2.7.0", "source": "venv",
            "vuln_id": "GHSA-new", "severity": "CRITICAL", "summary": "decoder bug", "fixed_in": ["2.8.0"],
        })
        alert, _ = sw.decide_watch(data, state, "high")
        self.assertIn("GHSA-new", alert)
        self.assertNotIn("GHSA-old", alert)
        self.assertIn("Do not pip-upgrade", alert)
        self.assertNotIn("pip install", alert)

    def test_report_omits_exploit_fields_and_says_not_applied(self):
        data = self._data()
        data["kev"] = {"items": [sw.kev_public({
            "cveID": "CVE-9", "vendorProject": "OpenSSL", "product": "OpenSSL",
            "dateAdded": "2026-10-20", "vulnerabilityName": "OpenSSL bug",
            "shortDescription": "exploit payload here",
        })]}
        text = sw.render_report(data, "high")
        self.assertIn("Nothing was patched", text)
        self.assertIn("current-release pins", text)
        self.assertNotIn("Suggested, not applied: `hermes update`", text)
        self.assertIn("unknown 1", text)
        self.assertNotIn("exploit payload", text)
        self.assertNotIn("shortDescription", text)


if __name__ == "__main__":
    unittest.main()
