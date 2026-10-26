# Sources

All fetches are HTTPS GET. Failures are recorded as degraded sources. They are not treated as a clean bill of health.

| Source | What it answers | What it does not answer |
| --- | --- | --- |
| `hermes --version` | Install dir, method, whether Hermes itself is behind | Whether dependencies are patched |
| `hermes security audit --json --fail-on low` | Known vulns in the Hermes venv, plugin requirements, and pinned MCP servers, via OSV.dev | Global site-packages, distro packages, editor extensions |
| `hermes_cli.security_advisories` | Curated compromised releases (for example a poisoned PyPI version). Run with the Hermes venv Python so the check sees that environment | New CVEs that are not in the curated catalog |
| `GET https://api.github.com/repos/NousResearch/hermes-agent/security-advisories?state=published` | Published Hermes GitHub advisories | Unpublished reports. An empty list is normal |
| CISA KEV JSON feed | Exploited vulns added in the lookback window whose vendor/product matches OpenSSH, OpenSSL, sudo, glibc, Docker, containerd, Kubernetes, nginx, Python, Node, npm, systemd, curl, git, Linux kernel, or Hermes | Proof the product is installed. `shortDescription` is discarded so attack text never enters the report |
| Profile `config.yaml` plus `.env` key names | Approval mode, allow-all, redaction, private URLs, API server key presence | Secret values. The parser must not copy values into the report |
| `/usr/lib/update-notifier/apt-check` | Count of pending distro updates, including the security count | The package names, and it does not install them |

Snapshot file: `$HERMES_HOME/security-watch/state.json` (mode 0600). `report` does not write it. `baseline` and `watch` do.

Alert threshold defaults to high. Moderate and low OSV rows are counted in the report and omitted from the default list so a daily alert is not a firehose.
