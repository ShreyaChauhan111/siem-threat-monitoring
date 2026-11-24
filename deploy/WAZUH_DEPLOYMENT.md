# Production Deployment Guide: Wazuh SIEM

Wazuh is a free, open-source SIEM/XDR (manager + indexer + dashboard + agents). This guide follows the project plan phases.
Always take exact install commands from the current official docs: https://documentation.wazuh.com (the version in URLs changes).

## 1. Sizing (Phase 1)
- Pilot / lab (<100 endpoints): 1 node, 4 vCPU, 8-16 GB RAM, 100+ GB SSD.
- Production: separate manager, 3-node indexer cluster, dashboard; size disks from `EPS x avg event size x retention`.
- Estimate: GB/day = EPS x 86400 x ~400 bytes / 1e9; add 30-50% headroom.

## 2. Install (Phase 2)
Option A: all-in-one assisted installer (lab/pilot). Download the installer script and run it with the "all-in-one" option as shown in the official quickstart. It prints generated admin credentials at the end. Save them securely.

Option B: Docker single-node, using the official `wazuh-docker` repository (clone the release branch matching the current version, generate certificates with the provided compose file, then `docker compose up -d`).

Option C: distributed install for production, with step-by-step guides for indexer cluster, manager cluster, and dashboard.

After install:
- Change all default passwords and enable MFA/SSO for admins.
- Open ports only as needed: 1514/1515 (agents), 55000 (API), 9200 (indexer, internal), 443 (dashboard).
- Put the dashboard behind your VPN or reverse proxy with TLS.

## 3. Enroll agents (Phase 3)
Use the dashboard: Agents -> Deploy new agent. It generates an install command for Windows, Linux, or macOS with your manager address. Roll out in waves: domain controllers, servers, then workstations. For GPO/Intune/Ansible rollout, use the MSI/package from the same page.

Recommended extras:
- **Windows:** install Sysmon (SwiftOnSecurity or Olaf Hartong config) and collect `Microsoft-Windows-Sysmon/Operational`, PowerShell 4104, and Security logs.
- **Linux:** enable auditd and collect `/var/log/auth.log` or `/var/log/secure`.
- **Network devices:** forward syslog with `rsyslog-forward.conf` or point devices directly at the manager on UDP/TCP 514 (enable the `syslog` remote block in `ossec.conf`).
- **Cloud:** enable the AWS, Azure, Microsoft 365, and Google Cloud wodle modules.

## 4. Detection engineering (Phase 4)
1. Wazuh ships thousands of rules and MITRE/PCI/GDPR mappings. Review them in Dashboard -> Rules.
2. Add custom rules from `custom_wazuh_rules.xml` (this folder) to `/var/ossec/etc/rules/local_rules.xml` on the manager, then restart the manager. The sample rules mirror R001-R010 of the mini SIEM.
3. Add the threat-intel feed through CDB lists (`/var/ossec/etc/lists`), for example the contents of `data/blocklist.txt`.
4. Test rules with `/var/ossec/bin/wazuh-logtest` before enabling them.

## 5. Response (Phase 5)
- Enable **Active Response** for low-risk automatic actions (for example firewall-drop for brute-force sources, with an allowlist).
- Forward alerts to Slack/Teams/email via the integrations block, or ship to TheHive/Jira/ServiceNow for case management.

## 6. Validate (Phase 6)
- Run Atomic Red Team tests (T1110, T1059.001, T1070.001, T1098) on a test host and confirm each alert fires.
- Verify agent health: Dashboard -> Agents -> status "Active" for every enrolled host.
- Measure and record MTTD/MTTR, false-positive rate, and log-source coverage.

## 7. Operations
- Daily: review critical/high alerts and agent health.
- Weekly: tune noisy rules, review new log-source requests.
- Monthly: patch the manager/indexer/agents, review retention, test backups.
- Quarterly: purple-team exercise and ATT&CK coverage review.
