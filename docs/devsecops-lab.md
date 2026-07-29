# DevSecOps Home Lab — Master Documentation

> **Purpose:** This document serves as the complete, replicable guide for building a home DevSecOps CI/CD pipeline integrating enterprise-grade security controls. It is written to be both a practical build guide and a reference for understanding the technology decisions made throughout. Sections that are planned but not yet completed are listed with descriptions only.

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Hardware](#2-hardware)
3. [Network Architecture — pfSense](#3-network-architecture--pfsense)
4. [pfSense Hardening](#4-pfsense-hardening)
5. [Ubuntu Server Hardening](#5-ubuntu-server-hardening)
6. [Docker Installation and Hardening](#6-docker-installation-and-hardening)
7. [Core Services — SonarQube and Minio](#7-core-services--sonarqube-and-minio)
8. [GitHub Repository and Self-Hosted Runner](#8-github-repository-and-self-hosted-runner)
   - [Reusable Workflow Architecture](#reusable-workflow-architecture)
   - [Onboarding a New Repository](#onboarding-a-new-repository)
9. [Sample Application](#9-sample-application)
10. [Pipeline — SAST with SonarQube](#10-pipeline--sast-with-sonarqube)
11. [Pipeline — Build and Trivy Scanning](#11-pipeline--build-and-trivy-scanning)
12. [Pipeline — Harbor Registry](#12-pipeline--harbor-registry)
13. [Pipeline — OWASP ZAP DAST](#13-pipeline--owasp-zap-dast)
14. [Pipeline — Dependency Scanning](#14-pipeline--dependency-scanning)
15. [Pipeline — Terraform and Minio Backend](#15-pipeline--terraform-and-minio-backend)
16. [Pipeline — Full Integration and Stage Gates](#16-pipeline--full-integration-and-stage-gates)
17. [Patch Management and Maintenance](#17-patch-management-and-maintenance)
18. [Kali Attack Box](#18-kali-attack-box)

---

## 1. Architecture Overview

### What We Are Building

A home CI/CD pipeline that mirrors enterprise DevSecOps practice. Code is pushed to GitHub, a self-hosted runner on an Ubuntu server executes the pipeline, and a suite of security tools automatically analyse the code, dependencies, and built artifacts at each stage. The goal is to produce a pipeline that can demonstrate real security control integration.

### Technology Stack

| Layer | Tool | Purpose |
|---|---|---|
| Source control | GitHub | Code hosting, pipeline orchestration |
| CI/CD runner | GitHub Actions (self-hosted) | Pipeline execution on local hardware |
| SAST | SonarQube Community | Static code analysis, quality gates |
| Image/IaC scanning | Trivy | CVE scanning of Docker images and IaC files |
| DAST | OWASP ZAP | Dynamic scanning of running application |
| SCA | OWASP Dependency-Check + Dependabot | Vulnerability scanning of dependencies |
| Container registry | Harbor | Local image storage and signing |
| Secrets management | HashiCorp Vault | Runtime secrets, no hardcoded credentials |
| IaC | Terraform | Infrastructure provisioning |
| State backend | Minio | S3-compatible Terraform state storage |
| Firewall/routing | pfSense | Network segmentation, VPN |
| OS | Ubuntu | Server hosting all lab services |

### Network Topology

```
ISP
 └── Home Router
       ├── Home PC
       └── pfSense WAN
             └── LAB Interface
                   ├── Ubuntu Server
                   └── Kali Box
```

---

## 2. Hardware

### Ubuntu Server (Primary Lab Box)

The server running all pipeline services. Spec requirements are driven by SonarQube (which embeds Elasticsearch) being the most memory-hungry service.

**Minimum recommended:**
- CPU: i5 8th gen or newer (6 cores preferred)
- RAM: 16GB DDR4
- Storage: 256GB SSD (500GB recommended)

**Current build:** Dell OptiPlex or equivalent SFF with Ubuntu installed clean.

### pfSense Box

Dedicated machine running pfSense CE. Any low-power x86 machine with two NICs works. A used SFF (Dell OptiPlex, HP EliteDesk) is sufficient.

### Home PC

Used for administration only — SSH into Ubuntu server, accessing service UIs via SSH tunnel, and GitHub. Does not run any lab services.

---

## 3. Network Architecture — pfSense

### Overview

pfSense is an open source firewall/router running on dedicated hardware. It sits between the home router and the lab subnet, providing network segmentation, firewall rules, VPN, DNS, DHCP, and NTP for all lab services.

**Why pfSense instead of a software firewall on Ubuntu?**
Dedicated network-layer firewall mirrors enterprise architecture (Fortinet, Palo Alto). Concepts learned here — stateful inspection, interface-based rules, policy-based routing — transfer directly to enterprise platforms. pfSense also provides the foundation for future VLANs.

### Interface Setup

| Interface | Subnet | Purpose |
|---|---|---|
| WAN | 192.168.1.0/24 | Connected to home router LAN |
| LAB (OPT1) | 192.168.3.0/24 | Lab infrastructure subnet |

### DHCP Configuration

DHCP server runs on the LAB interface only. Static DHCP mappings are configured by MAC address for all lab hosts — this means hosts get their IP via DHCP but always receive the same address. All IP assignments are managed centrally in pfSense rather than configured on individual hosts.

```
Ubuntu Server: 192.168.3.x (static DHCP mapping by MAC)
```

**Why static DHCP mappings instead of host-level static IPs?**
Centralised IP management mirrors enterprise IPAM (IP Address Management) practice. If a machine is rebuilt, it automatically receives the same IP without reconfiguration.

### VPN via WireGuard on pfSense

All outbound internet traffic from the LAB subnet routes through VPN. This is implemented as a WireGuard tunnel on pfSense using your preferred VPN's WireGuard configuration.

**Setup steps:**
1. Download WireGuard config from your VPN's website → Downloads → WireGuard configuration
2. Certain VPN providers may have a guide for pfSense and Wireguard. **Please follow that.**
3. pfSense → VPN → WireGuard → Add Tunnel → paste private key from config
4. Add server as peer with public key and endpoint from config
5. Assign tunnel as interface (xxxVPN)
6. Create gateway: System → Routing → Gateways → Add → Interface: xxxVPN
7. Add policy-based routing rule on LAB interface:

```
ALLOW  LAB subnet → !192.168.3.0/24 : any
Gateway: xxxVPN_GW
```

The `!` (not) operator means: all traffic from LAB that is NOT destined for the local lab subnet routes out through VPN. Local lab traffic stays internal.

**Kill switch:** Add a LAB interface block rule that activates when xxxVPN_GW is down — prevents traffic falling back to real WAN IP if VPN drops.

### DNS Configuration

pfSense runs Unbound as the DNS resolver for the lab. All lab hosts use 192.168.3.1 (pfSense LAB interface) as their DNS server.

**DNS over TLS** is enabled in Unbound, pointing upstream to Quad9 (9.9.9.9) — encrypts DNS queries leaving the network.

**Important:** Docker containers cannot reach 192.168.3.1 directly due to bridge network routing. See Section 6 for the Docker networking fix applied.

### Firewall Rules

**Key design principle:** Rules are written on the source interface. Rules on the LAB interface control traffic originating from lab hosts.

**WAN Interface:**
```
BLOCK  any → any (implicit deny — no inbound rules needed)
```
Note: Block private networks is DISABLED on WAN because pfSense's WAN interface sits on the home router's LAN (192.168.1.x) — enabling it would block the Home PC from reaching pfSense admin.

**LAB Interface:**
```
1. ALLOW  LAB → any : 443 TCP     (HTTPS — GitHub, Docker Hub, updates via VPN)
2. ALLOW  LAB → any : 80 TCP      (HTTP — apt repositories)
3. ALLOW  LAB → any : 123 UDP     (NTP)
4. ALLOW  LAB → LAB : any         (intra-lab communication)
5. BLOCK  LAB → 192.168.1.0/24   (prevent lateral movement to home network, logged)
6. BLOCK  LAB → any               (catch-all, logged)
```

**RFC1918 East-West Blocking (Rule 5):**
RFC1918 refers to private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16). East-west traffic means lateral movement between internal segments. Rule 5 prevents anything on the lab network from reaching the home PC subnet — a core zero trust principle. If a lab service is compromised it cannot pivot to the home network.

### NTP

pfSense acts as the NTP server for the lab (Services → NTP, bound to LAB interface only). Lab hosts sync time from 192.168.3.1. Accurate time is critical for TLS certificates, log correlation, and matching attack timestamps with server logs in security exercises.

---

## 4. pfSense Hardening

### Admin Interface

```
System → Advanced → Admin Access:
  Protocol: HTTPS only
  TCP Port: 8443 (changed from default 443)
  Max Processes: 2
  Login Protection: Enabled
  HTTP Strict Transport Security: Enabled
```

Default admin account is disabled. A non-default admin user is created and used for all access.

### SSH

SSH on pfSense itself is disabled — console access via monitor/keyboard is used for emergency recovery instead. This eliminates an attack surface entirely.

### WAN Hardening

```
Block bogon networks: ENABLED (blocks unallocated/reserved IP space)
Block private networks: DISABLED (see Section 3 — WAN is on private network)
UPnP: DISABLED
SNMP: DISABLED
```

**Why disable UPnP?**
UPnP allows devices to automatically open firewall ports without administrator knowledge. Malware exploits this. There is no legitimate use case for it in a controlled lab environment.

### Internal PKI

A self-signed Certificate Authority is created in pfSense (System → Certificate Manager → CAs) and used to sign pfSense's web interface certificate. The CA is imported into the Windows trusted root store on the Home PC — eliminating browser certificate warnings and establishing a basic internal PKI, which mirrors enterprise certificate management practice.

### Logging

All BLOCK rules have logging enabled. Logs are reviewed periodically to understand traffic patterns and identify anomalies. Remote syslog to the Ubuntu server (Splunk) [future functionality].

### Configuration Backup

pfSense config is exported as XML after every significant change (Diagnostics → Backup & Restore → Download). This is the equivalent of infrastructure-as-code for pfSense — the entire firewall configuration can be restored from this file in minutes.

### Lessons Learned During Setup

**KeaDHCP interface validation:** pfSense migrated from ISC DHCP to Kea DHCP. Unlike ISC DHCP, Kea refuses to start if any interface it is configured for does not physically exist. If DHCP stops working after a config change, check Services → DHCP Server and disable DHCP on any interface tabs that don't correspond to physical interfaces.

**Block private networks on WAN:** This setting is appropriate when pfSense's WAN faces the public internet directly. When pfSense sits behind a home router (double NAT), its WAN interface has a private IP — enabling this setting will block the Home PC from reaching pfSense admin entirely. Always confirm your topology before enabling.

**Console access bypasses all network rules:** Physical keyboard and monitor access to the pfSense box gives direct OS access regardless of firewall rules, locked ports, or changed admin passwords. This is intentional (recovery mechanism) but means physical security of the pfSense box is important. The same principle applies to all network devices — Cisco, Fortinet, Palo Alto all have out-of-band console access for this reason.

---

## 5. Ubuntu Server Hardening

### System Updates

```bash
sudo apt update && sudo apt upgrade -y
sudo apt autoremove -y
```

**Unattended security upgrades** configured to automatically apply security patches only — not full upgrades, which can break service dependencies:

```
# /etc/apt/apt.conf.d/50unattended-upgrades
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
};
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
```

Automatic reboot is disabled — reboots are performed manually to avoid disrupting running services (azan.service, Docker containers).

### SSH Hardening

SSH is the primary access method from the Home PC. Key-based authentication only — password authentication is disabled.

**Key generation on Home PC (Windows PowerShell):**
```powershell
ssh-keygen -t ed25519 -C "homepc-to-ubuntu"
type $env:USERPROFILE\.ssh\id_ed25519.pub | ssh yourusername@192.168.3.x "mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys"
```

**`/etc/ssh/sshd_config` changes:**
```
Port 2222
PermitRootLogin no
PasswordAuthentication no
AllowUsers yourusername
PermitEmptyPasswords no
X11Forwarding no
LoginGraceTime 30
MaxAuthTries 3
KerberosAuthentication no
GSSAPIAuthentication no
```

**Always test SSH in a second terminal before restarting sshd.** Closing the only session before confirming the new config works will lock you out and require physical console access.

**SSH tunnel for accessing services:** Since Docker services are bound to 127.0.0.1 (localhost only), they are accessed from the Home PC via SSH port forwarding:

```powershell
ssh -i $env:USERPROFILE\.ssh\id_ed25519 -p 2222 `
  -L 9100:127.0.0.1:9100 `
  -L 9201:127.0.0.1:9201 `
  -L 9200:127.0.0.1:9200 `
  yourusername@192.168.3.x -N
```

This is more secure than opening ports in UFW — nothing is exposed on the network, services are only accessible through an authenticated SSH session.

### Fail2Ban

Fail2Ban monitors auth logs and bans IPs after repeated failed authentication attempts.

```bash
sudo apt install fail2ban -y
sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
```

**Why edit jail.local and not jail.conf?**
`jail.conf` is overwritten by package updates. `jail.local` is never touched by updates and takes precedence over `jail.conf` at runtime — it is the correct override mechanism. This pattern (`.local` or `.d/` overrides) is common across Linux services.

`/etc/fail2ban/jail.local` sshd section:
```ini
[sshd]
enabled = true
port    = 2222
filter  = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 1h
findtime = 10m
```

Note: Do not include `backend = %(sshd_backend)` in jail.local — this variable exists in jail.conf context but causes a bad interpolation error when referenced in jail.local.

### UFW Firewall

UFW (Uncomplicated Firewall) provides host-level firewall rules on Ubuntu, complementing pfSense. This is defence in depth — two independent firewall layers.

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 2222/tcp   # SSH
sudo ufw allow 9100/tcp   # SonarQube
sudo ufw allow 9200/tcp   # Minio API
sudo ufw allow 9201/tcp   # Minio Console
sudo ufw allow 8080/tcp   # App staging
sudo ufw enable
```

**`DEFAULT_FORWARD_POLICY`:** Changed from `DROP` to `ACCEPT` in `/etc/default/ufw`. This is required for Docker container networking — UFW drops forwarded packets by default which prevents containers from reaching the internet. This was discovered during Docker networking troubleshooting.

### Kernel Hardening

`/etc/sysctl.d/99-hardening.conf`:
```bash
net.ipv4.ip_forward = 1                        # required for Docker networking
net.ipv4.conf.all.accept_source_route = 0      # disable source routing
net.ipv4.conf.all.accept_redirects = 0         # disable ICMP redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.tcp_syncookies = 1                    # SYN flood protection
net.ipv4.conf.all.log_martians = 1             # log suspicious packets
net.ipv6.conf.all.disable_ipv6 = 1            # IPv6 disabled (not in use)
vm.max_map_count = 262144                      # required for SonarQube/Elasticsearch
```

Note: `ip_forward = 1` is required for Docker to forward packets between container bridge networks and the host's network interfaces. Initially commented out — this was corrected during Docker networking troubleshooting.

### Audit Logging

`auditd` tracks changes to sensitive files and failed access attempts. These logs feed into Splunk SIEM (future functionality).

```bash
sudo apt install auditd -y
```

`/etc/audit/rules.d/hardening.rules`:
```bash
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/sudoers -p wa -k sudoers
-w /etc/ssh/sshd_config -p wa -k sshd
-a always,exit -F arch=b64 -S open -F exit=-EACCES -k access
```

---

## 6. Docker Installation and Hardening

### Why Docker

All pipeline security tools (SonarQube, Minio, Harbor, ZAP) run as Docker containers. This provides isolation between services, consistent environments, easy version management, and mirrors how these tools are deployed in enterprise environments.

### Installation

```bash
# Remove old versions
sudo apt remove docker docker-engine docker.io containerd runc -y

# Add Docker's official GPG key and repository
sudo apt install ca-certificates curl gnupg lsb-release -y
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# Install
sudo apt update
sudo apt install docker-ce docker-ce-cli containerd.io docker-compose-plugin -y

# Add user to docker group
sudo usermod -aG docker $USER
sudo systemctl enable docker
```

### Docker Hardening

**`/etc/docker/daemon.json`:**
```json
{
  "iptables": false,
  "dns": ["9.9.9.9", "1.1.1.1"],
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  },
  "no-new-privileges": true,
  "live-restore": true
}
```

**`iptables: false`** — stops Docker from writing its own iptables rules which would bypass UFW. Docker's default behaviour is to punch holes in your firewall silently. Disabling this means we manage routing manually but have full control and visibility.

**`dns`** — explicit DNS servers for containers. Set to public DNS (9.9.9.9, 1.1.1.1) after discovering containers cannot reach pfSense at 192.168.3.1 from the Docker bridge networks due to routing. pfSense DNS is used by the host; containers use public DNS. All traffic still routes through VPN on pfSense.

**`no-new-privileges: true`** — prevents processes inside containers from gaining additional privileges via setuid binaries.

**`live-restore: true`** — containers keep running if the Docker daemon restarts or crashes. Critical for keeping services like SonarQube up during daemon updates.

**`log-driver + log-opts`** — without log rotation Docker will fill your disk. Each container is limited to 3 files of 10MB each.

### UFW and Docker Conflict Resolution

Docker and UFW conflict by default. Docker writes directly to iptables, bypassing UFW rules. The fix involves three parts:

**1. `/etc/ufw/after.rules` — add at the end:**
```bash
# DOCKER-USER chain — drop unsolicited inbound on main interface
*filter
:DOCKER-USER - [0:0]
-A DOCKER-USER -i enp2s0 -j DROP
COMMIT

# NAT masquerade for container outbound traffic
*nat
:POSTROUTING ACCEPT [0:0]
-A POSTROUTING -s 172.17.0.0/16 ! -o docker0 -j MASQUERADE
-A POSTROUTING -s 172.18.0.0/16 ! -o lab-br0 -j MASQUERADE
-A POSTROUTING -s 172.17.0.0/16 -d 192.168.3.0/24 -j MASQUERADE
-A POSTROUTING -s 172.18.0.0/16 -d 192.168.3.0/24 -j MASQUERADE
COMMIT
```

**Important:** Each iptables table (`*filter`, `*nat`) must have its own `COMMIT` statement. Mixing tables or having two `*filter` blocks causes UFW to fail on reload.

**2. `/etc/default/ufw`:**
```
DEFAULT_FORWARD_POLICY="ACCEPT"
```

**3. `/etc/sysctl.d/99-hardening.conf`:**
```
net.ipv4.ip_forward = 1
```

All three changes are required together. Missing any one will break container networking.

### userns-remap — Decision

`userns-remap` was initially added to daemon.json as a security hardening measure. It remaps container UIDs to unprivileged host UIDs (offset by 100000), so a container running as root maps to an unprivileged user on the host.

**It was removed** because SonarQube manages its own internal user and is incompatible with forced userns-remap — it caused persistent `Permission denied` errors on volume mounts that were not worth the complexity to resolve. The other hardening measures (`no-new-privileges`, `cap_drop`, `iptables: false`) provide sufficient protection without it.

**Lesson:** Security hardening has diminishing returns and compatibility costs. Understand what each control actually protects against before adding it.

### Docker Compose Structure

All services are defined in `~/lab/docker-compose.yml`. Each service uses:
- Pinned image versions (never `latest`)
- `restart: unless-stopped` for persistence across reboots
- Ports bound to `127.0.0.1` only (not `0.0.0.0`)
- `no-new-privileges: true`
- `cap_drop: ALL` with only required capabilities added back
- Log rotation configured per container
- No Docker socket mounts (except Trivy — see Section 11)

**Directory structure:**
```
~/lab/
├── docker-compose.yml
├── sonarqube/
│   ├── data/
│   ├── logs/
│   └── extensions/
├── minio/
│   └── data/
├── harbor/          (planned)
├── zap/             (planned)
└── scripts/
    └── update-services.sh
```

### Patch Management Script

`~/lab/scripts/update-services.sh` — run monthly after reviewing release notes for each service. Never auto-update service containers — breaking changes in SonarQube, Harbor, or Minio can silently break the pipeline.

---

## 7. Core Services — SonarQube and Minio

### SonarQube

**What it is:** An open source platform for continuous code quality and security inspection. It performs SAST (Static Application Security Testing) — analysing source code without running it, looking for bugs, vulnerabilities, code smells, and security hotspots.

**Why SonarQube specifically:** Industry standard tool. SonarQube Community Edition is free and functionally equivalent to the paid versions for learning purposes. The quality gate concept, SARIF output, and GitHub integration are directly transferable to enterprise environments.

**Port:** 9100 (moved from default 9000 — conflict with existing service)

**SonarQube vs Issues vs Security Hotspots:**
- **Issues** — definite problems SonarQube is confident about (bugs, vulnerabilities). Pipeline fails on these if quality gate is configured to do so.
- **Security Hotspots** — suspicious code that requires human review. SonarQube flags it but a developer must confirm whether it is actually a risk. Hardcoded credentials appear here.

**Prerequisite — vm.max_map_count:**
SonarQube embeds Elasticsearch which requires a higher virtual memory limit than Ubuntu's default:
```bash
# /etc/sysctl.d/99-hardening.conf
vm.max_map_count = 262144
```
Without this, Elasticsearch silently exits with code 1 and SonarQube never fully starts. This is one of the most common SonarQube deployment failures.

**Docker Compose config (relevant sections):**
```yaml
sonarqube:
  image: sonarqube:10.4-community
  ports:
    - "127.0.0.1:9100:9000"
  environment:
    - SONAR_ES_BOOTSTRAP_CHECKS_DISABLE=true
  volumes:
    - ./sonarqube/data:/opt/sonarqube/data
    - ./sonarqube/logs:/opt/sonarqube/logs
    - ./sonarqube/extensions:/opt/sonarqube/extensions
```

**First login:** `admin / admin` — change immediately on first access.

**Generate pipeline token:**
```
SonarQube UI → My Account → Security → Generate Token
Type: Global Analysis Token
Name: github-actions
```
Store in GitHub Secrets as `SONAR_TOKEN`.

### Minio

**What it is:** An open source S3-compatible object storage server. In this lab it serves as the Terraform state backend — storing Terraform's state files the same way AWS S3 would in a cloud environment.

**Why Minio:** Terraform requires a remote state backend in any real-world usage. Using Minio locally teaches the exact same concepts as S3 (bucket creation, access keys, state locking) without requiring a cloud account.

**Ports:** 9200 (API), 9201 (Console UI)

**Setup after first login:**
1. Create bucket: `terraform-state`
2. Create access key — save both Access Key and Secret Key for Terraform configuration

---

## 8. GitHub Repository and Self-Hosted Runner

### Why a Self-Hosted Runner

GitHub Actions provides hosted runners (GitHub's own machines) for free. Enterprise environments almost universally use self-hosted runners instead for several reasons: security (build artifacts and secrets never leave your network), performance (your hardware, not shared), access to internal services (the runner can reach SonarQube at 127.0.0.1:9100 because it runs on the same machine), and cost (no minutes limit).

### Repository Setup

```
github.com → New repository
Name: devsecops-lab
Visibility: Public (required for GitHub Advanced Security — Security tab, SARIF upload; otherwise private is fine)
```


**Why public?** GitHub Advanced Security features (Security tab, code scanning, SARIF upload) are only available on public repos for personal accounts, or on Organisation accounts with a paid plan. Making the repo public unlocks these features at no cost. All sensitive values are in GitHub Secrets — never in code — so making it public is safe.

### Organization Migration

The lab started on a personal GitHub account with the runner registered directly to `devsecops-lab`. That model stops working the moment a second repo needs the same runner: **self-hosted runners registered at the repository level can only run jobs from that one repository** — a personal account has no umbrella scope that lets several of its repos share a runner. GitHub's only mechanism for one physical runner to serve many repos automatically is an **Organization-level runner group**.

Steps:
1. Convert the personal account to an Organization (GitHub Settings → "Organizations" → "Turn [account] into an organization"), or create a fresh Organization and transfer `devsecops-lab` (and future repos) into it.
2. Organization Settings → Actions → Runner groups → create (or use the default) group, and grant it access to the repositories that should be able to dispatch to the runner — select "All repositories" if every repo created going forward should automatically be covered, or "Selected repositories" and add each one explicitly.
3. Re-register the physical runner against the **organization**, not the repository (see "Runner Installation" below) — this replaces the existing repo-scoped registration.
4. Move `SONAR_TOKEN` / `SONAR_HOST_URL` / (optional) `NVD_API_KEY` to **Organization secrets** (see "GitHub Secrets" below) and the Actions allowlist/SHA-pin policy to **Organization Settings → Actions → General** (see "Actions Permissions Hardening" below) — both are one-time, org-wide instead of per-repo.
5. **Token consequence**: any fine-grained PAT minted against the personal account (including the coding agent's own token — see `docs/Isolated-Coding-Agent-User.md`, Section 5) is bound to that resource owner at creation time and will not resolve to a repo once it's owned by the org. A new fine-grained PAT with resource owner = the org, scoped to the relevant repos, must be generated and (depending on org policy) approved by an org admin under Organization Settings → Personal access tokens → Settings before it's usable.

### SSH Authentication for Git

GitHub removed password authentication for git operations. SSH key authentication is required.

```bash
# Generate dedicated key for GitHub on Ubuntu
ssh-keygen -t ed25519 -C "ubuntu-server-github" -f ~/.ssh/github_ed25519

# Add public key to GitHub: Settings → SSH keys → New SSH key
cat ~/.ssh/github_ed25519.pub

# Configure SSH to use this key for GitHub
# ~/.ssh/config
Host github.com
  HostName github.com
  User git
  IdentityFile ~/.ssh/github_ed25519
  IdentitiesOnly yes
```

Clone using SSH (not HTTPS):
```bash
git clone git@github.com:yourgithubusername/devsecops-lab.git
```

### Runner Installation

Register at the **organization** level so the runner is available to every repo the runner group covers, not just one:

```
github.com/organizations/<org-name> → Settings → Actions → Runners → New runner → Linux x64
```

(Before the org migration this pointed at `GitHub repo → Settings → Actions → Runners` instead — that repo-scoped path only ever registers the runner to a single repository and should no longer be used.)

Follow the generated commands to download and configure the runner. **Do not run `./run.sh`** — this runs the runner interactively in the foreground and dies when the terminal closes. Install as a systemd service instead:

```bash
# Must be run from inside the runner directory
cd /home/github-runner/actions-runner
sudo ./svc.sh install github-runner
sudo ./svc.sh start
sudo systemctl status actions.runner.<org-name>.*
```

**Runner labels:** `self-hosted, linux, lab`. Workflows no longer hardcode `runs-on: self-hosted` — the reusable workflow (`security-scan.yml`) takes a `runner_labels` input (default `["self-hosted","linux","lab"]`) so the label set is a single, callable-configurable point rather than duplicated across every caller repo's own workflow file.

### Dedicated Runner User

The runner must not run as your primary user which has sudo access. A dedicated low-privilege user is created:

```bash
# Create dedicated runner user
sudo useradd -m -s /bin/bash github-runner

# Add to docker group only — no sudo
sudo usermod -aG docker github-runner
```

The runner is then installed and runs as `github-runner`. This means if a malicious pipeline job executes on the runner it cannot escalate privileges, cannot access your SSH keys, and cannot sudo. It can only interact with Docker.

**Note on installation:** `svc.sh install` must be run from inside the runner directory. Running it from any other path produces `Failed: Must run from runner root`. The workaround when the runner directory is owned by `github-runner`:

```bash
# Temporarily grant passwordless sudo to github-runner
sudo visudo -f /etc/sudoers.d/github-runner-temp
# Add: github-runner ALL=(ALL) NOPASSWD: ALL

# Run install
sudo -u github-runner bash -c "cd /home/github-runner/actions-runner && sudo ./svc.sh install github-runner"

# Immediately remove temporary sudo
sudo rm /etc/sudoers.d/github-runner-temp
```

### Systemd Hardening for Runner Service

```bash
sudo systemctl edit actions.runner.yourgithubusername-devsecops-lab.*
```

Add under `[Service]`:
```ini
NoNewPrivileges=true
PrivateTmp=true
```

```bash
sudo systemctl daemon-reload
sudo systemctl restart actions.runner.*


### `.github` Directory

The `.github` directory is a special convention GitHub recognises automatically. It is a hidden directory (dot prefix) in the repo root:

```
.github/
├── workflows/         # Pipeline YAML files — scanned automatically on push
├── dependabot.yml     # Dependabot configuration
└── CODEOWNERS         # Review requirements
```

Any `.yml` file in `.github/workflows/` is automatically treated as a pipeline definition. No additional configuration is needed.

### GitHub Secrets

Sensitive values used in the pipeline are stored as **Organization secrets** (Organization Settings → Secrets and variables → Actions, not per-repo) so that every repo the runner group covers gets them automatically, with no per-repo secret configuration. Set visibility to "All repositories" for zero-touch onboarding, or "Selected repositories" and add each new repo to the list as it's created. They are injected into pipeline steps as environment variables and never appear in logs.

| Secret | Value | Used by |
|---|---|---|
| SONAR_TOKEN | SonarQube analysis token | SonarQube scan job (`sast`) |
| SONAR_HOST_URL | http://127.0.0.1:9100 | SonarQube scan job (`sast`) |
| NVD_API_KEY | Free NVD API key (optional) | Dependency-Check job (`dependency-check`) — raises the NVD lookup rate limit from 5 to 50 requests/30s; the job runs without it, just slower on a cold cache |

Every caller workflow (this repo's `pipeline.yml` and every other repo's `security.yml`) passes these through with an **explicit named mapping** (`secrets: { SONAR_TOKEN: ..., SONAR_HOST_URL: ..., NVD_API_KEY: ... }`), not `secrets: inherit`. `inherit` can't grant access beyond what the caller already has, but it would forward *every* secret the caller repo holds into every step of the shared workflow — explicit mapping keeps `security-scan.yml`'s blast radius to exactly these three, regardless of what unrelated secrets a given repo happens to also store.

---


### Actions Permissions Hardening (Public Repo)

With a public repo, anyone can fork it and open a pull request. Without restrictions, a malicious PR could execute arbitrary code on your self-hosted runner. Post-org-migration, configure this **once, org-wide**, instead of per-repo:

```
Organization Settings → Actions → General
```

**Actions permissions:**
```
Select: "Allow <org-name>, and select non-<org-name> actions and reusable workflows"
Tick: "Allow actions created by GitHub"
Tick: "Require actions to be pinned to a full-length commit SHA"
```

Add explicit allowlist for third-party actions and reusable workflows used in the pipeline:
```
SonarSource/sonarqube-scan-action
sonarsource/sonarqube-scan-action
actions/*
aquasec/*
github/codeql-action
<org-name>/devsecops-lab/.github/workflows/security-scan.yml@*
```

Note: GitHub normalises action names to lowercase internally. Adding both `SonarSource/` and `sonarsource/` variants avoids case-sensitivity matching failures. The last entry is required for other repos to be permitted to call `security-scan.yml` at all — without it, this org-wide allowlist would block the entire reusable-workflow mechanism this document is about.

**Reusable workflow "Access" setting — do not skip this check.** `devsecops-lab`'s own repo (or org-level equivalent) Settings → Actions → General → **Access** controls which other repositories may reference *its* reusable workflows and actions. This has never mattered while the repo was public (public reusable workflows are inherently callable by anyone), but confirm it explicitly once the repo lives in the org — especially if org policy defaults new/transferred repos to private. If `Access` is set to "Not accessible," every other repo's `uses: <org>/devsecops-lab/.github/workflows/security-scan.yml@...` call fails outright, silently defeating the whole design. Set it to "Accessible from repositories in the organization" (or keep the repo public, which sidesteps the setting) once the migration is done.

**Fork pull request workflows:**
```
"Run workflows from fork pull requests" → UNCHECKED
```
This prevents external contributors' PRs from triggering pipeline execution on your runner without your approval.

**Workflow permissions:**
```
Read repository contents and packages permissions (read-only)
Allow GitHub Actions to create and approve pull requests → UNCHECKED
Access → Not accessible
```

### Action SHA Pinning

**Why pin to SHA instead of tags?**

Tags like `@v4` or `@master` are moveable — a publisher can silently reassign a tag to a completely different commit. If their account is compromised, malicious code could be pushed under an existing tag and every pipeline using that tag runs it automatically.

A commit SHA is permanent and immutable — it can never be reassigned:

```yaml
# Unsafe — tag can be moved
uses: actions/checkout@v4

# Safe — SHA is immutable
uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
```

**Finding SHAs:** Go to the action's GitHub repository → Tags → find the release version → click it → copy the full 40-character commit SHA.

**This is enforced** by the "Require actions to be pinned to a full-length commit SHA" setting — the pipeline will fail if any action reference uses a tag or branch instead of a full SHA.

**SHAs are not your commits** — they are commits in the action's own repository. You only update them when you deliberately want to upgrade the action version, not on every push.

**Open risk — SHA pinning vs. tag-pinned reusable workflow calls.** The "require actions to be pinned to a full-length commit SHA" org policy above applies uniformly to any `uses:` reference — including `jobs.<job>.uses:` reusable-workflow calls, not just individual actions. The chosen versioning scheme for `security-scan.yml` (see "Reusable Workflow Architecture" below) has callers reference a moving tag like `@v1` rather than a raw SHA, specifically so routine fixes to the shared workflow don't require touching every calling repo. **Before cutting the first tag, verify in the org's actual policy UI whether a tag reference is accepted for a reusable-workflow `uses:` line once this setting is enabled** — there is no documented per-item exception for the pin-to-SHA requirement as of this writing. If tags are rejected, the fallback is to pin every caller to the literal commit SHA of `security-scan.yml` instead, with the SHA recorded in this doc's changelog table and bumped deliberately across all callers on every update — more manual work, but it's the safe default if the assumption above doesn't hold.

### Workflow Permissions for Security Tab

The pipeline requires explicit permission to upload SARIF results to the GitHub Security tab:

```yaml
# At the top level of the workflow file, after the on: block
permissions:
  contents: read
  security-events: write
  actions: read
```

Without `security-events: write` the GITHUB_TOKEN does not have sufficient scope to write to the Security tab even on a public repo.

### CODEOWNERS

```bash
# .github/CODEOWNERS
* @yourgithubusername
.github/workflows/ @yourgithubusername
```

Any change to pipeline files requires your explicit review. Nobody can merge a workflow change without your approval.

### Reusable Workflow Architecture

The scanning logic lives once, in `devsecops-lab`'s `.github/workflows/security-scan.yml`, declared with `on: workflow_call`. `devsecops-lab` itself calls it locally (`.github/workflows/pipeline.yml`, `uses: ./.github/workflows/security-scan.yml`) to scan its own vulnerable app on every push — this doubles as the integration test for any change to the shared workflow before a new version is cut. Every other repo calls the same file remotely (`uses: <org>/devsecops-lab/.github/workflows/security-scan.yml@v1`).

**Job graph:**
```
sast              dependency-check          build
(independent)     (independent)             (runs if enable_build_scan or enable_dast)
                                                  │
                                                  ▼
                                                dast (needs: build)
                                                  │
            cleanup (needs: [build, dast], if: always())
```
`sast` is intentionally decoupled from `build` — a SonarQube outage shouldn't block Trivy, Dependency-Check, or ZAP from running and reporting. Because the whole org shares one physical runner, "independent" jobs still execute one at a time in practice; the graph exists for correctness and `if: always()` semantics, not wall-clock parallelism. If queuing becomes a real bottleneck across many repos, the option is a second runner process registered under the same label group on the same box — note the Dependency-Check NVD cache volume below would then need per-runner scoping to avoid concurrent-write issues.

| Job | What it does | Report destination |
|---|---|---|
| `sast` | SonarQube static analysis against the caller's `sonar-project.properties` | SonarQube's own UI/quality gate |
| `dependency-check` | OWASP Dependency-Check SCA scan of the checked-out repo, using a shared, globally-named NVD cache Docker volume (persistent runner ⇒ every repo benefits from a warm cache) | Security tab (SARIF, category `dependency-check`) + HTML artifact |
| `build` | `docker build` from the caller's Dockerfile, then Trivy scans of the built image and the filesystem | Security tab (SARIF, categories `trivy-image` / `trivy-fs`) |
| `dast` | Runs the built image on an auto-assigned host port, waits for a health check, then an OWASP ZAP baseline scan against it | Build artifact only (HTML/JSON/MD) — ZAP's baseline script has no native SARIF output and there's no vetted, SHA-pinnable converter that fits the current allowlist model; wiring SARIF for ZAP is a documented v1.1 follow-up, not done in v1 |
| `cleanup` | Removes any container labelled `devsecops=ephemeral` and prunes images older than 24h, regardless of what else failed | — (runner hygiene; self-hosted runners aren't ephemeral like GitHub-hosted ones, so nothing tears itself down automatically) |

**Inputs** (`workflow_call` inputs must default to literals, never expressions): `image_name` (default `""`, falls back to the repo name), `app_context` (default `"."`), `app_port` (required), `zap_target_path` / `health_check_path` (default `"/"`), `health_check_timeout_seconds` (default `60`), `dependency_check_project_name` (default `""`, falls back to `owner/repo`), `runner_labels` (default `["self-hosted","linux","lab"]`, parsed via `fromJSON()`), and four `enable_*` booleans (all default `true`) to skip individual jobs. **Secrets**: `SONAR_TOKEN` / `SONAR_HOST_URL` (required), `NVD_API_KEY` (optional) — see "GitHub Secrets" above for why callers map these by name instead of using `secrets: inherit`.

**Caller contract**: a repo calling `security-scan.yml` must have, at its root, a `Dockerfile` and a `sonar-project.properties` — no auto-generation, no skip-if-missing logic. `devsecops-lab`'s own copies are the reference example; `templates/security.yml` in this repo is the copy-paste starting point for a new caller workflow file.

**Versioning**: callers pin to a moving tag (e.g. `@v1`) rather than `@main`, advanced manually after a change is reviewed (CODEOWNERS already gates `.github/workflows/`) and exercised via `devsecops-lab`'s own local-reference dogfood run. Backward-compatible changes move the same tag forward; breaking changes to `inputs:`/`secrets:` cut a new major tag and leave the old one pointed at the previous commit, so downstream repos upgrade explicitly rather than being broken silently. See the open SHA-vs-tag risk callout under "Action SHA Pinning" above before the first tag is cut.

**Agent push restriction**: per `docs/Isolated-Coding-Agent-User.md` Section 5, the coding agent's token has Contents access only, no Workflows scope — it can write `security-scan.yml` and `pipeline.yml` to disk, but pushes touching `.github/workflows/` are rejected server-side and must be done by a human. `templates/security.yml` and this doc have no such restriction.

### Onboarding a New Repository

1. Confirm the repo is in the org and covered by the runner group (Organization Settings → Actions → Runner groups).
2. Add a root `Dockerfile` (see `devsecops-lab`'s as a reference).
3. Add a root `sonar-project.properties` (see `devsecops-lab`'s as a reference — update `sonar.projectKey` / `sonar.sources` for the new repo).
4. Confirm the repo is covered by the org secrets' visibility (`SONAR_TOKEN`, `SONAR_HOST_URL`, optionally `NVD_API_KEY`) — automatic if visibility is "All repositories," otherwise add the repo to the "Selected repositories" list.
5. Copy `templates/security.yml` from `devsecops-lab` into the new repo as `.github/workflows/security.yml`; fill in `image_name` and `app_port`.
6. Confirm the workflow's `permissions:` block (`contents: read`, `security-events: write`, `actions: read`) is present in the caller — omitting it silently breaks SARIF upload due to org-default read-only tokens.
7. Confirm the org Actions allowlist includes `<org-name>/devsecops-lab/.github/workflows/security-scan.yml@*` (see "Actions Permissions Hardening" above).
8. Push / open a PR and watch the run: verify all five jobs complete, SARIF findings land under the new repo's Security → Code scanning tab, and the ZAP/Dependency-Check artifacts are downloadable.
9. Optionally add a repo-local `CODEOWNERS` entry for its own `.github/workflows/` directory, mirroring `devsecops-lab`'s.

**Planned automation, not yet built**: this checklist is currently manual per repo. Two documented follow-ups would remove most of it — (a) mark a starter repo as a GitHub Template Repository so `gh repo create --template` scaffolds the Dockerfile / sonar-project.properties / caller workflow automatically for brand-new repos, or (b) a local `scripts/bootstrap-repo.sh` that retrofits an existing repo with the same three files and optionally calls the GitHub API to add it to the org secrets' visibility list.

## 9. Sample Application

A deliberately vulnerable Flask application is used as the pipeline target. Using a vulnerable app rather than clean code ensures every security tool has real findings to report — this is how you learn to interpret tool output and tune pipelines.

### Intentional Vulnerabilities

`app/app.py` contains:

1. **Hardcoded secrets** — `SECRET_KEY` and `DB_PASSWORD` as plaintext strings → detected by SonarQube as security hotspots
2. **Command injection** — unsanitised user input passed directly to `subprocess.run()` with `shell=True` → detected by SonarQube and OWASP ZAP
3. **Weak cryptography** — MD5 used for password hashing → detected by SonarQube and Trivy
4. **Outdated dependencies** — pinned to older versions in `requirements.txt` → detected by Dependency-Check and Dependabot
5. **Debug mode enabled** — Flask running with `debug=True` → detected by SonarQube

### Application Structure

```
devsecops-lab/
├── .github/
│   └── workflows/
│       ├── pipeline.yml         # thin caller: dogfoods security-scan.yml against this repo
│       └── security-scan.yml    # the reusable workflow other repos call
├── app/
│   ├── app.py
│   └── requirements.txt
├── templates/
│   └── security.yml             # example caller for onboarding a new repo
├── Dockerfile
└── sonar-project.properties
```

### Dockerfile

```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY app/requirements.txt .
RUN pip install -r requirements.txt
COPY app/ .
EXPOSE 8080
CMD ["python", "app.py"]
```

### sonar-project.properties

```properties
sonar.projectKey=devsecops-lab
sonar.projectName=DevSecOps Lab
sonar.projectVersion=1.0
sonar.sources=app
sonar.language=py
sonar.python.version=3.11
```

---

## 10. Pipeline — SAST with SonarQube

### What SAST Is

Static Application Security Testing analyses source code without executing it. It looks for known vulnerability patterns, insecure coding practices, and code quality issues. It runs early in the pipeline (before build) because it is fast and catches issues at the cheapest point to fix — in the code itself before it becomes a running application.

### Pipeline Stage

`fetch-depth: 0` — by default GitHub Actions only checks out the latest commit (shallow clone). SonarQube needs full git history to generate blame information showing who introduced each issue. Without this, blame data is missing from findings.

### Results

On first run SonarQube detected 4 security hotspots corresponding to the intentional hardcoded credentials in `app.py`. The pipeline passed (hotspots require human review, they do not auto-fail).

**Quality gate configuration (future):** Quality gates define pass/fail thresholds — for example, fail if any new critical vulnerabilities are introduced, or fail if coverage drops below 80%. This is configured in SonarQube UI → Quality Gates and is the mechanism that makes SAST actually gate deployments rather than just report.

---

## 11. Pipeline — Build and Trivy Scanning

### What Trivy Does

Trivy is an open source vulnerability scanner that operates on built artifacts rather than source code. Where SonarQube scans your code, Trivy scans:
- Docker images — checking all installed OS packages and application dependencies against CVE databases
- IaC files — checking Terraform, Dockerfiles, Kubernetes manifests for misconfigurations
- Filesystems and repositories — scanning dependency files directly

### Artifact Tagging Strategy

Every Docker image built by the pipeline is tagged with the git commit SHA:

```bash
docker build -t devsecops-lab:${{ github.sha }} .
docker tag devsecops-lab:${{ github.sha }} devsecops-lab:latest
```

`github.sha` is automatically populated by GitHub Actions with the current commit hash (e.g. `a3f9c2b`). This produces immutable, traceable image tags — you can always determine exactly which code produced which image. This is a core enterprise practice called immutable artifact tagging.


### SARIF and the GitHub Security Tab

SARIF (Static Analysis Results Interchange Format) is a standard JSON format for security tool output. GitHub natively understands it and renders findings in the Security tab under Code Scanning. Findings include file locations, CVE references, severity ratings, and remediation advice. They can be filtered, dismissed, and tracked over time.

**Requirements for SARIF upload to work:**
- Repo must be public (GitHub Advanced Security is required for private repos on personal accounts)
- Workflow must have `security-events: write` permission explicitly declared
- Action must be pinned to a full SHA (enforced by repo settings)

**Viewing findings:**
```
GitHub repo → Security tab → Code scanning alerts
```

### Docker Socket Mount — Accepted Exception

Trivy requires `-v /var/run/docker.sock:/var/run/docker.sock` to inspect locally built images. This is one of the specific cases where mounting the Docker socket is an accepted and necessary tradeoff. Trivy is a read-only scanning tool — it does not modify images or the Docker daemon. This exception is documented and understood rather than being an oversight.

### `if: always()`

The upload steps use `if: always()` so they execute even if Trivy found vulnerabilities and exited with a non-zero code. Without this, findings would never reach the Security tab — the upload step would be skipped whenever Trivy detected issues, which defeats the purpose entirely.

### `--exit-code` Strategy

Both Trivy steps currently use `--exit-code 0` — Trivy reports findings but does not fail the pipeline. This is intentional for initial setup. The correct progression is:

1. Start with `--exit-code 0` — review all findings, understand what's there
2. Once findings are understood, change image scan to `--exit-code 1` for CRITICAL severity
3. This makes Trivy a hard gate — CRITICAL CVEs in the Docker image block the pipeline

A common enterprise pattern:
```bash
--exit-code 1 --severity CRITICAL    # hard fail
--exit-code 0 --severity HIGH        # report only
```

### Trivy Vulnerability Database

Trivy automatically downloads and caches its vulnerability database before each scan. The cache volume `-v $HOME/.cache/trivy:/root/.cache/trivy` persists this between runs — first run downloads the DB, subsequent runs are significantly faster. The DB is self-updating and requires no manual maintenance.

---

## 12. Pipeline — Harbor Registry

*(Planned)*

Harbor is a self-hosted container registry with built-in vulnerability scanning, image signing (Cosign), and role-based access control. It replaces Docker Hub for storing pipeline-built images locally. Images will be pushed to Harbor after Trivy scanning passes, and pulled from Harbor for deployment.

---

## 13. Pipeline — OWASP ZAP DAST

**Implemented** as the `dast` job in the reusable workflow (`.github/workflows/security-scan.yml` — see Section 8, "Reusable Workflow Architecture").

OWASP ZAP performs Dynamic Application Security Testing — it sends real HTTP requests to a running application and analyses responses for vulnerabilities. Unlike SAST which reads code, DAST interacts with the actual running application the way an attacker would. ZAP runs as an ephemeral pipeline stage: the `build` job's image is deployed to a container on an auto-assigned host port (avoids port collisions now that the runner is shared across repos), a health check confirms readiness, `ghcr.io/zaproxy/zaproxy:stable` runs a baseline scan against it, and the `cleanup` job tears the container down afterward regardless of outcome. This mirrors enterprise ephemeral environment patterns even though the underlying runner itself is persistent, not ephemeral.

Findings are published as HTML/JSON/Markdown build artifacts, not SARIF — ZAP's baseline script has no native SARIF output and there's no vetted, SHA-pinnable converter action that fits the existing allowlist model. Security-tab integration for ZAP is a documented follow-up, not implemented in v1.

---

## 14. Pipeline — Dependency Scanning

**Implemented** as the `dependency-check` job in the reusable workflow (`.github/workflows/security-scan.yml`), alongside the Dependabot config already in `.github/dependabot.yml`.

OWASP Dependency-Check scans application dependencies (requirements.txt, package.json etc.) against the NVD CVE database and uploads SARIF findings to the Security tab (category `dependency-check`) plus an HTML report as a build artifact. GitHub Dependabot separately raises PRs when dependency vulnerabilities are discovered. The distinction matters: Dependabot proposes fixes asynchronously on its own weekly schedule, while Dependency-Check reports findings synchronously on every pipeline run. The job uses a single, globally-named NVD cache Docker volume shared across all repos on the runner (not scoped per repo) since the CVE database is identical regardless of caller and the runner is persistent — every repo benefits from whichever repo warmed the cache first. An optional `NVD_API_KEY` org secret raises the NVD lookup rate limit from 5 to 50 requests/30s.

---

## 15. Pipeline — Terraform and Minio Backend

*(Planned)*

Terraform will be used to provision the application's infrastructure (initially Docker containers locally, transferable to cloud). Key concepts to implement: remote state in Minio (mirrors S3 in AWS), plan/apply as separate pipeline stages with a manual approval gate between them, and drift detection. The Minio bucket `terraform-state` created in Section 7 is the backend target.

---

## 16. Pipeline — Full Integration and Stage Gates

*(Planned)*

The complete pipeline tying all stages together with proper gate logic: SAST must pass before build, Trivy must pass before push to Harbor, ZAP must pass before Terraform apply. Branch protection rules on GitHub main branch will require the full pipeline to pass before any PR can be merged. GitHub Environments with protection rules will implement the manual approval gate for production deploys.

---

## 17. Patch Management and Maintenance

*(Planned)*

Monthly maintenance procedures covering: Ubuntu security updates (unattended-upgrades), Docker service image updates (manual, with release note review), GitHub Actions version pinning and updates, pfSense updates, Trivy database (self-updating), SonarQube plugin updates, and certificate renewal. Includes the `update-services.sh` script and a monthly checklist.

---

## 18. Kali Attack Box

*(Planned)*

A dedicated Kali Linux attack box on a used Dell/HP SFF machine (target: i5 8th gen+, 16GB RAM, SSD). Will sit on the LAB subnet behind pfSense alongside the Ubuntu server. Used for security testing exercises against lab targets without touching the home PC. Access via RDP from Home PC through pfSense rules that explicitly allow RDP to Kali but block Kali from initiating connections to the home network.

---

## Appendix — Port Reference

| Port | Service | Host | Notes |
|---|---|---|---|
| 2222 | SSH | Ubuntu | Non-default port |
| 9000 | PHP-FPM | Ubuntu host | FOG — do not use |
| 9100 | SonarQube | Docker | Moved from 9000 |
| 9200 | Minio API | Docker | |
| 9201 | Minio Console | Docker | |
| 8080 | App staging | Docker | Ephemeral, used for ZAP |
| 80 | Apache (FOG) | Ubuntu host | FOG web interface |
| 443 | Apache (FOG) | Ubuntu host | FOG web interface |
| 3306 | MariaDB | Ubuntu host | Bound to 127.0.0.1 only |
| 21 | vsftpd | Ubuntu host | Disabled |

## Appendix — Key Files Reference

| File | Purpose |
|---|---|
| `/etc/docker/daemon.json` | Docker daemon hardening config |
| `/etc/ufw/after.rules` | UFW rules including Docker NAT |
| `/etc/default/ufw` | UFW forwarding policy |
| `/etc/sysctl.d/99-hardening.conf` | Kernel parameters |
| `/etc/ssh/sshd_config` | SSH hardening |
| `/etc/fail2ban/jail.local` | Fail2Ban overrides |
| `/etc/mysql/mariadb.conf.d/50-server.cnf` | MariaDB bind address |
| `/etc/apt/apt.conf.d/50unattended-upgrades` | Auto security updates |
| `/etc/audit/rules.d/hardening.rules` | Auditd rules |
| `~/lab/docker-compose.yml` | All lab service definitions |
| `~/lab/scripts/update-services.sh` | Monthly service update script |
| `.github/workflows/pipeline.yml` | Thin caller — dogfoods `security-scan.yml` against this repo's own app |
| `.github/workflows/security-scan.yml` | The reusable workflow (`on: workflow_call`) every repo calls |
| `templates/security.yml` | Example caller workflow for onboarding a new repo |
| `sonar-project.properties` | SonarQube project config |

---
