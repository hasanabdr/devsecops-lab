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

```
GitHub repo → Settings → Actions → Runners → New self-hosted runner → Linux x64
```

Follow the generated commands to download and configure the runner. **Do not run `./run.sh`** — this runs the runner interactively in the foreground and dies when the terminal closes. Install as a systemd service instead:

```bash
# Must be run from inside the runner directory
cd /home/github-runner/actions-runner
sudo ./svc.sh install github-runner
sudo ./svc.sh start
sudo systemctl status actions.runner.yourgithubusername-devsecops-lab.*
```

**Runner labels:** `self-hosted, linux, lab` — referenced in pipeline YAML as `runs-on: self-hosted`

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

Sensitive values used in the pipeline are stored as GitHub Secrets (repo → Settings → Secrets and variables → Actions). They are injected into pipeline steps as environment variables and never appear in logs.

| Secret | Value | Used by |
|---|---|---|
| SONAR_TOKEN | SonarQube analysis token | SonarQube scan action |
| SONAR_HOST_URL | http://127.0.0.1:9100 | SonarQube scan action |

---


### Actions Permissions Hardening (Public Repo)

With a public repo, anyone can fork it and open a pull request. Without restrictions, a malicious PR could execute arbitrary code on your self-hosted runner. These settings are configured at:

```
GitHub repo → Settings → Actions → General
```

**Actions permissions:**
```
Select: "Allow yourgithubusername, and select non-yourgithubusername actions and reusable workflows"
Tick: "Allow actions created by GitHub"
Tick: "Require actions to be pinned to a full-length commit SHA"
```

Add explicit allowlist for third-party actions used in the pipeline:
```
SonarSource/sonarqube-scan-action
sonarsource/sonarqube-scan-action
actions/*
aquasec/*
github/codeql-action
```

Note: GitHub normalises action names to lowercase internally. Adding both `SonarSource/` and `sonarsource/` variants avoids case-sensitivity matching failures.

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
│       └── pipeline.yml
├── app/
│   ├── app.py
│   └── requirements.txt
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

*(Planned)*

OWASP ZAP performs Dynamic Application Security Testing — it sends real HTTP requests to a running application and analyses responses for vulnerabilities. Unlike SAST which reads code, DAST interacts with the actual running application the way an attacker would. ZAP will be deployed as an ephemeral pipeline stage: deploy app to staging container → ZAP scans it → tear down container. This mirrors enterprise ephemeral environment patterns.

---

## 14. Pipeline — Dependency Scanning

*(Planned)*

OWASP Dependency-Check scans application dependencies (requirements.txt, package.json etc) against the NVD CVE database. GitHub Dependabot will be configured to automatically raise PRs when dependency vulnerabilities are discovered. The distinction between Dependabot (automated update PRs) and Dependency-Check (CVE scanning in pipeline) is important.

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
| `.github/workflows/pipeline.yml` | CI/CD pipeline definition |
| `sonar-project.properties` | SonarQube project config |

---
