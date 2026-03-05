# DevSecOps Home Lab

A home CI/CD pipeline integrating enterprise-grade security controls, built for hands-on learning. The pipeline runs on self-hosted infrastructure behind a pfSense firewall and attempts to mirror real-world DevSecOps practice.

> ⚠️ The sample application in this repo contains **intentional vulnerabilities** for security tool demonstration purposes. Do not deploy it in any production or internet-facing environment.

---

## PLANNED Pipeline Overview

```
Push to GitHub
      ↓
SAST — SonarQube (static code analysis)
      ↓
Build — Docker image
      ↓
Scan — Trivy (CVE scanning of image and IaC)
      ↓
DAST — OWASP ZAP (dynamic scanning of running app)
      ↓
Dependencies — OWASP Dependency-Check + Dependabot
      ↓
Registry — Harbor (image storage and signing)
      ↓
Infrastructure — Terraform + Minio state backend
```

---

## Stack

| Tool | Purpose |
|---|---|
| GitHub Actions (self-hosted runner) | Pipeline orchestration |
| SonarQube Community | SAST, quality gates |
| Trivy | Container and IaC scanning |
| OWASP ZAP | DAST |
| OWASP Dependency-Check | SCA |
| Harbor | Container registry |
| Terraform | Infrastructure as code |
| Minio | Terraform state backend (S3-compatible) |
| pfSense | Network segmentation, VPN routing |
| Ubuntu | Self-hosted runner and services |

---

## Infrastructure

All pipeline tools run as Docker containers on a self-hosted Ubuntu server sitting behind a pfSense firewall. The runner executes locally — build artifacts and secrets never leave the network.

Full build documentation is in [`docs/devsecops-lab.md`](docs/devsecops-lab.md).
