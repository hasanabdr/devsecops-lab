# DevSecOps Home Lab

A home CI/CD pipeline integrating enterprise-grade security controls, built for hands-on learning. The pipeline runs on self-hosted infrastructure behind a pfSense firewall and attempts to mirror real-world DevSecOps practice.

This repo is two things at once: the deliberately vulnerable app the pipeline was built to scan, and the **source of a reusable GitHub Actions workflow** (`.github/workflows/security-scan.yml`) that any other repo in the org can call to get the same scanning on the same self-hosted runner, with no per-repo pipeline authoring.

> ⚠️ The sample application in this repo contains **intentional vulnerabilities** for security tool demonstration purposes. Do not deploy it in any production or internet-facing environment.

---

## Pipeline Overview

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
Registry — Harbor (image storage and signing)               [planned]
      ↓
Infrastructure — Terraform + Minio state backend             [planned]
```

Everything above the `[planned]` line is implemented as jobs in `.github/workflows/security-scan.yml` and exercised against this repo's own app via `.github/workflows/pipeline.yml` on every push.

---

## Using this pipeline in another repo

Any repo covered by the org's shared self-hosted runner can call the same scanning pipeline:

1. Add a root `Dockerfile` and `sonar-project.properties` (required — see this repo's own copies as the reference).
2. Copy [`templates/security.yml`](templates/security.yml) in as `.github/workflows/security.yml` and fill in `image_name` / `app_port`.
3. Push — SAST, SCA, container/filesystem CVE scanning, and DAST run automatically, with findings on the Security tab and as build artifacts.

Full step-by-step checklist and the workflow's inputs/secrets reference are in [`docs/devsecops-lab.md`](docs/devsecops-lab.md), under "Reusable Workflow Architecture" / "Onboarding a New Repository" (Section 8).

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
