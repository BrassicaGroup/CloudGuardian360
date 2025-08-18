# Cloud_360_Proj
Smart System Solution SecOps Project for Cloud CVEs


# CloudGuard360-DB
Secure, productized vulnerability intelligence microservice for **RM Smart System Solutions**.  
Ingests CVE feeds, normalizes to Postgres, matches against CycloneDX SBOMs, and exposes a REST API for policy gates.


## Quick start (Docker)
```bash
docker compose up -d
# API: http://localhost:8080/docs



Components

/api — FastAPI service to query CVEs, packages, and policy gates.

/db — Postgres schema & migrations.

/etl — Feed ingesters (NVD JSON 2.0) and loaders.

/sbom_matcher — CycloneDX SBOM parsing & PURL-based matching.

/policy — YAML policy gates for CI (fail on CVSS, KEV, or exploit maturity).

/data — Structure for year/vendor separated CVE files + samples.

Data sources (configure in configs/config.yaml)

NVD JSON 2.0 (optional API key)

CISA KEV catalog (optional)

GitHub Security Advisories (optional, via token)
(Scripts provided; you must supply your own keys/tokens and comply with terms of use.)
