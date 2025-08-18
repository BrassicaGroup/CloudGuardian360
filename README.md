# Cloud_360_Proj
Smart System Solution SecOps Project for Cloud CVEs


# CloudGuard360-DB
Secure, productized vulnerability intelligence microservice for **RM Smart System Solutions**.  
Ingests CVE feeds, normalizes to Postgres, matches against CycloneDX SBOMs, and exposes a REST API for policy gates.

## Quick start (Docker)
```bash
docker compose up -d
# API: http://localhost:8080/docs



