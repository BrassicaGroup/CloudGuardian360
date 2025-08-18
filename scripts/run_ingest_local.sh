#!/usr/bin/env bash
set -euo pipefail
if [[ $# -lt 1 ]]; then
  echo "Usage: $0 /path/to/nvd.json.gz [more files...]"
  exit 1
fi
export DATABASE_URL="${DATABASE_URL:-postgresql+psycopg2://cg360:cg360@localhost:5432/cg360}"
python etl/nvd_ingest.py "$@"
