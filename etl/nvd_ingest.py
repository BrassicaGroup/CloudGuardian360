import json, gzip, os, sys
import yaml
from sqlalchemy import create_engine, text

def load_config():
    with open(os.getenv("CG360_CONFIG", "configs/config.yaml"), "r") as f:
        return yaml.safe_load(f)

def upsert(engine, sql, params):
    with engine.begin() as conn:
        conn.execute(text(sql), params)

def parse_nvd_item(item):
    cve_id = item["cve"]["id"]
    desc = (item["cve"].get("descriptions") or [{}])[0].get("value")
    severity = None
    cvss = None
    metrics = item.get("metrics") or {}
    if "cvssMetricV31" in metrics:
        m = metrics["cvssMetricV31"][0]["cvssData"]
        severity = metrics["cvssMetricV31"][0].get("baseSeverity")
        cvss = m.get("baseScore")
    elif "cvssMetricV30" in metrics:
        m = metrics["cvssMetricV30"][0]["cvssData"]
        severity = metrics["cvssMetricV30"][0].get("baseSeverity")
        cvss = m.get("baseScore")
    pub = item.get("published")
    mod = item.get("lastModified")
    return {
        "id": cve_id,
        "summary": desc,
        "severity": severity,
        "cvss_v3": cvss,
        "published": pub,
        "last_modified": mod,
        "source": json.dumps(item),
    }

def load_nvd_json(path, engine):
    if path.endswith(".gz"):
        import gzip, json
        with gzip.open(path, "rt", encoding="utf-8") as f:
            data = json.load(f)
    else:
        import json
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    for wrapper in data.get("vulnerabilities", []):
        item = wrapper.get("cve") or wrapper
        row = parse_nvd_item(item)
        upsert(engine, """
            insert into cve (id, summary, severity, cvss_v3, published, last_modified, source)
            values (:id, :summary, :severity, :cvss_v3, :published, :last_modified, :source)
            on conflict (id) do update set
              summary=excluded.summary,
              severity=excluded.severity,
              cvss_v3=excluded.cvss_v3,
              published=excluded.published,
              last_modified=excluded.last_modified,
              source=excluded.source
        """, row)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python etl/nvd_ingest.py <path-to-nvd-json-or-json.gz>")
        sys.exit(1)
    cfg = load_config()
    db_url = os.getenv("DATABASE_URL", cfg["database"]["url"])
    engine = create_engine(db_url, pool_pre_ping=True)
    # Init schema if needed
    from sqlalchemy import text as _t
    with engine.begin() as conn:
        conn.execute(_t(open("db/schema.sql").read()))
    for path in sys.argv[1:]:
        print("Loading", path)
        load_nvd_json(path, engine)
    print("Done")
