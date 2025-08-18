from fastapi import FastAPI, Query
from sqlalchemy import create_engine, text
import os

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql+psycopg2://cg360:cg360@localhost:5432/cg360")
app = FastAPI(title="CloudGuard360-DB API", version="0.1.0")
engine = create_engine(DATABASE_URL, pool_pre_ping=True)

@app.get("/v1/health")
def health():
    try:
        with engine.connect() as conn:
            conn.execute(text("select 1"))
        return {"status": "ok"}
    except Exception as e:
        return {"status": "error", "detail": str(e)}

@app.get("/v1/cves")
def list_cves(q: str | None = Query(None, description="search id/summary"),
              min_score: float | None = None,
              kev_only: bool = False,
              limit: int = 50, offset: int = 0):
    base = "select c.id, c.severity, c.cvss_v3, c.summary from cve c"
    if kev_only:
        base += " join kev k on k.cve_id = c.id"
    where = []
    params = {}
    if q:
        where.append("(c.id ilike :q or c.summary ilike :q)")
        params["q"] = f"%{q}%"
    if min_score is not None:
        where.append("(c.cvss_v3 >= :min_score)")
        params["min_score"] = min_score
    if where:
        base += " where " + " and ".join(where)
    base += " order by c.cvss_v3 desc nulls last, c.id asc limit :limit offset :offset"
    params["limit"] = limit
    params["offset"] = offset
    with engine.connect() as conn:
        rows = conn.execute(text(base), params).mappings().all()
    return [dict(r) for r in rows]

@app.get("/v1/packages/{purl}/cves")
def cves_for_package(purl: str):
    sql = """
    select c.id, c.severity, c.cvss_v3, c.summary, ca.version_range
      from cve c
      join cve_affects ca on ca.cve_id = c.id
      join package p on p.id = ca.package_id
     where p.purl = :purl
     order by c.cvss_v3 desc nulls last, c.id asc
    """
    with engine.connect() as conn:
        rows = conn.execute(text(sql), {"purl": purl}).mappings().all()
    return [dict(r) for r in rows]
