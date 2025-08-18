-- Postgres schema for CloudGuard360-DB
create table if not exists cve (
  id text primary key,
  published timestamptz,
  last_modified timestamptz,
  source jsonb,
  cvss_v2 numeric,
  cvss_v3 numeric,
  severity text,
  summary text
);

create table if not exists cwe (
  id text primary key,
  name text
);

create table if not exists cve_cwe (
  cve_id text references cve(id) on delete cascade,
  cwe_id text references cwe(id) on delete cascade,
  primary key (cve_id, cwe_id)
);

create table if not exists package (
  id serial primary key,
  purl text unique,         -- package URL
  name text,
  ecosystem text
);

create table if not exists cve_affects (
  cve_id text references cve(id) on delete cascade,
  package_id int references package(id) on delete cascade,
  version_range text,
  primary key (cve_id, package_id, version_range)
);

create table if not exists kev (
  cve_id text primary key references cve(id) on delete cascade,
  date_added date,
  due_date date
);
