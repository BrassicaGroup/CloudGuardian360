import json, sys

def load_sbom(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def list_purls(sbom):
    comps = sbom.get("components", [])
    for c in comps:
        p = c.get("purl")
        if p:
            yield f"{p}    {c.get('name')}@{c.get('version')}"

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python sbom_matcher/sbom_match.py path/to/cyclonedx.json")
        sys.exit(1)
    for line in list_purls(load_sbom(sys.argv[1])):
        print(line)
