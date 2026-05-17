import json
import sys
import urllib.request
import urllib.error

OSV_API_URL = "https://api.osv.dev/v1/query"

def load_sbom(path):
    with open(path, "r") as f:
        sbom = json.load(f)
    return sbom.get("components", [])

def query_osv(purl):
    payload = json.dumps({"package": {"purl": purl}}).encode("utf-8")
    request = urllib.request.Request(
        OSV_API_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            data = json.loads(response.read())
            return data.get("vulns", [])
    except urllib.error.URLError as e:
        print("Verbindungsfehler " + str(e))
        return []

def extract_cve_id(vuln):
    for alias in vuln.get("aliases", []):
        if alias.startswith("CVE-"):
            return alias
    return vuln.get("id", "unbekannt")

def extract_severity(vuln):
    severities = vuln.get("severity", [])
    if severities:
        return severities[0].get("score", "n/a")
    return "n/a"

def scan_component(component):
    name = component.get("name", "unbekannt")
    version = component.get("version", "unbekannt")
    purl = component.get("purl")

    print()
    print("Das Paket " + name + " in der Version " + version + " wird angeschaut")

    if not purl:
        print("Purl fehlt")
        return []

    vulns = query_osv(purl)

    if not vulns:
        print("keine Schwachstellen!")
        return []

    print("Es wurden " + str(len(vulns)) + " Schwachstelle(n) gefunden:")
    findings = []
    
    for v in vulns:
        cve_id = extract_cve_id(v)
        summary = v.get("summary") or v.get("details") or "Keine genaue Beschreibung vorhanden"
        severity = extract_severity(v)
        
        short_summary = summary[:80]
        print("  - " + cve_id + ": " + short_summary)
        
        findings.append({
            "component": name,
            "version": version,
            "cve_id": cve_id,
            "summary": summary,
            "severity": severity,
        })
        
    return findings

def main():
    if len(sys.argv) != 3:
        print("Fehler: Bitte Input- und Output-Datei angeben!")
        sys.exit(1)

    sbom_path = sys.argv[1]
    output_path = sys.argv[2]
    
    print("SBOM laden " + sbom_path)
    components = load_sbom(sbom_path)
    print("Ich habe " + str(len(components)) + " Komponenten darin gefunden")

    all_findings = []
    for component in components:
        all_findings.extend(scan_component(component))

    print()
    print("============================================================")
    print("Es wurden " + str(len(all_findings)) + " Schwachstellen gefunden.")
    print("============================================================")

    with open(output_path, "w") as f:
        json.dump(all_findings, f, indent=2) 
        
    print("Ergebnisse in " + output_path + " gespeichert")
if __name__ == "__main__":
    main()