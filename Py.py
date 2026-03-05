
import requests
import json
import os

# Die offiziellen Quellen von MITRE (GitHub ist oft am stabilsten)
SOURCES = {
    "ics": "https://raw.githubusercontent.com/mitre/cti/master/ics-attack/ics-attack.json",
    "enterprise": "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
}

def update_and_filter_repo(keywords, output_file="subrepo/filtered_threats.json"):
    """Lädt MITRE Daten und speichert nur relevante Techniken."""
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    
    combined_results = []

    for domain, url in SOURCES.items():
        print(f"Lade {domain} Daten von MITRE...")
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            objects = data.get("objects", [])
            
            # Filtern: Nur Techniken, die unsere Keywords (CAN, Serial...) enthalten
            for obj in objects:
                if obj.get("type") == "attack-pattern":
                    name = obj.get("name", "").lower()
                    desc = obj.get("description", "").lower()
                    
                    if any(k.lower() in name or k.lower() in desc for k in keywords):
                        # Wir speichern nur, was wir brauchen, um das Subrepo schlank zu halten
                        combined_results.append({
                            "id": obj.get("external_references", [{}])[0].get("external_id"),
                            "name": obj.get("name"),
                            "domain": domain,
                            "description": obj.get("description"),
                            "platforms": obj.get("x_mitre_platforms", [])
                        })
        else:
            print(f"Fehler beim Laden von {domain}: {response.status_code}")

    # Speichern im Subrepo
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(combined_results, f, indent=4, ensure_ascii=False)
    
    print(f"Fertig! {len(combined_results)} Bedrohungen im Subrepo gespeichert.")

# Beispielaufruf für Lütze:
update_and_filter_repo(["CAN Bus", "Serial", "RS485", "Modbus"])
