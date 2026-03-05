import json
import os
from datetime import datetime
from exel_baugruppe import get_excel_tasks
from mitre_api import fetch_mitre_data

# --- KONFIGURATION ---
SUBREPO_PATH = "subrepo/groups"
# Nur diese Plattformen sind für Lütze Hardware relevant:
VALID_PLATFORMS = ["field controller/rtu/plc/ied", "input/output server", "control server", "none"]
BLACKLIST = ["cloud", "azure", "office 365", "macos", "ios", "active directory"]

def run_pipeline():
    run_timestamp = datetime.now().strftime("%Y%m%d_%H%M")
    os.makedirs(SUBREPO_PATH, exist_ok=True)
    
    raw_data = fetch_mitre_data()
    tasks = get_excel_tasks("Produktliste_Luetze.xlsx")

    # Mapping vorbereiten für Performance
    mitigations = {obj['id']: obj for obj in raw_data if obj.get('type') == 'course-of-action'}
    relationships = [obj for obj in raw_data if obj.get('type') == 'relationship' and obj.get('relationship_type') == 'mitigates']

    for task in tasks:
        clean_name = "".join(e for e in task['bezeichnung'] if e.isalnum() or e == " ").replace(" ", "-")
        filename = f"{run_timestamp}_{task['materialnummer']}_{clean_name}.json"
        
        filtered_results = []
        keywords = [k.lower() for k in task['keywords']]

        for obj in raw_data:
            if obj.get("type") == "attack-pattern":
                name = obj.get("name", "").lower()
                desc = obj.get("description", "").lower()
                platforms = [p.lower() for p in obj.get("x_mitre_platforms", [])]
                assets = [a.lower() for a in obj.get("x_mitre_assets", [])]

                # --- DER FILTER-CHECK ---
                # 1. Keyword muss in Name, Beschreibung ODER Asset-Tag sein
                keyword_match = any(k in name or k in desc or k in assets for k in keywords)
                # 2. Plattform muss Hardware-nah sein (kein Windows/Cloud Fokus)
                platform_match = any(p in VALID_PLATFORMS for p in platforms)
                # 3. Blacklist Check
                on_blacklist = any(b in name or b in desc for b in BLACKLIST)

                if keyword_match and platform_match and not on_blacklist:
                    tech_id = obj.get("id")
                    ext_id = obj.get("external_references", [{}])[0].get("external_id")
                    
                    # Verknüpfte Mitigations finden
                    found_mitigations = []
                    for rel in relationships:
                        if rel.get('target_ref') == tech_id:
                            mit = mitigations.get(rel.get('source_ref'))
                            if mit:
                                found_mitigations.append({
                                    "id": mit.get("external_references", [{}])[0].get("external_id"),
                                    "name": mit.get("name"),
                                    "description": mit.get("description")
                                })

                    filtered_results.append({
                        "asset": task['bezeichnung'],
                        "attack_pattern": {"id": ext_id, "name": obj.get("name"), "description": obj.get("description")},
                        "weaknesses": ["CWE-XXX: Manuell durch Experte zu ergänzen"],
                        "mitigations": found_mitigations
                    })

        with open(os.path.join(SUBREPO_PATH, filename), "w", encoding="utf-8") as f:
            json.dump(filtered_results, f, indent=4, ensure_ascii=False)
        print(f"Datei erstellt: {filename} ({len(filtered_results)} relevante Treffer)")

if __name__ == "__main__":
    run_pipeline()
    
