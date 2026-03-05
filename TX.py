import json
import os
from datetime import datetime
from exel_baugruppe import get_excel_tasks
from mitre_api import fetch_mitre_data

SUBREPO_PATH = "subrepo/groups"

def run_pipeline():
    run_timestamp = datetime.now().strftime("%Y%m%d_%H%M")
    os.makedirs(SUBREPO_PATH, exist_ok=True)
    
    raw_data = fetch_mitre_data()
    excel_tasks = get_excel_tasks("Produktliste_Luetze.xlsx")

    # Hilfs-Dictionaries für schnellen Zugriff auf Mitigations
    # Wir brauchen: Relationen (wer gehört zu wem) und die eigentlichen Mitigations
    mitigations = {obj['id']: obj for obj in raw_data if obj.get('type') == 'course-of-action'}
    relationships = [obj for obj in raw_data if obj.get('type') == 'relationship' and obj.get('relationship_type') == 'mitigates']

    for task in excel_tasks:
        clean_name = "".join(e for e in task['bezeichnung'] if e.isalnum() or e == " ").replace(" ", "-")
        filename = f"{run_timestamp}_{task['materialnummer']}_{clean_name}.json"
        
        filtered_threats = []
        
        for obj in raw_data:
            if obj.get("type") == "attack-pattern":
                name, desc = obj.get("name", "").lower(), obj.get("description", "").lower()
                
                if any(k.lower() in name or k.lower() in desc for k in task['keywords']):
                    tech_id = obj.get("id") # STIX ID (z.B. attack-pattern--...)
                    ext_id = obj.get("external_references", [{}])[0].get("external_id") # ATT&CK ID (T0834)
                    
                    # Suche nach verknüpften Mitigations für diese Technik
                    found_mitigations = []
                    for rel in relationships:
                        if rel.get('target_ref') == tech_id:
                            mit_obj = mitigations.get(rel.get('source_ref'))
                            if mit_obj:
                                m_ext_id = mit_obj.get("external_references", [{}])[0].get("external_id")
                                found_mitigations.append({
                                    "mitigation_id": m_ext_id,
                                    "name": mit_obj.get("name"),
                                    "description": mit_obj.get("description")
                                })

                    filtered_threats.append({
                        "asset": task['bezeichnung'],
                        "attack_pattern": {
                            "id": ext_id,
                            "name": obj.get("name"),
                            "description": obj.get("description")
                        },
                        "weaknesses": ["CWE-XXX (Platzhalter für manuelle Ergänzung)"], 
                        "mitigations": found_mitigations
                    })

        with open(os.path.join(SUBREPO_PATH, filename), "w", encoding="utf-8") as f:
            json.dump(filtered_threats, f, indent=4, ensure_ascii=False)
        print(f"Erstellt: {filename}")

if __name__ == "__main__":
    run_pipeline()
