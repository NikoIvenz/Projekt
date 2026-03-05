import requests
import json
import os
from datetime import datetime

SOURCES = {
    "ics": "https://raw.githubusercontent.com/mitre/cti/master/ics-attack/ics-attack.json",
    "enterprise": "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
}

def get_mitre_data():
    """Holt die aktuellsten Daten von der Website."""
    all_objects = []
    for domain, url in SOURCES.items():
        print(f"Lade {domain}...")
        res = requests.get(url)
        if res.status_code == 200:
            all_objects.extend(res.json().get("objects", []))
    return all_objects

def filter_for_group(group_name, keywords, raw_data):
    """Erstellt eine neue Liste für eine Bauteilgruppe (z.B. CAN Bus)."""
    results = []
    for obj in raw_data:
        # Wir nehmen nur Techniken (Attack Patterns)
        if obj.get("type") == "attack-pattern":
            name = obj.get("name", "").lower()
            desc = obj.get("description", "").lower()
            
            # Suche in Name ODER Beschreibung (wegen Software-Zusammenhang)
            if any(k.lower() in name or k.lower() in desc for k in keywords):
                results.append({
                    "id": obj.get("external_references", [{}])[0].get("external_id"),
                    "name": obj.get("name"),
                    "description": obj.get("description"),
                    "last_mitre_update": obj.get("modified")
                })
    
    file_path = f"subrepo/groups/{group_name}.json"
    os.makedirs("subrepo/groups", exist_ok=True)
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=4)
    print(f"Gruppe {group_name} mit {len(results)} Bedrohungen erstellt.")



def migrate_to_v1(group_name):
    """Vergleicht v1.0 mit dem Subrepo und zeigt neue Bedrohungen an."""
    v1_path = f"projects/v1.0/{group_name}.json"
    subrepo_path = f"subrepo/groups/{group_name}.json"
    
    if not os.path.exists(v1_path):
        print("Erstelle erste v1.0 Version...")
        os.makedirs("projects/v1.0", exist_ok=True)
        # Hier kopieren wir das Original einfach rüber
        with open(subrepo_path, "r") as src, open(v1_path, "w") as dst:
            dst.write(src.read())
        return

    # Migration / Vergleich
    with open(v1_path, "r") as f: v1_data = json.load(f)
    with open(subrepo_path, "r") as f: sub_data = json.load(f)
    
    v1_ids = {item["id"] for item in v1_data}
    
    print(f"\n--- Update-Check für {group_name} v1.0 ---")
    for item in sub_data:
        if item["id"] not in v1_ids:
            print(f"NEU BEI MITRE: {item['id']} - {item['name']}. Hinzufügen? (y/n)")
            # Hier könnte man die Migration automatisieren






import pandas as pd
import os

def process_lütze_excel(file_path):
    # 1. Excel laden
    df = pd.read_excel(file_path)
    
    # Wir machen die Spaltennamen klein, damit wir sie leichter finden
    df.columns = [c.lower().strip() for c in df.columns]
    
    # Hier definierst du später, wie deine Spalten wirklich heißen
    col_has_sw = "hat software" # Die "Ja/Nein" Spalte
    col_sw_type = "software"     # Die Baugruppen/Zusammenhang Spalte
    col_interface = "interface"  # Die Hardware-Spalte (z.B. CAN Bus)

    results_to_fetch = []

    for index, row in df.iterrows():
        # --- OPTIONALER CHECK 1: Hat das Teil überhaupt Software? ---
        has_software = str(row.get(col_has_sw, "")).lower()
        if has_software != "ja":
            continue # Springe zum nächsten Teil, wenn keine Software drauf ist
            
        # --- LOGIK 2: Zusammenhang über Software-ID/Typ ---
        sw_context = str(row.get(col_sw_type, ""))
        
        # --- LOGIK 3: Hardware-Schnittstelle ---
        hw_interface = str(row.get(col_interface, ""))

        # Wir sammeln die Keywords für den MITRE-Filter
        # Alles was in sw_context oder hw_interface steht, wird zum Suchbegriff
        keywords = [hw_interface, sw_context]
        # Leere Einträge entfernen
        keywords = [k for k in keywords if k and k != "nan"]

        if keywords:
            results_to_fetch.append({
                "line": index + 2, # +2 wegen Header und 0-Index
                "group_name": f"{hw_interface}_{sw_context}".replace(" ", "_"),
                "keywords": keywords
            })
            
    return results_to_fetch

# --- Integration mit dem MITRE-Download ---

def run_threat_pipeline(excel_path):
    # 1. Excel analysieren
    tasks = process_lütze_excel(excel_path)
    
    # 2. Einmalig frische Daten von MITRE laden
    from your_script import get_mitre_data, filter_for_group # Dein Code von vorhin
    raw_mitre = get_mitre_data()
    
    for task in tasks:
        print(f"Verarbeite Excel-Zeile {task['line']}: {task['group_name']}")
        
        # 3. In das Subrepo filtern
        filter_for_group(task['group_name'], task['keywords'], raw_mitre)
        
    print("\nAlle Bauteilgruppen im Subrepo aktualisiert.")
  
