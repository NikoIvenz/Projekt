import json
import os
from datetime import datetime
#from exel_baugruppe import get_excel_tasks
from mitre_api import fetch_mitre_data

# --- KONFIGURATION ---
SUBREPO_PATH = "subrepo/groups"
# Nur diese Plattformen sind für Lütze Hardware relevant:
TEST = [
    {'materialnummer': '123', 'bezeichnung': 'CAN Bus', 'keywords': 'Can Bus'},
    {'materialnummer': '13',  'bezeichnung': 'Serial',  'keywords': 'Serial'},
    {'materialnummer': '33',  'bezeichnung': 'Ethernet','keywords': 'Ethernet'}
]

def run_pipeline():
    run_timestamp = datetime.now().strftime("%Y%m%d_%H%M")
    os.makedirs(SUBREPO_PATH, exist_ok=True)
    
    raw_data = fetch_mitre_data()
    #tasks = get_excel_tasks("Produktliste_Luetze.xlsx")
    tasks = TEST
    
    # --- 1. Mapping vorbereiten für Performance ---
    # Gegenmaßnahmen (Mitigations)
    mitigations = {obj['id']: obj for obj in raw_data if obj.get('type') == 'course-of-action'}
    mitigates_rels = [obj for obj in raw_data if obj.get('type') == 'relationship' and obj.get('relationship_type') == 'mitigates']
    
    # NEU: Malware und Tools vorbereiten
    malwares = {obj['id']: obj for obj in raw_data if obj.get('type') in ['malware', 'tool']}
    uses_rels = [obj for obj in raw_data if obj.get('type') == 'relationship' and obj.get('relationship_type') == 'uses']
    
    for task in tasks:
        clean_name = "".join(e for e in task['bezeichnung'] if e.isalnum() or e == " ").replace(" ", "_")
        filename = f"{run_timestamp}_{task['materialnummer']}_{clean_name}.json"
        filepath = os.path.join(SUBREPO_PATH, filename)
        
        # Keyword für die Suche (case-insensitive)
        keyword = task['keywords'].lower()
        matched_threats = []
        
        # --- 2. Filtere die MITRE-Daten nach dem Keyword ---
        for obj in raw_data:
            if obj.get('type') == 'attack-pattern':
                name = obj.get('name', '').lower()
                desc = obj.get('description', '').lower()
                
                # Wenn das Keyword im Namen oder in der Beschreibung vorkommt
                if keyword in name or keyword in desc:
                    obj_id = obj.get('id')
                    
                    # --- 3. Suche nach passenden Gegenmaßnahmen (Mitigations) ---
                    related_mitigations = []
                    for rel in mitigates_rels:
                        if rel.get('target_ref') == obj_id:
                            mitigation_id = rel.get('source_ref')
                            if mitigation_id in mitigations:
                                miti_obj = mitigations[mitigation_id]
                                related_mitigations.append({
                                    "name": miti_obj.get('name'),
                                    "description": miti_obj.get('description')
                                })
                                
                    # --- NEU: 4. Suche nach Malware/Tools, die diese Technik nutzen ---
                    related_malware = []
                    for rel in uses_rels:
                        # Bei 'uses' ist source_ref die Malware und target_ref die Technik
                        if rel.get('target_ref') == obj_id:
                            malware_id = rel.get('source_ref')
                            if malware_id in malwares:
                                mal_obj = malwares[malware_id]
                                related_malware.append({
                                    "name": mal_obj.get('name'),
                                    "type": mal_obj.get('type'), # Zeigt an, ob es 'malware' oder 'tool' ist
                                    "description": mal_obj.get('description')
                                })
                    
                    # --- 5. Extrahiere die MITRE ID (z.B. T1000) ---
                    mitre_id = "N/A"
                    url = ""
                    for ext_ref in obj.get('external_references', []):
                        if ext_ref.get('source_name') in ['mitre-attack', 'mitre-ics-attack']:
                            mitre_id = ext_ref.get('external_id', 'N/A')
                            url = ext_ref.get('url', '')
                            break
                    
                    # --- 6. Füge den Treffer zur Liste hinzu ---
                    matched_threats.append({
                        "technique_id": mitre_id,
                        "name": obj.get('name'),
                        "url": url,
                        "description": obj.get('description'),
                        "known_malware_and_tools": related_malware, # NEU: Hier hängt jetzt die Malware dran
                        "mitigations": related_mitigations
                    })
        
        # --- 7. Baue das finale JSON-Dokument ---
        output_data = {
            "hardware_info": task,
            "scan_timestamp": run_timestamp,
            "threats_found_count": len(matched_threats),
            "threats": matched_threats
        }
        
        # --- 8. Speichere die Datei ab ---
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(output_data, f, indent=4, ensure_ascii=False)
            
        print(f"[+] {len(matched_threats)} Bedrohungen für '{task['bezeichnung']}' gefunden. Gespeichert in: {filepath}")

if __name__ == "__main__":
    run_pipeline()


import os
import json
import shutil

def get_mat_from_filename(fname):
    """Extrahiert die Materialnummer aus dem Dateinamen (Format: YYYYMMDD_HHMM_MatNr_Name.json)."""
    parts = fname.split("_")
    # parts[0] = Datum, parts[1] = Uhrzeit, parts[2] = Materialnummer
    return parts[2] if len(parts) > 2 else None

def run_update_management():
    sub_dir = "subrepo/groups"
    v1_dir = "projects/v1_0"

    # Sicherstellen, dass die Ordner existieren
    os.makedirs(sub_dir, exist_ok=True)
    os.makedirs(v1_dir, exist_ok=True)

    # 1. Initial-Check: Falls v1_0 leer ist, kopiere einfach alles initial rüber
    if not os.listdir(v1_dir):
        print(f"[*] Ordner '{v1_dir}' ist leer. Starte initiales Kopieren...")
        for f in os.listdir(sub_dir):
            if f.endswith(".json"):
                shutil.copy2(os.path.join(sub_dir, f), os.path.join(v1_dir, f))
                print(f"  -> Initial kopiert: {f}")
        print("[+] Initiales Setup abgeschlossen.\n")
        return

    # 2. Update-Logik: Bestehende v1_0 prüfen
    sub_files = [f for f in os.listdir(sub_dir) if f.endswith(".json")]
    v1_files = [f for f in os.listdir(v1_dir) if f.endswith(".json")]
    
    # Mapping: Materialnummer -> Dateiname für v1.0
    v1_mat_map = {get_mat_from_filename(f): f for f in v1_files if get_mat_from_filename(f)}

    print("[*] Starte Abgleich zwischen Subrepo und v1.0...\n")

    for s_file in sub_files:
        s_mat = get_mat_from_filename(s_file)
        if not s_mat:
            continue
            
        s_path = os.path.join(sub_dir, s_file)

        # --- FALL A: NEUES BAUTEIL (in v1_0 noch nicht vorhanden) ---
        if s_mat not in v1_mat_map:
            user_input = input(f"[?] NEUE DATEI gefunden: {s_file}. Zu v1.0 hinzufügen? (y/n): ").strip().lower()
            if user_input == 'y':
                shutil.copy2(s_path, os.path.join(v1_dir, s_file))
                print("  [+] Erfolgreich hinzugefügt.\n")
            else:
                print("  [-] Übersprungen.\n")

        # --- FALL B: BESTEHENDES BAUTEIL (Prüfe auf neue Gefahren / Append-Logik) ---
        else:
            v1_file = v1_mat_map[s_mat]
            v1_path = os.path.join(v1_dir, v1_file)
            
            # JSON-Daten laden
            try:
                with open(s_path, "r", encoding="utf-8") as f:
                    s_data = json.load(f)
                with open(v1_path, "r", encoding="utf-8") as f:
                    v1_data = json.load(f)
            except json.JSONDecodeError:
                print(f"[!] Fehler beim Lesen der JSON-Dateien für MatNr {s_mat}. Überspringe.")
                continue

            # Sicherstellen, dass wir die "threats"-Listen vergleichen
            s_threats = s_data.get("threats", [])
            v1_threats = v1_data.get("threats", [])

            # Sammle alle bestehenden Technique-IDs aus v1.0
            v1_ids = {item.get("technique_id") for item in v1_threats if item.get("technique_id")}
            
            # Filtere die neuen Gefahren heraus, deren ID noch nicht in v1.0 ist
            new_threats = [item for item in s_threats if item.get("technique_id") not in v1_ids]

            if new_threats:
                print(f"[*] ÄNDERUNG für MatNr {s_mat}: {len(new_threats)} neue Gefahr(en) im Subrepo gefunden.")
                for t in new_threats:
                    print(f"    -> [{t.get('technique_id')}] {t.get('name')}")
                
                user_input = input(f"[?] Diese {len(new_threats)} Gefahren an v1.0 ANHÄNGEN? (Expertenwissen bleibt erhalten) (y/n): ").strip().lower()
                
                if user_input == 'y':
                    # Append an die spezifische "threats" Liste im Dictionary
                    v1_data["threats"].extend(new_threats)
                    
                    # Metadaten updaten
                    v1_data["threats_found_count"] = len(v1_data["threats"])
                    v1_data["last_update"] = s_data.get("scan_timestamp")

                    # Datei neu schreiben
                    with open(v1_path, "w", encoding="utf-8") as f:
                        json.dump(v1_data, f, indent=4, ensure_ascii=False)
                    print("  [+] Gefahren erfolgreich angehängt.\n")
                else:
                    print("  [-] Übersprungen.\n")

    print("[*] Update-Management abgeschlossen.")

if __name__ == "__main__":
    run_update_management()


    
