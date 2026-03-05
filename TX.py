import json
import os
import shutil
from datetime import datetime
#from exel_baugruppe import get_excel_tasks
from mitre_api import fetch_mitre_data

# --- KONFIGURATION ---
SUBREPO_PATH = "subrepo/groups"

# Nur diese Plattformen sind für Lütze Hardware relevant:
# WICHTIG: Mehrere Suchbegriffe (Keywords) werden jetzt durch Komma getrennt!
TEST = [
    {'materialnummer': '123', 'bezeichnung': 'CAN Bus', 'keywords': 'can bus, controller area network, fieldbus'},
    {'materialnummer': '13',  'bezeichnung': 'Serial',  'keywords': 'serial, rs-232, rs-485'},
    {'materialnummer': '33',  'bezeichnung': 'Ethernet','keywords': 'ethernet, tcp/ip'}
]

def run_pipeline():
    run_timestamp = datetime.now().strftime("%Y%m%d_%H%M")
    
    # --- 1. Aufräumen: Alten Ordner komplett löschen, falls er existiert ---
    if os.path.exists(SUBREPO_PATH):
        shutil.rmtree(SUBREPO_PATH)
        print(f"[*] Alter Ordner '{SUBREPO_PATH}' wurde bereinigt.")
        
    # Ordner frisch und leer neu anlegen
    os.makedirs(SUBREPO_PATH, exist_ok=True)
    
    # Daten von MITRE holen
    raw_data = fetch_mitre_data()
    #tasks = get_excel_tasks("Produktliste_Luetze.xlsx")
    tasks = TEST
    
    # --- 2. Mapping vorbereiten für Performance ---
    # Gegenmaßnahmen (Mitigations)
    mitigations = {obj['id']: obj for obj in raw_data if obj.get('type') == 'course-of-action'}
    mitigates_rels = [obj for obj in raw_data if obj.get('type') == 'relationship' and obj.get('relationship_type') == 'mitigates']
    
    # Malware und Tools
    malwares = {obj['id']: obj for obj in raw_data if obj.get('type') in ['malware', 'tool']}
    uses_rels = [obj for obj in raw_data if obj.get('type') == 'relationship' and obj.get('relationship_type') == 'uses']
    
    for task in tasks:
        clean_name = "".join(e for e in task['bezeichnung'] if e.isalnum() or e == " ").replace(" ", "_")
        filename = f"{run_timestamp}_{task['materialnummer']}_{clean_name}.json"
        filepath = os.path.join(SUBREPO_PATH, filename)
        
        # Keywords am Komma trennen und säubern
        keywords = [k.strip().lower() for k in task['keywords'].split(',')]
        matched_threats = []
        
        # --- 3. Filtere die MITRE-Daten nach den Keywords ---
        for obj in raw_data:
            if obj.get('type') == 'attack-pattern':
                name = obj.get('name', '').lower()
                desc = obj.get('description', '').lower()
                
                # Prüfe, ob IRGENDEIN Keyword aus unserer Liste im Namen oder in der Beschreibung vorkommt
                if any(kw in name or kw in desc for kw in keywords):
                    obj_id = obj.get('id')
                    
                    # --- 4. Suche nach passenden Gegenmaßnahmen (Mitigations) ---
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
                                
                    # --- 5. Suche nach Malware/Tools, die diese Technik nutzen ---
                    related_malware = []
                    for rel in uses_rels:
                        if rel.get('target_ref') == obj_id:
                            malware_id = rel.get('source_ref')
                            if malware_id in malwares:
                                mal_obj = malwares[malware_id]
                                related_malware.append({
                                    "name": mal_obj.get('name'),
                                    "type": mal_obj.get('type'),
                                    "description": mal_obj.get('description')
                                })
                    
                    # --- 6. Extrahiere die MITRE ID (z.B. T1000) ---
                    mitre_id = "N/A"
                    url = ""
                    for ext_ref in obj.get('external_references', []):
                        if ext_ref.get('source_name') in ['mitre-attack', 'mitre-ics-attack']:
                            mitre_id = ext_ref.get('external_id', 'N/A')
                            url = ext_ref.get('url', '')
                            break
                    
                    # --- 7. Füge den Treffer zur Liste hinzu ---
                    matched_threats.append({
                        "technique_id": mitre_id,
                        "name": obj.get('name'),
                        "url": url,
                        "description": obj.get('description'),
                        "known_malware_and_tools": related_malware,
                        "mitigations": related_mitigations
                    })
        
        # --- 8. Baue das finale JSON-Dokument ---
        output_data = {
            "hardware_info": task,
            "scan_timestamp": run_timestamp,
            "threats_found_count": len(matched_threats),
            "threats": matched_threats
        }
        
        # --- 9. Speichere die Datei ab ---
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(output_data, f, indent=4, ensure_ascii=False)
            
        print(f"[+] {len(matched_threats)} Bedrohungen für '{task['bezeichnung']}' gefunden. Gespeichert in: {filepath}")

if __name__ == "__main__":
    run_pipeline()

    
