import sqlite3
import pandas as pd
import os

DB_NAME = "threat_modeling.db"

def init_db():
    """Erstellt die Tabellen in der SQLite-Datenbank, falls sie nicht existieren."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    # Tabelle für die Threat-Modelle (basierend auf der Software/Basis-Plattform)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS threat_modelle (
            software_id TEXT PRIMARY KEY,
            keywords TEXT,
            last_scan TIMESTAMP,
            threats_count INTEGER DEFAULT 0
        )
    ''')

    # Tabelle für die physischen Produkte/Materialnummern
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS produkte (
            materialnummer TEXT PRIMARY KEY,
            bezeichnung TEXT,
            software_id TEXT,
            FOREIGN KEY (software_id) REFERENCES threat_modelle(software_id)
        )
    ''')
    
    conn.commit()
    return conn

def import_excel_to_db(filepath, conn):
    """Liest die Excel aus, gruppiert Legacy-Produkte und schreibt sie in die DB."""
    print(f"[*] Lese Excel-Datei: {filepath}")
    df = pd.read_excel(filepath)
    cursor = conn.cursor()

    # Zähler für die Statistik am Ende
    produkte_count = 0
    modelle_count = 0

    for index, row in df.iterrows():
        mat_nr = str(row.get('Material', '')).strip()
        if not mat_nr or mat_nr == 'nan':
            continue # Leere Zeilen überspringen

        bez = str(row.get('Materialkurztext', '')).strip()
        
        # --- DIE GRUPPIERUNGS-LOGIK ---
        # 1. Wir schauen, ob es eine spezifische Software in SAP gibt (wie in deinem Bild)
        software_id = str(row.get('Gefundene Software in SAP', '')).strip()
        
        # 2. Fallback, falls die Zelle leer ist: Wir schneiden das ".01" von der Materialnummer ab 
        # und nutzen die Basis-Nummer (z.B. "103501") als Modell-Gruppierung
        if not software_id or software_id == 'nan':
            software_id = mat_nr.split('.')[0] + "_base"

        # --- AB IN DIE DATENBANK ---
        
        # 1. Threat-Modell anlegen (falls es das für diese Software_id noch nicht gibt)
        # INSERT OR IGNORE sorgt dafür, dass wir bei 10 gleichen Modellen nur 1 Eintrag anlegen
        cursor.execute('''
            INSERT OR IGNORE INTO threat_modelle (software_id, keywords) 
            VALUES (?, ?)
        ''', (software_id, "")) # Keywords lassen wir bei Legacy erstmal leer
        
        if cursor.rowcount > 0:
            modelle_count += 1

        # 2. Produkt anlegen und mit dem Threat-Modell (software_id) verknüpfen
        cursor.execute('''
            INSERT OR REPLACE INTO produkte (materialnummer, bezeichnung, software_id) 
            VALUES (?, ?, ?)
        ''', (mat_nr, bez, software_id))
        
        produkte_count += 1

    conn.commit()
    print(f"[+] Import fertig! {produkte_count} Produkte in {modelle_count} eindeutige Threat-Modelle (Software-Gruppen) aufgeteilt.")

if __name__ == "__main__":
    # Datenbank initialisieren
    db_conn = init_db()
    
    # Excel Datei Name (aus deinem Bild) anpassen:
    excel_file = "4_fertige_ausgewertet_20260223_160359.xlsx"
    
    if os.path.exists(excel_file):
        import_excel_to_db(excel_file, db_conn)
    else:
        print(f"[!] Datei {excel_file} nicht gefunden. Bitte Pfad prüfen.")
        
    db_conn.close()



import json
import os
import shutil
import sqlite3
from datetime import datetime
from mitre_api import fetch_mitre_data

# --- KONFIGURATION ---
SUBREPO_PATH = "subrepo/groups"
DB_NAME = "threat_modeling.db"

def fetch_tasks_from_db():
    """Holt die einzigartigen Threat-Modelle (Software) aus der Datenbank."""
    if not os.path.exists(DB_NAME):
        print(f"[!] Datenbank '{DB_NAME}' nicht gefunden. Bitte zuerst setup_db.py ausführen.")
        return []
        
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT software_id, keywords FROM threat_modelle")
    rows = cursor.fetchall()
    conn.close()

    tasks = []
    for row in rows:
        tasks.append({
            'software_id': row[0],
            'keywords': row[1] if row[1] else "" # Fallback auf leeren String, falls None
        })
    return tasks

def update_db_stats(software_id, threats_count, timestamp):
    """Speichert die Ergebnisse des Scans in der Datenbank."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE threat_modelle 
        SET threats_count = ?, last_scan = ? 
        WHERE software_id = ?
    ''', (threats_count, timestamp, software_id))
    conn.commit()
    conn.close()

def run_pipeline():
    run_timestamp = datetime.now().strftime("%Y%m%d_%H%M")
    
    # --- 1. Aufräumen: Alten Ordner komplett löschen ---
    if os.path.exists(SUBREPO_PATH):
        shutil.rmtree(SUBREPO_PATH)
        print(f"[*] Alter Ordner '{SUBREPO_PATH}' wurde bereinigt.")
        
    os.makedirs(SUBREPO_PATH, exist_ok=True)
    
    # --- 2. Aufgaben aus der DB holen ---
    tasks = fetch_tasks_from_db()
    if not tasks:
        print("[-] Keine Threat-Modelle in der Datenbank gefunden. Abbruch.")
        return
        
    print(f"[*] {len(tasks)} einzigartige Threat-Modelle aus DB geladen.")
    
    # --- 3. Daten von MITRE holen & vorbereiten ---
    raw_data = fetch_mitre_data()
    mitigations = {obj['id']: obj for obj in raw_data if obj.get('type') == 'course-of-action'}
    mitigates_rels = [obj for obj in raw_data if obj.get('type') == 'relationship' and obj.get('relationship_type') == 'mitigates']
    malwares = {obj['id']: obj for obj in raw_data if obj.get('type') in ['malware', 'tool']}
    uses_rels = [obj for obj in raw_data if obj.get('type') == 'relationship' and obj.get('relationship_type') == 'uses']
    
    # --- 4. Pipeline für jedes Software-Modell ausführen ---
    for task in tasks:
        software_id = task['software_id']
        keywords_str = task['keywords']
        
        # Dateiname basierend auf der Software-ID generieren
        clean_name = "".join(e for e in software_id if e.isalnum() or e in " ._-").replace(" ", "_")
        filename = f"{run_timestamp}_{clean_name}.json"
        filepath = os.path.join(SUBREPO_PATH, filename)
        
        matched_threats = []
        
        # Nur bei MITRE suchen, wenn auch Keywords hinterlegt sind
        if keywords_str.strip():
            keywords = [k.strip().lower() for k in keywords_str.split(',')]
            
            for obj in raw_data:
                if obj.get('type') == 'attack-pattern':
                    name = obj.get('name', '').lower()
                    desc = obj.get('description', '').lower()
                    
                    if any(kw in name or kw in desc for kw in keywords):
                        obj_id = obj.get('id')
                        
                        # Mitigations sammeln
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
                                    
                        # Malware/Tools sammeln
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
                        
                        # MITRE ID extrahieren
                        mitre_id = "N/A"
                        url = ""
                        for ext_ref in obj.get('external_references', []):
                            if ext_ref.get('source_name') in ['mitre-attack', 'mitre-ics-attack']:
                                mitre_id = ext_ref.get('external_id', 'N/A')
                                url = ext_ref.get('url', '')
                                break
                        
                        matched_threats.append({
                            "technique_id": mitre_id,
                            "name": obj.get('name'),
                            "url": url,
                            "description": obj.get('description'),
                            "known_malware_and_tools": related_malware,
                            "mitigations": related_mitigations
                        })
        
        # JSON zusammenbauen
        output_data = {
            "software_id": software_id,
            "scan_timestamp": run_timestamp,
            "keywords_used": keywords_str,
            "threats_found_count": len(matched_threats),
            "threats": matched_threats
        }
        
        # Speichern
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(output_data, f, indent=4, ensure_ascii=False)
            
        # Datenbank mit den Ergebnissen des Scans updaten
        update_db_stats(software_id, len(matched_threats), run_timestamp)
        
        print(f"[+] {len(matched_threats)} Bedrohungen für '{software_id}' gefunden.")

    print("\n[*] Pipeline erfolgreich durchgelaufen!")

if __name__ == "__main__":
    run_pipeline()
                                    
