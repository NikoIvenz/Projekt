import json
import os
from datetime import datetime
# from exel_baugruppe import get_excel_tasks
# from mitre_api import fetch_mitre_data

# --- KONFIGURATION ---
SUBREPO_PATH = "subrepo/groups"

# Nur diese Plattformen sind für Lütze Hardware relevant:
TEST = [
    {'materialnummer': '123', 'bezeichnung': 'CAN Bus', 'keywords': 'Can Bus'},
    {'materialnummer': '13',  'bezeichnung': 'Serial', 'keywords': 'Serial'},
    {'materialnummer': '33',  'bezeichnung': 'Ethernet','keywords': 'Ethernet'}
]

def filter_mitre_for_hardware(raw_mitre_data, hardware_list):
    """
    Filtert die MITRE-Daten basierend auf den Keywords der Hardware-Komponenten.
    Gibt eine strukturierte Liste zurück, die optimal für eine Threat Analyse ist.
    """
    analyzed_hardware = []

    for hw in hardware_list:
        # Keyword für die Suche vorbereiten (alles in Kleinbuchstaben für case-insensitive Suche)
        keyword = hw['keywords'].lower()
        
        # Struktur für das finale JSON aufbauen
        hw_threat_profile = {
            'materialnummer': hw['materialnummer'],
            'bezeichnung': hw['bezeichnung'],
            'suchbegriff': hw['keywords'],
            'gefundene_bedrohungen': []
        }

        # Durchsuche alle MITRE-Einträge
        for threat in raw_mitre_data:
            # Wir nehmen an, dass 'name' und 'description' die relevanten Felder im MITRE JSON sind.
            # Passe diese Keys an, falls deine fetch_mitre_data() Struktur anders aussieht.
            threat_name = threat.get('name', '').lower()
            threat_desc = threat.get('description', '').lower()
            
            # Wenn das Keyword im Namen oder der Beschreibung auftaucht, füge es hinzu
            if keyword in threat_name or keyword in threat_desc:
                hw_threat_profile['gefundene_bedrohungen'].append(threat)

        # Baugruppe nur hinzufügen, wenn auch Bedrohungen gefunden wurden
        # (Optional: Du kannst das if-Statement entfernen, wenn du auch Baugruppen mit 0 Threats protokollieren willst)
        if hw_threat_profile['gefundene_bedrohungen']:
            analyzed_hardware.append(hw_threat_profile)

    return analyzed_hardware


def run_pipeline():
    # 1. Setup & Timestamp
    run_timestamp = datetime.now().strftime("%Y%m%d_%H%M")
    os.makedirs(SUBREPO_PATH, exist_ok=True)
    
    print("[*] Starte MITRE Pipeline...")

    # 2. Daten abrufen (Hier würdest du deine Funktion aufrufen)
    print("[*] Beziehe rohe Daten von MITRE...")
    # raw_data = fetch_mitre_data()
    
    # --- DUMMY DATEN ZUM TESTEN DER PIPELINE ---
    raw_data = [
        {"id": "T0806", "name": "Brute Force", "description": "Adversaries may use brute force to compromise Ethernet networks."},
        {"id": "T0843", "name": "Program Download", "description": "Adversaries may download a new program over a Can Bus connection."},
        {"id": "T0861", "name": "Point & Tag Identification", "description": "Identify serial devices and read tags."},
        {"id": "T0888", "name": "Remote System Discovery", "description": "Unrelated protocol discovery."}
    ]
    # -------------------------------------------

    # 3. Daten filtern
    print("[*] Filtere Daten für Hardware-Threat-Analyse...")
    filtered_threat_data = filter_mitre_for_hardware(raw_data, TEST)

    # 4. Daten speichern
    output_filename = os.path.join(SUBREPO_PATH, f"threat_analysis_basis_{run_timestamp}.json")
    
    with open(output_filename, 'w', encoding='utf-8') as outfile:
        # indent=4 macht das JSON schön lesbar (Pretty Print)
        json.dump(filtered_threat_data, outfile, ensure_ascii=False, indent=4)
        
    print(f"[+] Pipeline erfolgreich beendet! Datei gespeichert unter: {output_filename}")


if __name__ == "__main__":
    run_pipeline()

