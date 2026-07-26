import sys
import socket
import time
import requests
from concurrent.futures import ThreadPoolExecutor
from typing import List, Set, Dict, Optional

_reverse_ip_cache: Dict[str, Set[str]] = {}
_reverse_ip_quota_esaurita = False

EXTENDED_PORTS = [
    20, 21, 22, 23, 25, 53, 69, 80, 81, 88, 110, 111, 119, 135, 137, 138, 139, 143, 161, 162,
    389, 443, 445, 465, 500, 514, 515, 523, 548, 587, 636, 873, 902, 989, 990, 993, 995,
    1080, 1194, 1433, 1434, 1521, 1723, 1883, 2049, 2082, 2083, 2086, 2087, 2095, 2096,
    2181, 2375, 2376, 3128, 3306, 3389, 3690, 4500, 4848, 5000, 5060, 5432, 5632, 5672,
    3000, 3001, 4443, 5900, 5901, 5984, 6000, 6379, 7001, 7002, 8000, 8008, 8080, 8081, 8088, 8443, 8500,
    8888, 9000, 9092, 9200, 9300, 9443, 9999, 11211, 27017, 27018, 27019, 50000, 6443
]

def _stampa_barra():
    print("=" * 75)

def _titolo(testo: str):
    print("")
    _stampa_barra()
    print(f"  [+] {testo.upper()}")
    _stampa_barra()

def _sotto_titolo(testo: str):
    print(f"\n---> {testo}")

def estrai_dominio_principale(dominio_inserito: str) -> str:
    parti = dominio_inserito.strip().lower().split('.')
    parti = [p for p in parti if p]
    if len(parti) <= 2:
        return ".".join(parti)
    estensioni_doppie = ["com", "co", "gov", "edu", "net", "org"]
    if parti[-2] in estensioni_doppie and len(parti) > 3:
        dominio_root = ".".join(parti[-3:])
    else:
        dominio_root = ".".join(parti[-2:])
    return dominio_root

def esegui_reverse_dns(ip: str) -> Optional[str]:
    try:
        nome_host, _, _ = socket.gethostbyaddr(ip)
        return nome_host.lower()
    except socket.herror:
        return None

def reverse_ip_lookup(ip: str) -> Set[str]:
    global _reverse_ip_cache, _reverse_ip_quota_esaurita
    
    if _reverse_ip_quota_esaurita:
        return set()
    
    if ip in _reverse_ip_cache:
        return _reverse_ip_cache[ip]
    
    domini: Set[str] = set()
    try:
        resp = requests.get(f"https://api.hackertarget.com/reverseiplookup/?q={ip}", timeout=10)
        testo = resp.text.strip()
        
        if "API count exceeded" in testo:
            _reverse_ip_quota_esaurita = True
            print("  [!] HackerTarget: quota giornaliera esaurita. Reverse IP lookup interrotto.")
            return set()
        
        if resp.status_code == 200 and testo and "error" not in testo.lower():
            for linea in testo.split("\n"):
                linea = linea.strip().lower()
                if linea:
                    domini.add(linea)
        
        _reverse_ip_cache[ip] = domini
        time.sleep(1.5)
    except Exception:
        pass
    return domini

def mappa_infrastruttura_certificati(dominio: str) -> Set[str]:
    hosts_rilevati: Set[str] = set()
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
    
    _sotto_titolo(f"Mappatura Infrastruttura tramite Certificate Fingerprinting per: {dominio}")
    url_crt = f"https://crt.sh/?q=%25.{dominio}&output=json"
    try:
        response = requests.get(url_crt, headers=headers, timeout=15)
        if response.status_code == 200:
            data = response.json()
            for cert in data:
                name_value = cert.get("name_value", "")
                for name in name_value.split("\n"):
                    name = name.strip().lower()
                    if name and not name.startswith("*."):
                        hosts_rilevati.add(name)
            print(f"  [OK] crt.sh ha mappato {len(hosts_rilevati)} nodi logici.")
            return hosts_rilevati
    except Exception:
        print("  [!] crt.sh temporaneamente sovraccarico. Avvio motori di riserva...")

    url_ht = f"https://api.hackertarget.com/hostsearch/?q={dominio}"
    try:
        response = requests.get(url_ht, headers=headers, timeout=10)
        if response.status_code == 200 and "error" not in response.text.lower():
            linee = response.text.strip().split("\n")
            for linea in linee:
                if "," in linea:
                    sub = linea.split(",")[0].strip().lower()
                    if sub:
                        hosts_rilevati.add(sub)
            print(f"  [OK] Motore alternativo ha recuperato {len(hosts_rilevati)} nodi host.")
    except Exception as e:
        print(f"  [!] Errore nei motori di riserva passivi: {e}")

    return hosts_rilevati

def mappa_dns_full(hosts: Set[str]) -> Dict[str, Dict]:
    _sotto_titolo("Generazione Mappa Combinata Forward & Reverse DNS...")
    mappa_infrastruttura: Dict[str, Dict] = {}
    
    for host in sorted(hosts):
        try:
            ips = list(set([info[4][0] for info in socket.getaddrinfo(host, None) if info[4][0]]))
            for ip in ips:
                if ip.startswith("127.") or ip.startswith("0."):
                    continue
                if ip not in mappa_infrastruttura:
                    mappa_infrastruttura[ip] = {"forward_domains": set(), "reverse_dns": None, "asn_org": "Sconosciuto"}
                mappa_infrastruttura[ip]["forward_domains"].add(host)
        except socket.gaierror:
            continue
            
    _sotto_titolo("Reverse IP Lookup in corso su HackerTarget per arricchimento domini...")
    for ip in mappa_infrastruttura.keys():
        domini_reverse = reverse_ip_lookup(ip)
        if domini_reverse:
            mappa_infrastruttura[ip]["forward_domains"].update(domini_reverse)
            print(f"  [OK] {ip}: +{len(domini_reverse)} domini aggiuntivi da reverse IP lookup")
    
    for ip in mappa_infrastruttura.keys():
        ptr_trovato = esegui_reverse_dns(ip)
        if ptr_trovato:
            mappa_infrastruttura[ip]["reverse_dns"] = ptr_trovato
            
        try:
            api_resp = requests.get(f"http://ip-api.com/json/{ip}?fields=reverse,as", timeout=5).json()
            if api_resp.get("status") != "fail":
                mappa_infrastruttura[ip]["asn_org"] = api_resp.get("as", "Sconosciuto")
                reverse_ext = api_resp.get("reverse", "").lower().strip(".")
                if reverse_ext and reverse_ext != ptr_trovato:
                    if not mappa_infrastruttura[ip]["reverse_dns"]:
                        mappa_infrastruttura[ip]["reverse_dns"] = reverse_ext
                    elif reverse_ext not in mappa_infrastruttura[ip]["reverse_dns"]:
                        mappa_infrastruttura[ip]["reverse_dns"] += f" / {reverse_ext}"
        except Exception:
            pass

    print("\n" + "-"*75)
    print("  MAPPA BI-DIREZIONALE DEGLI IP (FORWARD + REVERSE DETECTED)")
    print("-"*75)
    for ip, dati in mappa_infrastruttura.items():
        print(f"\n[IP TARGET] -> {ip}  ({dati['asn_org']})")
        
        if dati['reverse_dns']:
            print(f"  +-> [Reverse DNS / PTR]: {dati['reverse_dns']}  <-- COABITAZIONE/INFR. HOSTING")
        else:
            print("  +-> [Reverse DNS / PTR]: Nessun puntamento PTR pubblico configurato")
            
        print("  +-> Puntamenti Forward DNS emersi:")
        for s in sorted(dati["forward_domains"]):
            print(f"       +-> [Domain] {s}")
            
    return mappa_infrastruttura

def check_singola_porta(ip: str, porta: int) -> Optional[int]:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1.0)
        if s.connect_ex((ip, porta)) == 0:
            return porta
    return None

def scansiona_porte_host_esteso(ip: str) -> List[int]:
    porte_aperte = []
    with ThreadPoolExecutor(max_workers=50) as executor:
        risultati = executor.map(lambda p: check_singola_porta(ip, p), EXTENDED_PORTS)
        for r in risultati:
            if r is not None:
                porte_aperte.append(r)
    return sorted(porte_aperte)

def analizza_ip_via_shodan_internetdb(ip: str):
    url = f"https://internetdb.shodan.io/{ip}"
    try:
        resp = requests.get(url, headers={"User-Agent": "parallax/1.0"}, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            print(f"      +-> Porte storiche Shodan globali: {data.get('ports', [])}")
            print(f"      +-> Tag rilevati: {data.get('tags', [])}")
            cves = data.get("vulns", [])
            print(f"      +-> CVE Rilevate totali: {len(cves)} vulnerabilita note")
        elif resp.status_code == 404:
            print("      +-> Nessun record storico globale presente nei log passivi.")
    except Exception:
        print("      [!] Impossibile arricchire l'IP passivamente (Timeout).")

def esegui_mappatura():
    input_utente = input("\n[?] Inserisci il dominio da mappare (es. azienda.com): ").strip().lower()
    if not input_utente:
        return
        
    dominio_root = estrai_dominio_principale(input_utente)
    _titolo(f"Mappatura Infrastruttura Completa: {dominio_root}")
    
    nodi_host = mappa_infrastruttura_certificati(dominio_root)
    hosts_totali = nodi_host | {input_utente, dominio_root}
    
    mappa_infrastruttura = mappa_dns_full(hosts_totali)
    
    if not mappa_infrastruttura:
        print("\n[-] Nessun record DNS valido estratto.")
        return
        
    _stampa_barra()
    print(f"  [+] ANALISI COMPLETATA: {len(mappa_infrastruttura)} IP distinti decodificati.")
    _stampa_barra()
    
    ispezionare = input("\n[?] Vuoi lanciare la scansione live ampliata (100 Porte + CVE) su TUTTI gli IP? (s/n): ").strip().lower()
    if ispezionare == 's':
        for ip in mappa_infrastruttura.keys():
            print(f"\n[+] Scansione Massiva Live in corso per l'IP: {ip} ...")
            porte = scansiona_porte_host_esteso(ip)
            print(f"      +-> Porte APERTE rilevate adesso: {porte if porte else 'Nessuna delle 100 porte testate'}")
            analizza_ip_via_shodan_internetdb(ip)

def main():
    while True:
        print("\n" + "="*50)
        print("  PARALLAX RECON TOOL v1.0")
        print("="*50)
        print("  1. Avvia Mappatura Avanzata Dominio")
        print("  2. Esci")
        print("-" * 50)
        try:
            scelta = input("  Scegli un'opzione [1-2]: ").strip()
        except EOFError:
            break
            
        if scelta == "1":
            esegui_mappatura()
        elif scelta == "2":
            print("\nChiusura del tool.\n")
            sys.exit(0)
        else:
            if scelta:
                print(f"[!] Opzione non valida.")

if __name__ == "__main__":
    main()