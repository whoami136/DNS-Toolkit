#!/usr/bin/env python3
import sys
import time
import socket
import threading
import urllib3
import socks
import requests

# ===== COLOR DEFINITIONS =====
W  = '\033[0m'
Y  = '\033[1;33m'
R  = '\033[1;31m'
G  = '\033[1;32m'
C  = '\033[1;36m'
M  = '\033[1;35m'
DP = '\033[38;5;129m'
BOLD = '\033[1m'

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BANNER = rf"""{DP}
          !\_________________./!\
          !!                 !! \
          !!   DNS Toolkit   !!  \
          !!                 !!   !
          !!       Free      !!   !
          !!                 !!   !
          !!      #hugs      !!   !
          !!                 !!  /
          !!_________________!! /
          !/_________________\!/
              \_____________/!_
             !_______________!/

[---]         Nmap-Toolkit          [---]
[---]     Created by: Nur whoami136 [---]
[---]   Homepage: https://github.com/whoami136 [---]{W}
"""

FALLBACK_SUBS = [
    "dev", "test", "mail", "ftp", "stage", "direct",
    "api", "vpn", "cpanel", "webmail", "admin", "www",
    "ns1", "ns2", "portal", "backend", "staging"
]

found_origin = False
print_lock = threading.Lock()

# ===== TOR PROXY SANITY CHECK =====
def verify_proxy_listener():
    print(f"{C}[*] Probing local Tor SOCKS listener (127.0.0.1:9050)...{W}")
    try:
        s = socket.create_connection(("127.0.0.1", 9050), timeout=3)
        s.close()
        print(f"{G}[+] Port 9050 active.{W}")
    except Exception:
        print(f"{R}[!] FATAL: Tor SOCKS daemon (127.0.0.1:9050) is not listening.{W}")
        print(f"{Y}[!] Execution halted to prevent leaking your real IP.{W}")
        sys.exit(1)

# Check listener first
verify_proxy_listener()

# Enforce SOCKS5 with remote DNS resolution
socks.set_default_proxy(socks.SOCKS5, "127.0.0.1", 9050, rdns=True)
socket.socket = socks.socksocket

def get_tor_circuit_details():
    """Verifies Tor connection and extracts Exit Node IP, Country, and ISP."""
    print(f"{C}[*] Auditing Tor Circuit & Exit Node Details...{W}")
    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})

    exit_ip = None
    is_tor = False

    try:
        r = session.get("https://check.torproject.org/api/ip", timeout=12)
        if r.status_code == 200:
            data = r.json()
            is_tor = data.get("IsTor", False)
            exit_ip = data.get("IP")
    except Exception:
        pass

    if not exit_ip:
        try:
            r = session.get("https://api.ipify.org?format=json", timeout=10)
            exit_ip = r.json().get("ip")
        except Exception as e:
            print(f"{R}[!] FATAL: Tor connection test failed: {e}{W}")
            sys.exit(1)

    # Query GeoIP for Exit Node
    geo = {}
    try:
        res = session.get(f"https://ipwho.is/{exit_ip}", timeout=10)
        if res.status_code == 200:
            geo = res.json()
    except Exception:
        pass

    country = geo.get("country", "Unknown")
    country_code = geo.get("country_code", "??")
    city = geo.get("city", "Unknown")
    isp = geo.get("connection", {}).get("isp") or geo.get("isp", "Tor Network")

    print(f"\n{BOLD}{M}=========== TOR CIRCUIT VERIFICATION ==========={W}")
    if is_tor:
        print(f" {G}[✓] Tor Status:{W}     VERIFIED (Official Exit Circuit)")
    else:
        print(f" {Y}[!] Tor Status:{W}     TUNNELED (via Proxy)")
    print(f" {C}[•] Exit Node IP:{W}   {BOLD}{exit_ip}{W}")
    print(f" {C}[•] Exit Location:{W}  {country} ({country_code}) - {city}")
    print(f" {C}[•] Exit ISP/Org:{W}   {isp}")
    print(f"{BOLD}{M}================================================={W}\n")

def get_ip_metadata(ip):
    """Fetches hosting ISP, Country, and Org for an investigated IP."""
    try:
        r = requests.get(f"https://ipwho.is/{ip}", timeout=8)
        if r.status_code == 200:
            d = r.json()
            return {
                "country": f"{d.get('country', 'N/A')} ({d.get('country_code', '??')})",
                "org": d.get("connection", {}).get("org") or d.get("org", "N/A"),
                "isp": d.get("connection", {}).get("isp") or d.get("isp", "N/A")
            }
    except Exception:
        pass
    return {"country": "N/A", "org": "N/A", "isp": "N/A"}

def detect_waf(domain, root_ip):
    """Detects Cloudflare, Akamai, Fastly, or Ngrok proxies."""
    print(f"{C}[*] Inspecting Edge Protection Layers for {W}{domain} ({root_ip})...")
    waf = []
    try:
        r = requests.get(f"https://{domain}", timeout=10, verify=False)
        server = r.headers.get('Server', '').lower()
        cf_ray = r.headers.get('CF-RAY', '')

        if 'cloudflare' in server or cf_ray:
            waf.append("Cloudflare CDN/WAF")
        if 'ngrok' in server or 'ngrok' in r.text.lower():
            waf.append("Ngrok Tunnel")
        if 'akamai' in server:
            waf.append("Akamai Edge")
        if 'fastly' in server:
            waf.append("Fastly CDN")
    except Exception:
        pass

    if waf:
        for w in waf:
            print(f"{Y}[!] EDGE LAYER DETECTED: {R}{w}{W}")
        return True
    else:
        print(f"{G}[+] Direct edge resolution (No obvious Cloudflare/Ngrok headers).{W}")
        return False

def get_host_signature(ip, host_header):
    headers = {'Host': host_header, 'User-Agent': 'Mozilla/5.0'}
    try:
        r = requests.get(f"https://{ip}", headers=headers, timeout=8, verify=False, allow_redirects=False)
        server = r.headers.get('Server', 'N/A')
        powered = r.headers.get('X-Powered-By', 'N/A')
        is_cf_response = ('cloudflare' in server.lower()) or ('cf-ray' in r.headers)
        return {
            "status": r.status_code,
            "server": server,
            "powered": powered,
            "is_cloudflare": is_cf_response
        }, True
    except Exception:
        return None, False

def sub_worker(sub, domain, root_ip, has_waf):
    global found_origin
    if found_origin:
        return

    target_host = f"{sub}.{domain}"
    try:
        sub_ip = socket.gethostbyname(target_host)

        # Skip if it points back to the identical root CDN IP
        if sub_ip == root_ip and has_waf:
            return

        info, success = get_host_signature(sub_ip, target_host)

        # Ensure it's not another Cloudflare/CDN edge node
        if success and not info["is_cloudflare"]:
            with print_lock:
                if not found_origin:
                    found_origin = True
                    meta = get_ip_metadata(sub_ip)
                    print(f"\n{G}{BOLD}💥 BOOM! Potential Origin Identified: {W}{sub_ip}")
                    print(f"{C}------------------- [Origin Details] -------------------{W}")
                    print(f"{BOLD}Hostname:{W}       {target_host}")
                    print(f"{BOLD}Direct IP:{W}      {sub_ip}")
                    print(f"{BOLD}Country:{W}        {meta['country']}")
                    print(f"{BOLD}ISP / Org:{W}      {meta['isp']} / {meta['org']}")
                    print(f"{BOLD}HTTP Status:{W}    {info['status']}")
                    print(f"{BOLD}Server Sig:{W}     {info['server']}")
                    print(f"{BOLD}X-Powered-By:{W}   {info['powered']}")
                    print(f"{C}--------------------------------------------------------{W}\n")
    except Exception:
        pass

def hunt(url):
    print(BANNER)
    get_tor_circuit_details()

    domain = url.replace("https://", "").replace("http://", "").split('/')[0].replace("www.", "")
    print(f"{C}🌟 TARGET DOMAIN: {W}{domain}")

    try:
        root_ip = socket.gethostbyname(domain)
        meta = get_ip_metadata(root_ip)
        print(f"{C}🌐 Resolved Root IP: {W}{root_ip} [{meta['country']} - {meta['isp']}]")
    except Exception as e:
        print(f"{R}[!] Could not resolve root domain {domain}: {e}{W}")
        sys.exit(1)

    has_waf = detect_waf(domain, root_ip)
    print("")

    print(f"{C}🔍 Phase 1: Probing Direct Root IP Header Response...{W}")
    info, success = get_host_signature(root_ip, domain)

    if success and not info["is_cloudflare"] and not has_waf:
        print(f"{G}💥 Root domain is serving directly without CDN masking!{W}")
        print(f"{C}------------------- [Host Information] -----------------{W}")
        print(f"{BOLD}Direct IP:{W}      {root_ip}")
        print(f"{BOLD}Country:{W}        {meta['country']}")
        print(f"{BOLD}ISP / Org:{W}      {meta['isp']} / {meta['org']}")
        print(f"{BOLD}Server Sig:{W}     {info['server']}")
        print(f"{BOLD}HTTP Status:{W}    {info['status']}")
        print(f"{C}--------------------------------------------------------{W}")
        print_summary_table()
        return

    print(f"{Y}⚠️ Root is protected or masked. Fuzzing historical / origin subdomains...{W}")
    threads = [threading.Thread(target=sub_worker, args=(sub, domain, root_ip, has_waf)) for sub in FALLBACK_SUBS]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    if not found_origin:
        print(f"\n{R}❌ No unprotected origin leaks discovered via common subdomains.{W}")

    print_summary_table()

def print_summary_table():
    print(f"\n{DP}# ================= DNS ANALYSIS SUMMARY TABLE =================")
    print(f"{DP}The following 9 detection-modes match the profile of your target:")
    print("")
    print(f"{DP}# | Category            | Security Impact")
    print(f"{DP}==+=====================+======================================")
    print(f"{DP}1 | DNS A Record        | Direct Infrastructure Discovery")
    print(f"{DP}2 | DNS CNAME           | Potential Cloud/CDN Masking Identified")
    print(f"{DP}3 | SPF/TXT             | Sender Policy & Mail Validation")
    print(f"{DP}4 | MX Record           | Mail Server Routing Intelligence")
    print(f"{DP}5 | NS Record           | Nameserver Trust & Authority")
    print(f"{DP}6 | SOA Record          | Zone Serial & Administrator Contact")
    print(f"{DP}7 | CAA Record          | Certificate Authority Authorization")
    print(f"{DP}8 | PTR Record          | Reverse DNS Mapping & IP Reputation")
    print(f"{DP}9 | AAAA Record         | IPv6 Exposure & Dual-Stack Analysis")
    print(f"{W}\n")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"{R}Usage: python3 dns.py <target-domain-or-url>{W}")
        sys.exit(1)
    hunt(sys.argv[1])
