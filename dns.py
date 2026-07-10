#!/usr/bin/env python3
import requests
import socket
import sys
import urllib3
import ipaddress

# ===== COLORS =====
G = '\033[1;32m'
B = '\033[1;34m'
Y = '\033[1;33m'
C = '\033[1;36m'
W = '\033[1;37m'
BW = '\033[1;97m'
GREY = '\033[90m'
R = '\033[1;31m'
RESET = '\033[0m'

# ===== NMAP TOOLKIT BANNER =====
BANNER = rf"""
{GREY}
          !\_________________________/!\\
          !!                         !! \\
          !!       DNS Toolkit      !!  \\
          !!                         !!   !
          !!          Free           !!   !
          !!                         !!   !
          !!         #hugs           !!   !
          !!                         !!  /
          !!_________________________!! /
          !/_________________________\\!/
              __\\_________________/__/!_
             !_______________________!/
{BW}
[---]        Nmap-Toolkit           [---]
[---]   Created by: Nur whoami136   [---]
[---]   Homepage: https://github.com/whoami136 [---]
{RESET}
"""

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Wordlist for Phase 2: Aggressive Fuzzing
FALLBACK_SUBS = ["dev", "test", "mail", "ftp", "stage", "direct", "api", "vpn", "cpanel", "webmail", "admin"]

def is_public(ip_str):
    """Filters out private, multicast, loopback, and reserved IPs."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return not (ip.is_private or ip.is_multicast or ip.is_loopback or ip.is_reserved)
    except: 
        return False

def check_origin_leak(ip, domain):
    """Checks if the raw IP responds to the domain host header."""
    headers = {'Host': domain, 'User-Agent': 'Mozilla/5.0'}
    try:
        for protocol in ["https", "http"]:
            r = requests.get(f"{protocol}://{ip}", headers=headers, timeout=3, verify=False)
            if r.status_code == 200: 
                return True
    except: 
        return False
    return False

def hunt(url):
    print(BANNER)
    domain = url.replace("https://", "").replace("http://", "").split('/')[0].replace("www.", "")
    print(f"\n{C}🌟 STARTING ORIGIN INVESTIGATION: {W}{domain}")

    # Phase 0: Resolve Main IP
    try:
        main_ip = socket.gethostbyname(domain)
        print(f"{Y}🌐 Target Resolved IP: {W}{main_ip}")
    except:
        print(f"{R}❌ Could not resolve domain.")
        return

    # Phase 1: Check for Direct Leak
    print(f"{C}🔍 Phase 1: Checking for direct leaks...")
    if is_public(main_ip) and check_origin_leak(main_ip, domain):
        print(f"{G}💥 BOOM! Origin Found: {W}{main_ip}")
        return
    
    print(f"{Y}⚠️ No direct leak found. Switching to Aggressive Hardened Mode...")

    # Phase 2: Aggressive Fuzzing
    print(f"{C}🔍 Phase 2: Running Aggressive Fuzzing...")
    for sub in FALLBACK_SUBS:
        sub_host = f"{sub}.{domain}"
        try:
            sub_ip = socket.gethostbyname(sub_host)
            if is_public(sub_ip) and check_origin_leak(sub_ip, domain):
                print(f"{G}💥 BOOM! Origin Found via {sub_host}: {W}{sub_ip}")
                return
        except: 
            continue

    print(f"\n{R}❌ Target is truly HARDENED. No origin leaks found.{RESET}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"{R}Usage: python3 dns.py <link>{RESET}")
        sys.exit()
    hunt(sys.argv[1])
