# DNS-Toolkit
DNS-Toolkit An automated reconnaissance utility designed to uncover the origin IP addresses of domains protected by WAFs (Web Application Firewalls). It performs target resolution, direct leak checks, and aggressive subdomain fuzzing to identify potential origin exposures.

DNS-Toolkit 🛡️
DNS-Toolkit is an automated reconnaissance utility designed to uncover origin IP addresses of domains protected by WAFs (Web Application Firewalls). It combines network resolution, direct origin leak detection, and aggressive service probing to identify infrastructure exposures.

📦 Installation
```bash
# 1. Update your package manager
sudo apt update && sudo apt upgrade -y

# 2. Install Python3 and Pip if not already present
sudo apt install python3 python3-pip -y

# 3. Clone the repository
git clone git@github.com:whoami136/DNS-Toolkit.git
cd DNS-Toolkit

# 4. Install required Python libraries
pip3 install requests urllib3

# 5. Configure Proxychains for anonymity
sudo nano /etc/proxychains.conf
💻 Usage
Anonymous Scan (Recommended)
You should run the tool using proxychains4 to ensure your reconnaissance traffic is routed through your proxy configuration:

proxychains4 python3 dns.py https://target-domain.com

🔍 How it Works
Phase 1: DNS Resolution: Translates the target URL into its primary resolved IP.

Phase 2: Direct Origin Leak: Probes the resolved IP directly using the original Host header to see if the server bypasses the WAF.

Phase 3: SSH Probing: Automatically checks if port 22 is open on the target to identify management interfaces.

Phase 4: Aggressive Fuzzing: Cycles through a curated wordlist of common subdomains (dev, stage, cpanel, git, etc.) and repeats the leak/SSH detection logic for every resolved endpoint.

⚠️ Disclaimer
This tool is intended for educational and authorized security research purposes only. Users are responsible for ensuring they have explicit permission to test the target infrastructure. The author, whoami136, assumes no liability for the misuse of this tool.

Created by: Nur whoami136 | Homepage: https://github.com/whoami136
