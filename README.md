# Active Network and Fingerprint Scanner

this is the first script in my **100 Python Red Team Tools** project.

## description

a simple Python tool that performs:

- ping sweep to check if host is up
- OS detection based on TTL from ping response
- port scanning on common ports (including 8080)
- banner grabbing on open ports (HTTP example)

## usage

1. modify the target IP address inside `scripts/001_active_network_scanner.py` (variable `target_ip`).
2. Run the script:

bash
python scripts/001_active_network_scanner.py
