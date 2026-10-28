"""
Detection thresholds (from the Checkpoint 1 design rule table).

All detectors read their limits from here, so tuning in Checkpoint 7 means
changing numbers in this one file only.
"""

# Length of one time window used for per-source statistics (seconds)
WINDOW_SECONDS = 10

# 1. Port scan: one source probing many ports on one target
PORTSCAN_MIN_UNIQUE_PORTS = 20          # distinct destination ports in one window
PORTSCAN_HIGH_UNIQUE_PORTS = 100        # above this the scan is rated High

# 2. SYN flood: many SYNs to one target, few completed handshakes
SYNFLOOD_MIN_SYN_RATE = 100             # peak SYN packets per second to one destination
SYNFLOOD_MAX_ACK_RATIO = 0.2            # completed handshakes / SYNs
SYNFLOOD_CRITICAL_RATE = 1000           # above this the flood is rated Critical
SYNFLOOD_MAX_TARGET_PORTS = 5           # SYNs spread over more ports = a scan, not a flood

# 3. ARP spoofing: one IP claimed by more than one MAC
ARP_MAX_MACS_PER_IP = 1                 # alert when an IP maps to more MACs than this
GATEWAY_IPS = {"192.168.56.1", "192.168.1.1", "192.168.0.1", "10.0.0.1"}

# 4. Brute force: repeated connections to a login service
#    Port 80 is NOT counted by connections (browsers open many connections);
#    HTTP brute force is detected from "401 Unauthorized" replies instead.
BRUTEFORCE_PORTS = {21: "FTP", 22: "SSH", 23: "Telnet", 3389: "RDP"}
BRUTEFORCE_WINDOW_SECONDS = 60
BRUTEFORCE_MIN_ATTEMPTS = 10            # new connections (SYNs) per source per window
BRUTEFORCE_MIN_FAILED_LOGINS = 5        # FTP 530 / HTTP 401 replies per window

# 5. Plaintext credentials: any single occurrence is reported
CREDENTIAL_PORTS = {21: "FTP", 23: "Telnet", 80: "HTTP", 110: "POP3", 143: "IMAP"}
CREDENTIAL_KEYWORDS = ["user", "pass", "pwd", "login", "username", "password"]

# Optional extras
DNS_MAX_QNAME_LENGTH = 50               # characters in the full query name
DNS_MAX_LABEL_ENTROPY = 3.5             # Shannon entropy (bits/char) of the subdomain
DNS_MIN_ENTROPY_LENGTH = 16             # entropy is only meaningful on longer strings
DNS_MIN_SUSPICIOUS_QUERIES = 5          # UNIQUE suspicious names per source+domain before alerting
ICMP_FLOOD_MIN_RATE = 100               # peak echo requests per second to one destination
SUSPICIOUS_PORTS = {4444, 1337, 31337, 6667, 12345}

# Severity levels, lowest to highest
SEVERITY_LEVELS = ["Low", "Medium", "High", "Critical"]
