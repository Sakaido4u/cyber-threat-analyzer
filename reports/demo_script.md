# 10-Minute Demo Script — Cyber Threat Analyzer

## Before the examiner arrives (setup checklist, 5 min)

- [ ] Laptop on charger, notifications off, screen resolution 1920×1080, browser zoom 100 %.
- [ ] Open **PowerShell #1** in the project folder and run `.\venv\Scripts\Activate.ps1`.
- [ ] Open **PowerShell #2**, activate the venv, run `streamlit run dashboard\app.py` and leave it running.
- [ ] Browser tab 1: `http://localhost:8501/?sample=lab/mixed_attacks.pcap` (already analysed — cached).
- [ ] Wireshark open with `data\lab\mixed_attacks.pcap` loaded.
- [ ] `reports\report.docx` and the folder `reports\figures\` open in Explorer.
- [ ] **Backup:** `screenshots\` folder open, in case anything fails live (see the table at the end).

---

## 0:00 – 1:00 · Problem and goal (talk, no screen)

> "Attacks leave fingerprints in network traffic. A scanner touches hundreds of ports, a flood leaves half-open handshakes, an ARP spoofer claims somebody else's IP, and old protocols carry passwords in clear text. Our tool reads a packet capture, measures these fingerprints and reports each attack with evidence you can verify in Wireshark. All traffic is either public sample captures or generated offline for our own lab, so no network was attacked."

## 1:00 – 2:00 · Design (show `reports/architecture.png`)

Point along the pipeline: **PCAP → parser (Scapy) → features (pandas, 10-second windows) → 8 detectors (thresholds in config.py) → alerts → CLI + dashboard**.
Show `src\config.py` for 10 seconds: "Every threshold is in one file, and each one comes from the rule table in our design."

## 2:00 – 4:00 · Command-line analysis (PowerShell #1)

```powershell
python src\main.py --pcap data\lab\mixed_attacks.pcap
```

Say while it runs (~10 s): "38,000 packets, 10 minutes of lab traffic with nine attacks mixed into normal traffic."
Then scroll through the output and read out three alerts:

1. **Port Scan (High)** — "1000 ports in 2.5 s, the target replied RST 998 times, and it found that ports 22 and 80 are open."
2. **ARP Spoofing (Critical)** — "The gateway IP .1 was claimed by a second MAC, which also claims .101 — that's the attacker. Critical because it's the gateway: man-in-the-middle."
3. **Plaintext Credentials (Telnet)** — "The user typed one character per packet; we replay the session after the `login:` prompt. The password is masked on purpose."

## 4:00 – 5:00 · Prove one alert in Wireshark

Copy the `wireshark:` filter printed under the Port Scan alert, for example
`ip.src==192.168.56.101 && ip.dst==192.168.56.20 && tcp.flags.syn==1 && tcp.flags.ack==0`
and paste it into Wireshark → show the wall of SYN packets with increasing port numbers.
Optional: **Statistics → Conversations → TCP** to show 1000 conversations from one host.

> "Every alert carries a filter like this, so an analyst never has to trust the tool blindly."

## 5:00 – 7:30 · Dashboard (browser)

1. **Header metrics** — packets, duration, 4,815 source IPs ("most of those are spoofed SYN-flood sources"), 14 alerts.
2. **Traffic overview tab** — packets-per-second chart: point at the spikes (port scan, SYN flood, ICMP flood). "But ARP spoofing and credential theft cause no spike at all — that's why we need protocol-aware rules, not just volume."
3. **Alerts tab** — filter Severity = Critical (2 alerts: ARP spoofing of the gateway, and the FTP brute force whose last guess succeeded). Type `192.168.56.101` into the search box → everything the attacker did.
4. **Alert drill-down tab** — choose the **SYN Flood** alert: peak 801 SYN/s, completed-handshake ratio 0.00, 4,801 sources. Show the related-packets chart.
5. Sidebar → **Upload a PCAP** → upload `data\public\telnet-raw.pcap` (a *real* capture from Wireshark's sample library) → 1 alert: Telnet credentials for user `fake`. "Works on real traffic, not only ours."

## 7:30 – 9:00 · Evaluation (show `reports/figures/`)

- `detection_per_attack.png` — "32 of 33 attacks detected, 97 %, and **zero false positives** on four attack-free captures."
- `slow_scan_window_sensitivity.png` — "Our one miss: a scan at one port every 15 s never reaches 20 ports in a 10-s window. A 300-s window would catch it — this is the classic evasion technique."
- `ml_confusion_matrices.png` — "A Random Forest caught the slow scan, but produced 24 false-positive flows against our 5, and it cannot see ARP or passwords at all. So rules give precision and explanations, ML gives recall; a real system would use both."
- Optional: "We also found and fixed a false positive — a YouTube CDN hostname looked random. A tunnel never repeats names, so we count unique names."

## 9:00 – 10:00 · Countermeasures and close

> "For each attack the report lists the fix: SYN cookies against floods, Dynamic ARP Inspection against spoofing, fail2ban and SSH keys against brute force, and most importantly replacing FTP, Telnet and HTTP with SFTP, SSH and HTTPS. Limitations are encrypted traffic, slow attacks and fixed thresholds; future work is adaptive thresholds and TLS fingerprinting. Thank you — happy to take questions."

---

## If something fails live

| Failure | Do this instead |
|---|---|
| CLI crashes or is slow | Show `screenshots\cp4_cli_alerts.png` and `reports\output\mixed_attacks\alerts.csv` |
| Streamlit won't start | Show `screenshots\cp6_dashboard_overview.png`, `cp6_dashboard_alerts.png`, `cp6_dashboard_drilldown.png` |
| Port 8501 busy | `streamlit run dashboard\app.py --server.port 8502` |
| Wireshark issue | Show `screenshots\cp2_ws_*.png` |
| Laptop dies | Report PDF + all screenshots on a USB stick / Google Drive |

## Likely viva questions during the demo (short answers)

- *Why are there 4,815 source IPs?* The SYN flood spoofs a random source address per packet.
- *Why is the ARP alert Critical but the scan only High?* ARP spoofing of the gateway is an active man-in-the-middle on all traffic; a scan is reconnaissance.
- *Is it safe to show passwords?* We mask them (`S**********`) and the dashboard hides payloads.
- *Why not just use Snort?* Goal was to understand and explain detection from first principles; Snort rules are a good next step.
