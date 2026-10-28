# Checkpoint Guide — what was built, how to verify it, what to screenshot, viva prep

Run every command from `C:\Users\Shubh\Documents\cns_ass\ass_2` with the venv active:
`.\venv\Scripts\Activate.ps1`

---

## Checkpoint 0 — Environment setup ✅

**Done when**
- [x] Python 3.14 venv, `pip check` → `No broken requirements found.`
- [x] Npcap + Wireshark 4.6.9 installed
- [x] `python src\test_setup.py data\http.cap` prints 10 packets

**Screenshots:** `cp0_versions.png`, `cp0_test_script.png`, `cp0_wireshark_http.png` (done), `cp0_pip_check.png`

**Viva**
1. *Why a virtual environment?* Isolates and pins library versions → reproducible.
2. *What is Npcap?* Windows packet-capture driver used by Wireshark/Scapy.
3. *Why did you drop PyShark?* Version 0.6 crashes on Python 3.14 (asyncio event-loop change); Scapy covers every field we need.

---

## Checkpoint 1 — Background study & design ✅

**Files:** `reports/design_summary.md`, `reports/architecture.png`, `src/config.py`, report Sections 5–6.

**Done when**
- [x] Each attack explained: mechanism, OSI layer, signature, rule
- [x] Architecture diagram, module list, rule table (attack | indicator | threshold | why)

**Screenshots:** `architecture.png` is already the figure.

**Viva**
1. *Which OSI layer does ARP spoofing attack and why is it possible?* Layer 2; ARP has no authentication and hosts accept unsolicited replies.
2. *Why does a SYN flood work?* The server reserves state for each half-open connection; spoofed SYNs never complete, filling the backlog.
3. *Why rules instead of ML as the main engine?* Explainable evidence, no training data, low false positives; ML used as comparison.

---

## Checkpoint 2 — Data collection ✅

**What we have**
- `data\public\` — real Wireshark samples: `telnet-raw.pcap`, `telnet-cooked.pcap` (plaintext login), `dns.cap`, `arp-storm.pcap` (normal) + `data\http.cap`.
- `data\lab\` — 11 labelled captures built **offline** by `python src\generate_lab_pcaps.py` (nothing is transmitted) + `labels.csv` ground truth.
- `data\lab_test\` — independent copy (seed 2) for ML testing.

**Done when**
- [x] Every target attack has at least one PCAP
- [ ] Wireshark screenshot of each attack's signature (list below)

**Screenshots to take in Wireshark** (open the PCAP, paste the filter, screenshot):

| File name | PCAP | Filter | What it shows |
|---|---|---|---|
| `cp2_ws_portscan.png` | lab\port_scan.pcap | `tcp.flags.syn==1 && tcp.flags.ack==0 && ip.src==192.168.56.101` | SYNs to ever-changing ports |
| `cp2_ws_portscan_rst.png` | lab\port_scan.pcap | `tcp.flags.reset==1 && ip.dst==192.168.56.101` | Target's RST replies (closed ports) |
| `cp2_ws_synflood.png` | lab\syn_flood.pcap | `tcp.flags.syn==1 && tcp.flags.ack==0 && tcp.dstport==80` | Random source IPs, all to port 80 |
| `cp2_ws_synflood_io.png` | lab\syn_flood.pcap | Statistics → I/O Graphs | The spike |
| `cp2_ws_arpspoof.png` | lab\arp_spoof.pcap | `arp.src.proto_ipv4==192.168.56.1` | Two MACs for .1 (Wireshark also shows "duplicate use of IP" expert info) |
| `cp2_ws_bruteforce_ftp.png` | lab\brute_force.pcap | `ftp.response.code==530` | Repeated "Login incorrect" |
| `cp2_ws_bruteforce_ssh.png` | lab\brute_force.pcap | `tcp.dstport==22 && tcp.flags.syn==1` | 40 connections in 60 s |
| `cp2_ws_ftp_pass.png` | lab\plaintext_credentials.pcap | `ftp.request.command=="USER" \|\| ftp.request.command=="PASS"` | Password in clear |
| `cp2_ws_http_basic.png` | lab\plaintext_credentials.pcap | `http.authorization` (expand → Wireshark decodes Base64) | Base64 ≠ encryption |
| `cp2_ws_telnet_stream.png` | public\telnet-raw.pcap | `telnet` → right-click → Follow → TCP Stream | Real login: user `fake` |
| `cp2_ws_dns_tunnel.png` | lab\dns_tunnel.pcap | `dns.qry.name contains "tunnel-c2"` | Long random subdomains |
| `cp2_ws_icmp_flood.png` | lab\icmp_flood.pcap | `icmp.type==8` | 500 pings/s |

**Optional real lab (only if your examiner wants a live capture)**

> ⚠️ **SAFETY:** Only inside VirtualBox **host-only** networking with your own VMs. Never on college Wi-Fi, hostel LAN, or any network you do not own. Disconnect the VMs' NAT adapter while attacking.

1. VirtualBox → File → Tools → Network Manager → create a Host-only network `192.168.56.0/24`.
2. Kali VM and Ubuntu (target) VM: Adapter 1 = Host-only. Ubuntu: `sudo apt install openssh-server vsftpd`.
3. On Windows host, Wireshark: capture on "VirtualBox Host-Only Ethernet Adapter" only.
4. From Kali: `nmap -sS 192.168.56.<ubuntu>` and `hydra -l testuser -P small_list.txt ssh://192.168.56.<ubuntu> -t 4` (use a test account you created).
5. Save as `data\lab\real_lab_capture.pcapng`, then `python src\main.py --pcap data\lab\real_lab_capture.pcapng`.

**Viva**
1. *Why generate traffic instead of capturing college traffic?* Ethics and law: capturing others' traffic without consent is interception; generated traffic also gives exact ground truth.
2. *Is generated traffic realistic?* Attacks are modelled on real tools (nmap -sS, hping3, arpspoof, hydra, iodine) and mixed into normal background; we also validated on real public captures. Limitation: real networks are noisier.
3. *What does `arp-storm.pcap` test?* Many ARP requests but every IP has one MAC → must NOT alert (hard negative).

---

## Checkpoint 3 — Parser and feature extraction ✅

```powershell
python src\parser.py data\lab\port_scan.pcap --csv reports\output\port_scan\packets.csv
python src\features.py data\lab\port_scan.pcap --csv reports\output\port_scan\features.csv
```

**Expected:** packet summary (7,368 packets, TCP/DNS/ICMP/UDP/ARP counts), then a top-10 table where `192.168.56.101` has ~1000 `unique_dst_ports` and ~1000 `syn` with `ack` ≈ 0.

**Done when**
- [x] Clean `packets.csv` (one row per packet) and `features.csv` (per source per 10-s window) for each PCAP

**Screenshots:** `cp3_parser_output.png`, `cp3_features_top10.png`, `cp3_packets_csv_excel.png` (open CSV in Excel)

**Viva**
1. *Why time windows?* Attacks are about rate (many X in short time); windows turn a packet stream into per-source counts.
2. *What is Shannon entropy and why use it for DNS?* Average bits of information per character; encoded/random data ≈ 4.5–5, normal names ≈ 2.5–3.5.
3. *Why `PcapReader` and not `rdpcap`?* Streaming — doesn't load the whole file into memory.

---

## Checkpoint 4 — Rule-based detectors ✅

```powershell
python src\main.py --pcap data\lab\mixed_attacks.pcap
python src\main.py --pcap data\lab\normal_traffic.pcap
python src\main.py --pcap data\public\telnet-raw.pcap
```

**Expected:** 14 alerts on mixed (Port Scan, ARP Spoofing (Critical), Brute Force ×2 (FTP Critical — last guess succeeded; SSH High), 6× Plaintext Credentials, SYN Flood, DNS Tunneling, ICMP Flood, Suspicious Port); **0 alerts** on normal; 1 Telnet credential alert (user `fake`) on the real capture.

**Done when**
- [x] Each detector fires on its PCAP, quiet on normal traffic (verified by `evaluate.py`)

**Screenshots:** `cp4_cli_alerts.png` (mixed), `cp4_cli_normal.png` (0 alerts), `cp4_cli_telnet_real.png`

**Viva**
1. *How do you tell a SYN flood from a fast port scan? Both have many SYNs.* Scan = one source, many ports; flood = one/few ports, many (spoofed) sources, ACK ratio ≈ 0. Rule: flood requires ≤ 5 target ports.
2. *Why isn't port 80 in the brute-force connection rule?* Browsers open many parallel connections → false positives; HTTP brute force uses 401 replies instead.
3. *How do you extract a Telnet password when each packet holds one character?* Replay the session: after the server sends `Password:`, concatenate client characters until Enter, removing Telnet IAC negotiation bytes.

---

## Checkpoint 5 — ML comparison ✅

```powershell
python src\ml_compare.py
```

**Expected:** comparison table — Rules: precision 97.2 %, recall 84.1 %, 5 FP flows; RF: precision 87.0 %, recall 94.4 %, 24 FP flows; "Slow scan flows: 40 | rules caught 0 | RF caught 40".
Optional: download a CIC-IDS2017 MachineLearningCSV file and run `python src\ml_compare.py --cic <file.csv>`.

**Done when**
- [x] `reports/evaluation/ml_vs_rules_summary.csv`, `ml_confusion_matrices.png`, `ml_feature_importance.png`

**Screenshots:** the two figures + `cp5_ml_console.png`

**Viva**
1. *Why train on seed 1 and test on seed 2?* Testing on training data overstates accuracy; a separately generated dataset checks generalisation.
2. *Why is accuracy (99.8 %) misleading?* Classes are imbalanced — always predicting "Normal/SYN Flood" scores high. Macro precision/recall per attack class is more honest.
3. *Why can't the RF detect ARP spoofing or plaintext passwords?* Its features are IP flow statistics; ARP has no IP flow and passwords need payload inspection.

---

## Checkpoint 6 — Dashboard ✅

```powershell
streamlit run dashboard\app.py
```
Open `http://localhost:8501` (or `http://localhost:8501/?sample=lab/mixed_attacks.pcap` to jump straight to a sample).

**Done when**
- [x] Upload works end-to-end on a fresh PCAP (tested automatically on all 14 alerts' drill-downs)

**Screenshots (needed by the report — use these exact names):**
- `cp6_dashboard_overview.png` — Traffic overview tab (metrics + charts)
- `cp6_dashboard_alerts.png` — Alerts tab, filtered to Critical
- `cp6_dashboard_drilldown.png` — Drill-down of the SYN Flood or ARP alert
- `cp6_dashboard_upload.png` — after uploading `telnet-raw.pcap`

After saving them run `python reports\build_report.py` to embed them in the Word report.

**Viva**
1. *Why Streamlit?* Python-only web UI; fast to build; reuses the same `analyze()` function as the CLI.
2. *Why `@st.cache_data`?* Streamlit reruns the script on every click; caching by file content avoids re-parsing.
3. *How do you avoid leaking passwords in the UI?* Payloads are dropped (only length shown) and alerts mask passwords.

---

## Checkpoint 7 — Testing & evaluation ✅

```powershell
python src\evaluate.py
```

**Results:** 32/33 detected (97.0 %), 32 alerts all true (100 % precision), 0 alerts on 4 attack-free captures; ~3,200 packets/s, 91 % of time is parsing.

**Files:** `reports/evaluation/*.csv`; figures `detection_per_attack.png`, `alerts_by_severity.png`, `traffic_timeline_mixed.png`, `slow_scan_window_sensitivity.png`, `processing_time.png`.

**Screenshots:** `cp7_evaluate_console.png`

**Viva**
1. *Define detection rate and precision.* Detection rate = detected attacks / all attacks (recall). Precision = true alerts / all alerts.
2. *Why did the slow scan evade you, and how would you fix it?* 1 port/15 s never reaches 20 ports in 10 s. Fix: longer/cumulative counters or sequential hypothesis testing (TRW).
3. *Tell us about a false positive you found.* YouTube CDN name with entropy 3.53 → fixed by counting unique names (tunnels never repeat).

---

## Checkpoint 8 — Report & demo ✅ (draft)

- `reports/report.md` → `reports/report.docx` (`python reports\build_report.py`)
- `reports/demo_script.md` — timed 10-minute script with backup plan

**Done when**
- [ ] Names/USNs/guide filled in on the title page
- [ ] CO statements C403.1–C403.5 replaced with official wording (Section 12)
- [ ] Dashboard + Wireshark screenshots taken, report rebuilt
- [ ] Demo rehearsed once with a timer

**Viva**
1. *What is the single most effective countermeasure you recommend?* Encrypt everything (SSH/SFTP/HTTPS) — it neutralises credential sniffing and makes ARP-spoofing MITM far less useful.
2. *Map your project to a course outcome.* E.g. C403.4 — analysis of TCP handshake abuse and secure protocol replacements.
3. *What would you add with more time?* Adaptive thresholds, TRW scan detection, TLS fingerprinting (JA3), hybrid rules + ML.
