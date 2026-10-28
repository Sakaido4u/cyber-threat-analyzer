# Cyber Threat Analyzer

**Analysis of Cyber Threats and Attacks in Data Traffic** — BCS703 mini project, Dept. of CSE, JSSATE Bengaluru.

Reads a PCAP, detects 8 attack types with explainable rules, and reports each finding with time, source,
target, severity, evidence and a Wireshark filter — on the command line and in a Streamlit dashboard.

| Detects | Layer |
|---|---|
| Port scan, SYN flood, brute-force login, backdoor ports | L4 |
| ARP spoofing | L2 |
| Plaintext credentials (FTP, Telnet, HTTP, POP3, IMAP), DNS tunnelling | L7 |
| ICMP flood | L3 |

**Results:** 32/33 labelled attacks detected (97 %), 0 false positives, ~3,200 packets/s.

## Quick start (Windows PowerShell)

```powershell
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt                          # first time only
python src\generate_lab_pcaps.py                         # labelled test captures (built offline)
python src\main.py --pcap data\lab\mixed_attacks.pcap    # analyse a capture
streamlit run dashboard\app.py                           # dashboard -> http://localhost:8501
python src\evaluate.py                                   # detection rate, FP, timing, charts
python src\ml_compare.py                                 # Random Forest vs rules
python reports\build_report.py                           # report.md -> report.docx
```

## Layout

```
data/         public/ (Wireshark samples), lab/ + lab_test/ (generated, labelled), scale/ (speed test)
src/          config, parser, features, detectors, main, generate_lab_pcaps, evaluate, ml_compare
dashboard/    app.py (Streamlit)
reports/      report.md/.docx, demo_script.md, checkpoint_guide.md, design_summary.md,
              figures/, evaluation/, output/
screenshots/  images for the report and demo backup
```

## Safety and ethics

Only public datasets or traffic generated for / captured inside your **own isolated lab**
(VirtualBox host-only network). Never capture or attack networks you do not own, including college Wi-Fi.
`generate_lab_pcaps.py` writes packets straight to files — it never transmits anything.
Passwords are masked in all alerts and payloads are hidden in the dashboard.
