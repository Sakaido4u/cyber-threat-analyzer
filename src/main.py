"""
Checkpoint 4 - command-line analyzer.

Usage:
    python src/main.py --pcap data/lab/mixed_attacks.pcap
    python src/main.py --pcap data/public/telnet-raw.pcap --out reports/output/telnet
    python src/main.py --live "VirtualBox Host-Only Ethernet Adapter" --duration 60

Outputs (in --out, default reports/output/<pcap name>/):
    packets.csv   one row per packet          (parser.py)
    features.csv  per-source window stats     (features.py)
    alerts.csv    detected threats            (detectors.py)
    alerts.json   same alerts, JSON format

SAFETY: --live captures real traffic. Only use it on your own isolated lab
network (VirtualBox host-only adapter). Never on college Wi-Fi or any network
you do not own.
"""
import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from detectors import run_all  # noqa: E402
from features import source_window_stats  # noqa: E402
from parser import parse_pcap, summarize  # noqa: E402

PROJECT = Path(__file__).resolve().parent.parent


def analyze(pcap_path):
    """Full pipeline: PCAP -> packets -> features -> alerts. Returns everything + timings."""
    timings = {}
    t = time.perf_counter()
    packets = parse_pcap(pcap_path)
    timings["parse_s"] = time.perf_counter() - t

    t = time.perf_counter()
    features = source_window_stats(packets)
    timings["features_s"] = time.perf_counter() - t

    t = time.perf_counter()
    alerts = run_all(packets)
    timings["detect_s"] = time.perf_counter() - t
    timings["total_s"] = sum(timings.values())
    return packets, features, alerts, timings


def live_capture(iface, duration, out_file):
    """Capture from a local interface with Scapy/Npcap and save to a PCAP."""
    from scapy.all import sniff, wrpcap
    print("=" * 70)
    print("SAFETY: capture ONLY on your own isolated lab network (host-only adapter).")
    print("        Never capture college Wi-Fi or networks you do not own.")
    print("=" * 70)
    answer = input(f"Capture on '{iface}' for {duration}s - is this YOUR isolated lab network? (yes/no): ")
    if answer.strip().lower() != "yes":
        sys.exit("[!] Capture cancelled.")
    pkts = sniff(iface=iface, timeout=duration)
    out_file.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(out_file), pkts)
    print(f"[i] Captured {len(pkts)} packets -> {out_file}")
    return out_file


def print_alerts(alerts):
    if alerts.empty:
        print("\nNo threats detected.")
        return
    print(f"\n{len(alerts)} ALERT(S):")
    print("-" * 100)
    for _, a in alerts.iterrows():
        print(f"[{a['severity'].upper():8}] {a['time_utc']}  {a['attack_type']:<22} "
              f"{a['src']} -> {a['dst']}")
        print(f"           evidence : {a['evidence']}")
        print(f"           wireshark: {a['wireshark_filter']}")
    print("-" * 100)
    print("By type    : " + ", ".join(f"{k}={v}" for k, v in alerts["attack_type"].value_counts().items()))
    print("By severity: " + ", ".join(f"{k}={v}" for k, v in alerts["severity"].value_counts().items()))


def main():
    ap = argparse.ArgumentParser(description="Detect cyber attacks in network traffic (PCAP)")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--pcap", help="PCAP/PCAPNG file to analyze")
    src.add_argument("--live", metavar="IFACE", help="capture live from this interface (own lab only!)")
    ap.add_argument("--duration", type=int, default=60, help="live capture length in seconds")
    ap.add_argument("--out", help="output folder (default reports/output/<pcap name>)")
    args = ap.parse_args()

    if args.live:
        pcap = live_capture(args.live, args.duration, PROJECT / "data" / "lab" / "live_capture.pcap")
    else:
        pcap = Path(args.pcap)
        if not pcap.exists():
            sys.exit(f"[!] File not found: {pcap}")

    out = Path(args.out) if args.out else PROJECT / "reports" / "output" / pcap.stem
    print(f"[i] Analyzing {pcap} ...")
    packets, features, alerts, timings = analyze(pcap)
    print(summarize(packets))
    print(f"Processing   : {timings['total_s']:.2f} s "
          f"(parse {timings['parse_s']:.2f}, features {timings['features_s']:.2f}, "
          f"detect {timings['detect_s']:.2f})")
    print_alerts(alerts)

    out.mkdir(parents=True, exist_ok=True)
    packets.to_csv(out / "packets.csv", index=False)
    features.to_csv(out / "features.csv", index=False)
    alerts.to_csv(out / "alerts.csv", index=False)
    alerts.to_json(out / "alerts.json", orient="records", indent=2)
    print(f"\n[OK] Saved packets.csv, features.csv, alerts.csv, alerts.json -> {out}")


if __name__ == "__main__":
    main()
