"""
Checkpoint 3 - feature extraction.

Turns the per-packet table from parser.py into per-source, per-time-window
statistics. The detectors and the ML comparison both use these helpers.

Usage:
    python src/features.py data/http.cap                  -> prints top sources
    python src/features.py data/http.cap --csv feats.csv  -> also saves the table
"""
import argparse
import math
import re
import sys
from collections import Counter
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
import config  # noqa: E402
from parser import parse_pcap  # noqa: E402

# ---------- TCP flag helpers (flags are strings such as "S", "SA", "PA", "R") ----------


def is_syn(flags):
    """Connection request: SYN set, ACK not set."""
    return flags.str.contains("S") & ~flags.str.contains("A")


def is_synack(flags):
    return flags.str.contains("S") & flags.str.contains("A")


def is_pure_ack(flags):
    """ACK with nothing else - the third step of a completed handshake."""
    return flags == "A"


def is_rst(flags):
    return flags.str.contains("R")


def is_fin(flags):
    return flags.str.contains("F")


# ---------- payload helpers ----------

FAILED_LOGIN_RE = re.compile(r"^(530[ -]|HTTP/1\.[01] 401)", re.IGNORECASE)


def is_failed_login_reply(payload):
    """FTP '530 Login incorrect' or HTTP '401 Unauthorized' sent by a server."""
    return payload.str.match(FAILED_LOGIN_RE)


def shannon_entropy(text):
    """Bits of information per character; random strings score high (~4-5)."""
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


# ---------- windowing ----------


def add_window(df, seconds=config.WINDOW_SECONDS):
    """Add a 'window' column: which fixed-length time bucket each packet falls in."""
    df = df.copy()
    t0 = df["time"].min() if not df.empty else 0.0
    df["window"] = ((df["time"] - t0) // seconds).astype(int)
    df["window_start"] = t0 + df["window"] * seconds
    return df


def peak_rate(times):
    """Highest number of events in any single second."""
    if len(times) == 0:
        return 0
    return int(times.astype(int).value_counts().max())


def source_window_stats(df, seconds=config.WINDOW_SECONDS):
    """Per (source IP, window) statistics - this is features.csv."""
    ip = df[df["src_ip"].notna()].copy()
    if ip.empty:
        return pd.DataFrame()
    ip = add_window(ip, seconds)
    flags = ip["tcp_flags"]
    ip["syn"] = is_syn(flags)
    ip["synack"] = is_synack(flags)
    ip["ack"] = is_pure_ack(flags)
    ip["rst"] = is_rst(flags)
    ip["fin"] = is_fin(flags)
    ip["icmp_echo"] = ip["icmp_type"].fillna(-1) == 8
    ip["dns_query"] = (ip["protocol"] == "DNS") & (ip["dns_qr"].fillna(-1) == 0)
    ip["failed_login_reply"] = is_failed_login_reply(ip["payload"])

    g = ip.groupby(["src_ip", "window"])
    stats = g.agg(
        window_start=("window_start", "first"),
        packets=("length", "size"),
        bytes=("length", "sum"),
        unique_dst_ips=("dst_ip", "nunique"),
        unique_dst_ports=("dport", "nunique"),
        syn=("syn", "sum"),
        synack=("synack", "sum"),
        ack=("ack", "sum"),
        rst=("rst", "sum"),
        fin=("fin", "sum"),
        icmp_echo=("icmp_echo", "sum"),
        dns_queries=("dns_query", "sum"),
    ).reset_index()
    stats["pkt_rate"] = stats["packets"] / seconds
    stats["syn_ack_ratio"] = (stats["ack"] / stats["syn"].where(stats["syn"] > 0)).round(3)

    # A failed-login reply is sent BY the server TO the client, so credit it to dst_ip
    fails = (ip[ip["failed_login_reply"]].groupby(["dst_ip", "window"]).size()
             .rename("failed_logins").reset_index().rename(columns={"dst_ip": "src_ip"}))
    stats = stats.merge(fails, on=["src_ip", "window"], how="left")
    stats["failed_logins"] = stats["failed_logins"].fillna(0).astype(int)
    return stats.sort_values(["window", "packets"], ascending=[True, False]).reset_index(drop=True)


def main():
    ap = argparse.ArgumentParser(description="Compute per-source window statistics")
    ap.add_argument("pcap")
    ap.add_argument("--csv", help="where to save the features CSV")
    args = ap.parse_args()
    df = parse_pcap(args.pcap)
    stats = source_window_stats(df)
    print(f"{len(df)} packets -> {len(stats)} (source, {config.WINDOW_SECONDS}s window) rows\n")
    cols = ["src_ip", "window", "packets", "unique_dst_ports", "syn", "ack",
            "syn_ack_ratio", "rst", "icmp_echo", "dns_queries", "failed_logins"]
    print("Top 10 busiest source windows:")
    print(stats.sort_values("packets", ascending=False)[cols].head(10).to_string(index=False))
    if args.csv:
        Path(args.csv).parent.mkdir(parents=True, exist_ok=True)
        stats.to_csv(args.csv, index=False)
        print(f"\n[OK] Saved {args.csv}")


if __name__ == "__main__":
    main()
