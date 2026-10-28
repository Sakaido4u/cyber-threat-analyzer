"""
Checkpoint 3 - PCAP parser.

Reads a PCAP with Scapy (streaming, so large files don't fill memory) and turns
every packet into one row of a pandas DataFrame.

Usage:
    python src/parser.py data/http.cap                 -> prints a summary
    python src/parser.py data/http.cap --csv out.csv   -> also saves the table
"""
import argparse
import sys
from pathlib import Path

import pandas as pd
from scapy.all import ARP, DNS, ICMP, IP, TCP, UDP, Ether, IPv6, PcapReader, Raw

COLUMNS = [
    "time", "src_mac", "dst_mac", "src_ip", "dst_ip", "protocol", "sport", "dport",
    "tcp_flags", "length", "arp_op", "arp_psrc", "arp_hwsrc", "arp_pdst",
    "icmp_type", "dns_qname", "dns_qr", "payload",
]

# Only the start of each payload is kept - enough for login commands and HTTP headers
MAX_PAYLOAD = 1000


def _dns_qname(dns):
    """Return the first query name of a DNS packet as text (Scapy versions differ)."""
    qd = dns.qd
    if not qd:
        return None
    try:
        name = qd[0].qname          # Scapy 2.6+: qd is a list of questions
    except (TypeError, IndexError, AttributeError):
        name = getattr(qd, "qname", None)
    if name is None:
        return None
    if isinstance(name, bytes):
        name = name.decode("latin-1", errors="replace")
    return name.rstrip(".")


def packet_to_row(pkt):
    """Extract the fields we need from one Scapy packet into a dict."""
    row = dict.fromkeys(COLUMNS)
    row["time"] = float(pkt.time)
    row["length"] = len(pkt)
    row["protocol"] = "OTHER"

    if pkt.haslayer(Ether):
        row["src_mac"] = pkt[Ether].src
        row["dst_mac"] = pkt[Ether].dst

    if pkt.haslayer(ARP):
        arp = pkt[ARP]
        row.update(protocol="ARP", arp_op=int(arp.op), arp_psrc=arp.psrc,
                   arp_hwsrc=arp.hwsrc, arp_pdst=arp.pdst)
        return row

    if pkt.haslayer(IP):
        row["src_ip"], row["dst_ip"] = pkt[IP].src, pkt[IP].dst
        row["protocol"] = "IP"
    elif pkt.haslayer(IPv6):
        row["src_ip"], row["dst_ip"] = pkt[IPv6].src, pkt[IPv6].dst
        row["protocol"] = "IPv6"

    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        row.update(protocol="TCP", sport=int(tcp.sport), dport=int(tcp.dport),
                   tcp_flags=str(tcp.flags))
    elif pkt.haslayer(UDP):
        udp = pkt[UDP]
        row.update(protocol="UDP", sport=int(udp.sport), dport=int(udp.dport))
    elif pkt.haslayer(ICMP):
        row.update(protocol="ICMP", icmp_type=int(pkt[ICMP].type))

    if pkt.haslayer(DNS):
        row["protocol"] = "DNS"
        row["dns_qr"] = int(pkt[DNS].qr)
        row["dns_qname"] = _dns_qname(pkt[DNS])

    if pkt.haslayer(Raw) and (pkt.haslayer(TCP) or pkt.haslayer(UDP)):
        # latin-1 maps every byte to one character, so nothing is lost
        row["payload"] = bytes(pkt[Raw].load[:MAX_PAYLOAD]).decode("latin-1")
    return row


def parse_pcap(path, limit=None):
    """Read a PCAP/PCAPNG file and return a DataFrame with one row per packet."""
    rows = []
    with PcapReader(str(path)) as reader:
        for i, pkt in enumerate(reader):
            if limit is not None and i >= limit:
                break
            rows.append(packet_to_row(pkt))
    df = pd.DataFrame(rows, columns=COLUMNS)
    for col in ["sport", "dport", "arp_op", "icmp_type", "dns_qr"]:
        df[col] = df[col].astype("Int64")       # integer column that allows blanks
    df["payload"] = df["payload"].fillna("")
    df["tcp_flags"] = df["tcp_flags"].fillna("")
    df = df.sort_values("time", kind="stable").reset_index(drop=True)
    return df


def summarize(df):
    """Short text summary used by the CLI and the report."""
    if df.empty:
        return "0 packets"
    duration = df["time"].max() - df["time"].min()
    lines = [
        f"Packets      : {len(df)}",
        f"Duration     : {duration:.2f} s",
        f"Total bytes  : {int(df['length'].sum())}",
        f"Unique src IP: {df['src_ip'].nunique()}",
        "Protocols    : " + ", ".join(f"{k}={v}" for k, v in df["protocol"].value_counts().items()),
    ]
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description="Parse a PCAP into a per-packet table")
    ap.add_argument("pcap")
    ap.add_argument("--csv", help="where to save the per-packet CSV")
    args = ap.parse_args()
    if not Path(args.pcap).exists():
        sys.exit(f"[!] File not found: {args.pcap}")
    df = parse_pcap(args.pcap)
    print(summarize(df))
    print("\nFirst 5 rows:")
    print(df.drop(columns=["payload"]).head().to_string())
    if args.csv:
        Path(args.csv).parent.mkdir(parents=True, exist_ok=True)
        df.to_csv(args.csv, index=False)
        print(f"\n[OK] Saved {args.csv}")


if __name__ == "__main__":
    main()
