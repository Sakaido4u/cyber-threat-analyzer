"""
Checkpoint 0 - environment test.

Usage:
    python src/test_setup.py                    # uses data/sample.pcap (creates a synthetic one if missing)
    python src/test_setup.py data/http.cap      # any PCAP you downloaded

The synthetic PCAP is built offline with Scapy and written straight to a file.
No packets are sent on any network.
"""
import sys
from pathlib import Path

from scapy.all import ARP, DNS, DNSQR, Ether, IP, TCP, UDP, rdpcap, wrpcap

DEFAULT_PCAP = Path("data") / "sample.pcap"


def make_synthetic_pcap(path: Path) -> None:
    """Write a small PCAP containing a handshake, a DNS query and an ARP reply."""
    client, server = "192.168.56.10", "192.168.56.20"
    # Explicit MAC addresses stop Scapy from trying to look them up (avoids warnings)
    c_mac, s_mac = "08:00:27:11:22:33", "08:00:27:aa:bb:cc"
    to_server = Ether(src=c_mac, dst=s_mac)
    to_client = Ether(src=s_mac, dst=c_mac)
    packets = [
        to_client / ARP(op=2, psrc=server, hwsrc=s_mac, pdst=client, hwdst=c_mac),
        to_server / IP(src=client, dst="8.8.8.8") / UDP(sport=53000, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="example.com")),
        to_server / IP(src=client, dst=server) / TCP(sport=40000, dport=80, flags="S", seq=100),
        to_client / IP(src=server, dst=client) / TCP(sport=80, dport=40000, flags="SA", seq=500, ack=101),
        to_server / IP(src=client, dst=server) / TCP(sport=40000, dport=80, flags="A", seq=101, ack=501),
        to_server / IP(src=client, dst=server) / TCP(sport=40000, dport=80, flags="PA", seq=101, ack=501)
        / b"GET / HTTP/1.1\r\nHost: lab.local\r\n\r\n",
    ]
    # Give packets increasing timestamps so the capture looks realistic
    for i, pkt in enumerate(packets):
        pkt.time = 1_700_000_000 + i * 0.1
    path.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(path), packets)
    print(f"[i] Created synthetic test capture: {path}")


def main() -> None:
    pcap = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_PCAP
    if not pcap.exists():
        if len(sys.argv) > 1:
            sys.exit(f"[!] File not found: {pcap}")
        make_synthetic_pcap(pcap)

    packets = rdpcap(str(pcap))
    print(f"[i] Loaded {len(packets)} packets from {pcap}\n")
    print("First 10 packets:")
    for i, pkt in enumerate(packets[:10], start=1):
        print(f"{i:>2}. {pkt.summary()}")
    print("\n[OK] Scapy can read PCAP files - Checkpoint 0 test passed.")


if __name__ == "__main__":
    main()
