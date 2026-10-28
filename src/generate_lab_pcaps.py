"""
Checkpoint 2 - build a labelled test dataset of attack PCAPs.

Every packet is CRAFTED IN MEMORY with Scapy and written straight to a .pcap
file. Nothing is ever sent on any network, so this is 100% safe and needs no
lab VMs. The traffic models a VirtualBox host-only lab (192.168.56.0/24):

    192.168.56.1    gateway / DNS        192.168.56.20  web server
    192.168.56.10   alice (client)       192.168.56.21  FTP + SSH server
    192.168.56.11   bob   (client)       192.168.56.22  mail + Telnet server
    192.168.56.12   carol (client)       192.168.56.101 attacker (Kali)

Because we generate the attacks ourselves, we know exactly where they are:
labels.csv is the ground truth used by evaluate.py and ml_compare.py.

Usage:
    python src/generate_lab_pcaps.py                       -> data/lab/ (seed 1)
    python src/generate_lab_pcaps.py --seed 2 --out data/lab_test
"""
import argparse
import base64
import random
import sys
from pathlib import Path

import pandas as pd
from scapy.all import ARP, DNS, DNSQR, DNSRR, ICMP, IP, TCP, UDP, Ether, wrpcap

GW, ALICE, BOB, CAROL = "192.168.56.1", "192.168.56.10", "192.168.56.11", "192.168.56.12"
WEB, FILESRV, MAILSRV, ATTACKER = "192.168.56.20", "192.168.56.21", "192.168.56.22", "192.168.56.101"
MACS = {
    GW: "08:00:27:00:00:01", ALICE: "08:00:27:10:10:10", BOB: "08:00:27:11:11:11",
    CAROL: "08:00:27:12:12:12", WEB: "08:00:27:20:20:20", FILESRV: "08:00:27:21:21:21",
    MAILSRV: "08:00:27:22:22:22", ATTACKER: "08:00:27:66:66:66",
}
CLIENTS = [ALICE, BOB, CAROL]
INTERNET = ["93.184.216.34", "142.250.183.110", "151.101.1.69", "104.16.132.229", "13.107.42.14"]
NORMAL_NAMES = ["www.google.com", "fonts.gstatic.com", "www.wikipedia.org", "github.com",
                "api.github.com", "cdn.jsdelivr.net", "outlook.office365.com", "www.youtube.com",
                "r3---sn-ci5gup-qxas.googlevideo.com", "stackoverflow.com", "jssateb.ac.in"]
T0 = 1792490400.0          # 2026-10-20 10:00:00 UTC - start of every capture


def mac(ip):
    """Local hosts have their own MAC; anything outside the lab is behind the gateway."""
    return MACS.get(ip, MACS[GW])


class Trace:
    """A list of packets with timestamps (seconds from T0)."""

    def __init__(self, rng):
        self.rng, self.pkts = rng, []

    def add(self, pkt, t):
        pkt.time = T0 + t
        self.pkts.append(pkt)

    def ip(self, src, dst):
        return Ether(src=mac(src), dst=mac(dst)) / IP(src=src, dst=dst)

    def save(self, path):
        self.pkts.sort(key=lambda p: p.time)
        wrpcap(str(path), self.pkts)
        return len(self.pkts)

    # ---- building blocks ------------------------------------------------

    def tcp_session(self, c, s, sport, t, exchanges=(), rtt=0.004, close=True, cport=None):
        """Full TCP connection: handshake, data (list of ('c'|'s', bytes)), FIN close."""
        cport = cport or self.rng.randint(40000, 60999)
        cs, ss = self.rng.randint(1, 2**31), self.rng.randint(1, 2**31)
        self.add(self.ip(c, s) / TCP(sport=cport, dport=sport, flags="S", seq=cs), t)
        self.add(self.ip(s, c) / TCP(sport=sport, dport=cport, flags="SA", seq=ss, ack=cs + 1), t + rtt)
        t += 2 * rtt
        cs, ss = cs + 1, ss + 1
        self.add(self.ip(c, s) / TCP(sport=cport, dport=sport, flags="A", seq=cs, ack=ss), t)
        for who, data in exchanges:
            t += rtt + self.rng.uniform(0, 0.01)
            if who == "c":
                self.add(self.ip(c, s) / TCP(sport=cport, dport=sport, flags="PA", seq=cs, ack=ss) / data, t)
                cs += len(data)
                self.add(self.ip(s, c) / TCP(sport=sport, dport=cport, flags="A", seq=ss, ack=cs), t + rtt)
            else:
                self.add(self.ip(s, c) / TCP(sport=sport, dport=cport, flags="PA", seq=ss, ack=cs) / data, t)
                ss += len(data)
                self.add(self.ip(c, s) / TCP(sport=cport, dport=sport, flags="A", seq=cs, ack=ss), t + rtt)
            t += rtt
        if close:
            t += rtt
            self.add(self.ip(c, s) / TCP(sport=cport, dport=sport, flags="FA", seq=cs, ack=ss), t)
            self.add(self.ip(s, c) / TCP(sport=sport, dport=cport, flags="FA", seq=ss, ack=cs + 1), t + rtt)
            self.add(self.ip(c, s) / TCP(sport=cport, dport=sport, flags="A", seq=cs + 1, ack=ss + 1), t + 2 * rtt)
            t += 2 * rtt
        return t

    def dns_lookup(self, client, name, t, answer="93.184.216.34"):
        qid = self.rng.randint(1, 65535)
        sport = self.rng.randint(49152, 65535)
        self.add(self.ip(client, GW) / UDP(sport=sport, dport=53) /
                 DNS(id=qid, rd=1, qd=DNSQR(qname=name)), t)
        self.add(self.ip(GW, client) / UDP(sport=53, dport=sport) /
                 DNS(id=qid, qr=1, ra=1, qd=DNSQR(qname=name),
                     an=DNSRR(rrname=name, ttl=300, rdata=answer)), t + 0.012)

    def arp_exchange(self, asker, target, t):
        self.add(Ether(src=mac(asker), dst="ff:ff:ff:ff:ff:ff") /
                 ARP(op=1, hwsrc=mac(asker), psrc=asker, pdst=target), t)
        self.add(Ether(src=mac(target), dst=mac(asker)) /
                 ARP(op=2, hwsrc=mac(target), psrc=target, hwdst=mac(asker), pdst=asker), t + 0.001)


def tls_blob(rng, n):
    """Random bytes that look like an encrypted TLS record."""
    return b"\x17\x03\x03" + n.to_bytes(2, "big") + rng.randbytes(n)


# ---------------------------------------------------------------- normal traffic


def normal_background(tr, start, duration):
    """Ordinary office traffic: DNS, HTTPS browsing, intranet HTTP, one SSH session, pings, ARP."""
    rng = tr.rng
    for host in CLIENTS + [WEB, FILESRV, MAILSRV]:
        tr.arp_exchange(host, GW, start + rng.uniform(0, 2))
    t = start
    while t < start + duration:
        client = rng.choice(CLIENTS)
        kind = rng.random()
        if kind < 0.45:
            # Browse an HTTPS site: DNS lookup, then 2-6 parallel connections to port 443
            name, server = rng.choice(NORMAL_NAMES), rng.choice(INTERNET)
            tr.dns_lookup(client, name, t, server)
            for _ in range(rng.randint(2, 6)):
                ex = [("c", tls_blob(rng, rng.randint(200, 600)))] + \
                     [("s", tls_blob(rng, rng.randint(400, 1400))) for _ in range(rng.randint(2, 6))]
                tr.tcp_session(client, server, 443, t + rng.uniform(0.02, 0.3), ex, rtt=0.02)
        elif kind < 0.70:
            # Intranet page on the lab web server (plain HTTP, no login)
            page = rng.choice(["/", "/index.html", "/news.html", "/timetable.html", "/style.css"])
            req = f"GET {page} HTTP/1.1\r\nHost: intranet.lab\r\nUser-Agent: Mozilla/5.0\r\n\r\n".encode()
            body = b"<html><body>" + b"x" * rng.randint(200, 1200) + b"</body></html>"
            resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n" + body
            tr.tcp_session(client, WEB, 80, t, [("c", req), ("s", resp)])
        elif kind < 0.80:
            tr.dns_lookup(client, rng.choice(NORMAL_NAMES), t, rng.choice(INTERNET))
        elif kind < 0.87:
            for i in range(4):   # normal ping: 4 echo requests, 1 per second
                tr.add(tr.ip(client, GW) / ICMP(type=8, id=1, seq=i) / (b"a" * 32), t + i)
                tr.add(tr.ip(GW, client) / ICMP(type=0, id=1, seq=i) / (b"a" * 32), t + i + 0.001)
        elif kind < 0.92:
            # One legitimate SSH session (encrypted, so contents are random bytes)
            ex = [("s", b"SSH-2.0-OpenSSH_8.9p1\r\n"), ("c", b"SSH-2.0-OpenSSH_9.6\r\n")] + \
                 [(rng.choice("cs"), rng.randbytes(rng.randint(40, 300))) for _ in range(12)]
            tr.tcp_session(client, FILESRV, 22, t, ex)
        elif kind < 0.95:
            # Hard negative: a user mistypes an intranet password once (single 401)
            req = b"GET /staff/ HTTP/1.1\r\nHost: intranet.lab\r\n\r\n"
            tr.tcp_session(client, WEB, 80, t, [("c", req), ("s", b"HTTP/1.1 401 Unauthorized\r\n\r\n")])
        else:
            tr.add(tr.ip(client, "162.159.200.1") / UDP(sport=123, dport=123) / rng.randbytes(48), t)
            tr.add(tr.ip("162.159.200.1", client) / UDP(sport=123, dport=123) / rng.randbytes(48), t + 0.03)
        t += rng.expovariate(1 / 0.8)     # about one user action every 0.8 s


# ---------------------------------------------------------------- attacks
# Each function adds packets and returns ground-truth label dicts.


def port_scan(tr, start, target=WEB, n_ports=1000, rate=400, open_ports=(22, 80)):
    """nmap -sS style: SYN to many ports, RST/ACK for closed, SYN/ACK for open (attacker RSTs)."""
    rng = tr.rng
    ports = rng.sample(range(1, 1025), min(n_ports, 1024))
    sport = rng.randint(40000, 60000)
    t = start
    for p in ports:
        tr.add(tr.ip(ATTACKER, target) / TCP(sport=sport, dport=p, flags="S", seq=rng.randint(1, 2**31)), t)
        if p in open_ports:
            tr.add(tr.ip(target, ATTACKER) / TCP(sport=p, dport=sport, flags="SA"), t + 0.001)
            tr.add(tr.ip(ATTACKER, target) / TCP(sport=sport, dport=p, flags="R"), t + 0.002)
        else:
            tr.add(tr.ip(target, ATTACKER) / TCP(sport=p, dport=sport, flags="RA"), t + 0.001)
        t += 1 / rate
    return [dict(attack_type="Port Scan", src=ATTACKER, dst=target, start=start, end=t)]


def slow_scan(tr, start, target=FILESRV, n_ports=40, gap=15.0):
    """Stealthy scan: one port every 15 s. Designed to EVADE window-based rules (limitation)."""
    t = start
    for p in tr.rng.sample(range(1, 1025), n_ports):
        tr.add(tr.ip(ATTACKER, target) / TCP(sport=tr.rng.randint(40000, 60000), dport=p, flags="S"), t)
        tr.add(tr.ip(target, ATTACKER) / TCP(sport=p, dport=40000, flags="RA"), t + 0.001)
        t += gap
    return [dict(attack_type="Port Scan", src=ATTACKER, dst=target, start=start, end=t)]


def syn_flood(tr, start, target=WEB, port=80, rate=800, seconds=6):
    """hping3 --flood --rand-source style: spoofed SYNs, server SYN/ACKs go unanswered."""
    rng = tr.rng
    n = rate * seconds
    for i in range(n):
        t = start + i / rate
        spoof = f"{rng.randint(11, 223)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
        sp = rng.randint(1024, 65535)
        tr.add(tr.ip(spoof, target) / TCP(sport=sp, dport=port, flags="S", seq=rng.randint(1, 2**31)), t)
        if i % 3 == 0:     # server backlog fills up; it answers only some of them
            tr.add(tr.ip(target, spoof) / TCP(sport=port, dport=sp, flags="SA"), t + 0.0005)
    return [dict(attack_type="SYN Flood", src="*", dst=target, start=start, end=start + seconds)]


def arp_spoof(tr, start, seconds=60, victims=(ALICE, BOB)):
    """arpspoof style: attacker repeatedly tells victims 'the gateway is at MY MAC'."""
    t = start
    tr.arp_exchange(ATTACKER, GW, start - 1)          # attacker's own, honest ARP first
    while t < start + seconds:
        for v in victims:
            tr.add(Ether(src=MACS[ATTACKER], dst=mac(v)) /
                   ARP(op=2, hwsrc=MACS[ATTACKER], psrc=GW, hwdst=mac(v), pdst=v), t)
        t += 2
    return [dict(attack_type="ARP Spoofing", src=MACS[ATTACKER], dst=GW, start=start, end=t)]


def ssh_brute_force(tr, start, attempts=40, seconds=60):
    """hydra -t 1 ssh:// style: many short SSH connections, each closed after a failed password."""
    rng = tr.rng
    for i in range(attempts):
        t = start + i * seconds / attempts
        ex = [("s", b"SSH-2.0-OpenSSH_8.9p1\r\n"), ("c", b"SSH-2.0-libssh_0.10\r\n")] + \
             [(rng.choice("cs"), rng.randbytes(rng.randint(40, 200))) for _ in range(6)]
        tr.tcp_session(ATTACKER, FILESRV, 22, t, ex)
    return [dict(attack_type="Brute Force", src=ATTACKER, dst=FILESRV, start=start, end=start + seconds)]


def ftp_brute_force(tr, start, attempts=25, seconds=50, succeed=True):
    """Password guessing against FTP. Last guess succeeds (230) - worst case."""
    guesses = ["123456", "password", "admin", "letmein", "qwerty", "welcome", "monkey", "dragon",
               "football", "abc123", "111111", "iloveyou", "master", "sunshine", "ashley", "bailey",
               "passw0rd", "shadow", "123123", "654321", "superman", "qazwsx", "michael", "Football1",
               "Admin@123"]
    for i in range(attempts):
        t = start + i * seconds / attempts
        ok = succeed and i == attempts - 1
        ex = [("s", b"220 (vsFTPd 3.0.5)\r\n"), ("c", b"USER admin\r\n"),
              ("s", b"331 Please specify the password.\r\n"), ("c", f"PASS {guesses[i % 25]}\r\n".encode()),
              ("s", b"230 Login successful.\r\n" if ok else b"530 Login incorrect.\r\n")]
        tr.tcp_session(ATTACKER, FILESRV, 21, t, ex)
    return [dict(attack_type="Brute Force", src=ATTACKER, dst=FILESRV, start=start, end=start + seconds),
            dict(attack_type="Plaintext Credentials", src=ATTACKER, dst=FILESRV, start=start,
                 end=start + seconds)]


def http_brute_force(tr, start, attempts=15, seconds=30):
    """Repeated wrong passwords on an HTTP Basic-auth admin page -> many 401 replies."""
    for i in range(attempts):
        t = start + i * seconds / attempts
        cred = base64.b64encode(f"admin:guess{i}".encode()).decode()
        req = f"GET /admin/ HTTP/1.1\r\nHost: intranet.lab\r\nAuthorization: Basic {cred}\r\n\r\n".encode()
        tr.tcp_session(ATTACKER, WEB, 80, t, [("c", req), ("s", b"HTTP/1.1 401 Unauthorized\r\n\r\n")])
    return [dict(attack_type="Brute Force", src=ATTACKER, dst=WEB, start=start, end=start + seconds),
            dict(attack_type="Plaintext Credentials", src=ATTACKER, dst=WEB, start=start,
                 end=start + seconds)]


def plaintext_logins(tr, start):
    """Legitimate users logging in over protocols that do NOT encrypt passwords."""
    labels = []
    t = start
    # FTP
    tr.tcp_session(ALICE, FILESRV, 21, t, [
        ("s", b"220 (vsFTPd 3.0.5)\r\n"), ("c", b"USER alice\r\n"),
        ("s", b"331 Please specify the password.\r\n"), ("c", b"PASS Summer2026!\r\n"),
        ("s", b"230 Login successful.\r\n"), ("c", b"RETR marks.xlsx\r\n")])
    labels.append(dict(attack_type="Plaintext Credentials", src=ALICE, dst=FILESRV, start=t, end=t + 1))
    # HTTP login form
    t += 8
    body = "username=bob&password=Qwerty%40123"
    req = (f"POST /login.php HTTP/1.1\r\nHost: intranet.lab\r\n"
           f"Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {len(body)}\r\n\r\n{body}")
    tr.tcp_session(BOB, WEB, 80, t, [("c", req.encode()), ("s", b"HTTP/1.1 302 Found\r\nLocation: /home\r\n\r\n")])
    labels.append(dict(attack_type="Plaintext Credentials", src=BOB, dst=WEB, start=t, end=t + 1))
    # HTTP Basic authentication
    t += 8
    cred = base64.b64encode(b"carol:Library#42").decode()
    req = f"GET /reports/ HTTP/1.1\r\nHost: intranet.lab\r\nAuthorization: Basic {cred}\r\n\r\n".encode()
    tr.tcp_session(CAROL, WEB, 80, t, [("c", req), ("s", b"HTTP/1.1 200 OK\r\n\r\n<html>ok</html>")])
    labels.append(dict(attack_type="Plaintext Credentials", src=CAROL, dst=WEB, start=t, end=t + 1))
    # Telnet: the client sends ONE CHARACTER PER PACKET, the server echoes the username
    t += 8
    ex = [("s", b"\xff\xfd\x18\xff\xfd\x20\xff\xfd\x23"), ("c", b"\xff\xfb\x18\xff\xfb\x20"),
          ("s", b"Ubuntu 22.04 LTS\r\nmailsrv login: ")]
    for ch in "carol":
        ex += [("c", ch.encode()), ("s", ch.encode())]
    ex += [("c", b"\r\n"), ("s", b"\r\nPassword: ")]
    ex += [("c", ch.encode()) for ch in "tel!net9"]
    ex += [("c", b"\r\n"), ("s", b"\r\nWelcome to Ubuntu 22.04 LTS\r\ncarol@mailsrv:~$ ")]
    tr.tcp_session(CAROL, MAILSRV, 23, t, ex)
    labels.append(dict(attack_type="Plaintext Credentials", src=CAROL, dst=MAILSRV, start=t, end=t + 2))
    # POP3 mail
    t += 8
    tr.tcp_session(BOB, MAILSRV, 110, t, [
        ("s", b"+OK Dovecot ready.\r\n"), ("c", b"USER bob\r\n"), ("s", b"+OK\r\n"),
        ("c", b"PASS mailpass1\r\n"), ("s", b"+OK Logged in.\r\n")])
    labels.append(dict(attack_type="Plaintext Credentials", src=BOB, dst=MAILSRV, start=t, end=t + 1))
    return labels


def dns_tunnel(tr, start, queries=80, seconds=40, client=CAROL, domain="tunnel-c2.net"):
    """iodine/dnscat style: data hidden in long base32 subdomains of an attacker domain."""
    rng = tr.rng
    alphabet = "abcdefghijklmnopqrstuvwxyz234567"
    for i in range(queries):
        chunk = "".join(rng.choice(alphabet) for _ in range(rng.randint(40, 60)))
        name = f"{chunk[:30]}.{chunk[30:]}.{i:04x}.{domain}"
        tr.dns_lookup(client, name, start + i * seconds / queries, "10.10.10.10")
    return [dict(attack_type="DNS Tunneling", src=client, dst=domain, start=start, end=start + seconds)]


def icmp_flood(tr, start, target=WEB, rate=500, seconds=5):
    """hping3 --icmp --flood style ping flood."""
    for i in range(rate * seconds):
        tr.add(tr.ip(ATTACKER, target) / ICMP(type=8, id=99, seq=i % 65536) / (b"X" * 1000), start + i / rate)
    return [dict(attack_type="ICMP Flood", src=ATTACKER, dst=target, start=start, end=start + seconds)]


def backdoor_port(tr, start, victim=CAROL, c2="203.0.113.66", port=4444):
    """Infected host opens a reverse shell to an attacker server on port 4444 (Metasploit default)."""
    ex = [("s", b"Microsoft Windows [Version 10.0.19045]\r\nC:\\Users\\carol> "), ("c", b"whoami\r\n"),
          ("s", b"lab\\carol\r\n"), ("c", b"ipconfig\r\n"), ("s", b"IPv4 Address. . : 192.168.56.12\r\n")]
    end = tr.tcp_session(victim, c2, port, start, ex, rtt=0.05)
    return [dict(attack_type="Suspicious Port", src=victim, dst=c2, start=start, end=end)]


# ---------------------------------------------------------------- dataset

SCENARIOS = {
    # name: (background seconds, [(attack function, start time, kwargs)])
    "normal_traffic": (300, []),
    "port_scan": (120, [(port_scan, 40, {})]),
    "slow_port_scan": (660, [(slow_scan, 20, {})]),
    "syn_flood": (120, [(syn_flood, 50, {})]),
    "arp_spoof": (120, [(arp_spoof, 30, {})]),
    "brute_force": (180, [(ssh_brute_force, 20, {}), (ftp_brute_force, 100, {}),
                          (http_brute_force, 140, {})]),
    "plaintext_credentials": (120, [(plaintext_logins, 30, {})]),
    "dns_tunnel": (120, [(dns_tunnel, 40, {})]),
    "icmp_flood": (120, [(icmp_flood, 60, {})]),
    "backdoor_port": (120, [(backdoor_port, 50, {})]),
    "mixed_attacks": (600, [(port_scan, 30, {}), (arp_spoof, 90, {"seconds": 40}),
                            (ssh_brute_force, 160, {}), (ftp_brute_force, 240, {}),
                            (plaintext_logins, 300, {}), (syn_flood, 360, {}),
                            (dns_tunnel, 420, {}), (icmp_flood, 480, {}), (backdoor_port, 530, {})]),
}


def build(name, seed, out_dir):
    background, attacks = SCENARIOS[name]
    rng = random.Random(f"{seed}-{name}")
    tr = Trace(rng)
    normal_background(tr, 0, background)
    labels = []
    for func, start, kwargs in attacks:
        labels += func(tr, start, **kwargs)
    n = tr.save(out_dir / f"{name}.pcap")
    for lab in labels:
        lab.update(pcap=f"{name}.pcap", start=T0 + lab["start"], end=T0 + lab["end"])
    return n, labels


def main():
    ap = argparse.ArgumentParser(description="Generate labelled attack PCAPs offline (no packets sent)")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--out", default="data/lab")
    ap.add_argument("--only", nargs="*", help="build only these scenarios")
    args = ap.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    print("[i] Building PCAPs offline - no traffic is sent on any network.")
    all_labels = []
    for name in args.only or SCENARIOS:
        n, labels = build(name, args.seed, out)
        all_labels += labels
        print(f"  {name + '.pcap':<28} {n:>6} packets, {len(labels)} labelled attack(s)")
    cols = ["pcap", "attack_type", "src", "dst", "start", "end"]
    pd.DataFrame(all_labels, columns=cols).to_csv(out / "labels.csv", index=False)
    print(f"[OK] Ground truth -> {out / 'labels.csv'}")


if __name__ == "__main__":
    sys.exit(main())
