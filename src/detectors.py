"""
Checkpoint 4 - rule-based detectors.

One function per attack. Every function takes the per-packet DataFrame from
parser.py and returns a list of alert dicts with the same keys:

    time, end_time, attack_type, severity, src, dst, evidence, wireshark_filter

Thresholds come from config.py (the Checkpoint 1 rule table).
"""
import base64
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import unquote_plus

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
import config  # noqa: E402
from features import (add_window, is_failed_login_reply, is_pure_ack, is_rst,  # noqa: E402
                      is_syn, is_synack, peak_rate, shannon_entropy)

ALERT_COLUMNS = ["time", "time_utc", "end_time", "attack_type", "severity", "src", "dst",
                 "evidence", "wireshark_filter"]


# ---------------------------------------------------------------- helpers


def _alert(start, end, attack_type, severity, src, dst, evidence, wfilter):
    return {"time": float(start), "end_time": float(end), "attack_type": attack_type,
            "severity": severity, "src": str(src), "dst": str(dst),
            "evidence": evidence, "wireshark_filter": wfilter}


def _runs(windows):
    """Group sorted window numbers into runs of consecutive windows: [1,2,3,7] -> [[1,2,3],[7]]."""
    runs = []
    for w in sorted(windows):
        if runs and w - runs[-1][-1] <= 1:
            runs[-1].append(w)
        else:
            runs.append([w])
    return runs


def mask_secret(secret):
    """Show only the first character so the report never leaks a real password."""
    if not secret:
        return ""
    return secret[0] + "*" * (len(secret) - 1)


def _tcp(df):
    return df[(df["protocol"] == "TCP") & df["dport"].notna()]


# ---------------------------------------------------------------- 1. port scan


def detect_port_scan(df):
    """One source sends SYNs to many different ports of one target in a short window."""
    tcp = _tcp(df)
    syns = tcp[is_syn(tcp["tcp_flags"])]
    if syns.empty:
        return []
    syns = add_window(syns, config.WINDOW_SECONDS)
    per_win = syns.groupby(["src_ip", "dst_ip", "window"])["dport"].nunique()
    hot = per_win[per_win >= config.PORTSCAN_MIN_UNIQUE_PORTS].reset_index()

    alerts = []
    for (src, dst), grp in hot.groupby(["src_ip", "dst_ip"]):
        for run in _runs(grp["window"]):
            # Include the neighbouring windows: a scan rarely starts exactly on a window boundary
            span = range(run[0] - 1, run[-1] + 2)
            part = syns[(syns["src_ip"] == src) & (syns["dst_ip"] == dst) & syns["window"].isin(span)]
            t0, t1 = part["time"].min(), part["time"].max()
            ports = part["dport"].nunique()
            # How did the target answer during the scan?
            replies = tcp[(tcp["src_ip"] == dst) & (tcp["dst_ip"] == src)
                          & tcp["time"].between(t0, t1 + 2)]
            rst = int(is_rst(replies["tcp_flags"]).sum())
            open_ports = sorted(replies.loc[is_synack(replies["tcp_flags"]), "sport"].dropna()
                                .astype(int).unique().tolist())
            sev = "High" if ports >= config.PORTSCAN_HIGH_UNIQUE_PORTS else "Medium"
            ev = (f"{ports} distinct ports probed in {t1 - t0:.1f} s with {len(part)} SYN-only packets; "
                  f"target replied RST {rst} times; open ports seen: {open_ports[:10] or 'none'}")
            alerts.append(_alert(t0, t1, "Port Scan", sev, src, dst, ev,
                                 f"ip.src=={src} && ip.dst=={dst} && tcp.flags.syn==1 && tcp.flags.ack==0"))
    return alerts


# ---------------------------------------------------------------- 2. SYN flood


def detect_syn_flood(df):
    """Very high SYN rate to one target, and almost none of the handshakes complete."""
    tcp = _tcp(df)
    if tcp.empty:
        return []
    tcp = add_window(tcp, config.WINDOW_SECONDS)
    syn_mask = is_syn(tcp["tcp_flags"])
    syns, acks = tcp[syn_mask], tcp[is_pure_ack(tcp["tcp_flags"])]

    flagged = {}
    for (dst, win), part in syns.groupby(["dst_ip", "window"]):
        rate = peak_rate(part["time"])
        if rate < config.SYNFLOOD_MIN_SYN_RATE:
            continue
        # Many ports = a scan, not a flood (the port-scan detector handles that)
        if part["dport"].nunique() > config.SYNFLOOD_MAX_TARGET_PORTS:
            continue
        completed = len(acks[(acks["dst_ip"] == dst) & (acks["window"] == win)])
        ratio = completed / len(part)
        if ratio < config.SYNFLOOD_MAX_ACK_RATIO:
            flagged.setdefault(dst, []).append((win, rate, ratio))

    alerts = []
    for dst, rows in flagged.items():
        info = {w: (r, q) for w, r, q in rows}
        for run in _runs(info):
            part = syns[(syns["dst_ip"] == dst) & syns["window"].isin(run)]
            peak = max(info[w][0] for w in run)
            ratio = min(info[w][1] for w in run)
            n_src = part["src_ip"].nunique()
            src = part["src_ip"].iloc[0] if n_src == 1 else f"{n_src} sources (likely spoofed)"
            ports = sorted(part["dport"].astype(int).unique().tolist())
            sev = "Critical" if peak >= config.SYNFLOOD_CRITICAL_RATE else "High"
            ev = (f"peak {peak} SYN/s to port(s) {ports}; {len(part)} SYNs in "
                  f"{part['time'].max() - part['time'].min():.1f} s; completed-handshake ratio {ratio:.2f} "
                  f"(threshold < {config.SYNFLOOD_MAX_ACK_RATIO}); {n_src} distinct source IPs")
            alerts.append(_alert(part["time"].min(), part["time"].max(), "SYN Flood", sev, src, dst, ev,
                                 f"ip.dst=={dst} && tcp.flags.syn==1 && tcp.flags.ack==0"))
    return alerts


# ---------------------------------------------------------------- 3. ARP spoofing


def detect_arp_spoof(df):
    """The same IP address is claimed by more than one MAC address."""
    arp = df[(df["protocol"] == "ARP") & df["arp_psrc"].notna()]
    arp = arp[arp["arp_psrc"] != "0.0.0.0"]          # ARP probes carry no real claim
    alerts = []
    for ip, part in arp.groupby("arp_psrc"):
        macs = part.groupby("arp_hwsrc")["time"].agg(["min", "count"]).sort_values("min")
        if len(macs) <= config.ARP_MAX_MACS_PER_IP:
            continue
        original, newcomers = macs.index[0], macs.index[1:]
        for mac in newcomers:
            claims = part[part["arp_hwsrc"] == mac]
            # The attacker's MAC usually also announces its own, real IP
            other_ips = sorted(set(arp.loc[arp["arp_hwsrc"] == mac, "arp_psrc"]) - {ip})
            sev = "Critical" if ip in config.GATEWAY_IPS else "High"
            ev = (f"IP {ip} first seen at MAC {original} ({int(macs.loc[original, 'count'])} pkts), "
                  f"then claimed by {mac} in {len(claims)} ARP packets "
                  f"({int((claims['arp_op'] == 2).sum())} unsolicited/replies)")
            if other_ips:
                ev += f"; {mac} also claims {', '.join(other_ips[:3])} (attacker's own IP?)"
            if ip in config.GATEWAY_IPS:
                ev += "; target is the GATEWAY -> man-in-the-middle of all traffic"
            alerts.append(_alert(claims["time"].min(), claims["time"].max(), "ARP Spoofing", sev,
                                 f"{mac}" + (f" ({other_ips[0]})" if other_ips else ""), ip, ev,
                                 f"arp.src.proto_ipv4=={ip}"))
    return alerts


# ---------------------------------------------------------------- 4. brute force


def detect_brute_force(df):
    """Many login attempts to SSH/FTP/Telnet/RDP, or many 'login failed' replies (FTP/HTTP)."""
    tcp = _tcp(df)
    if tcp.empty:
        return []
    tcp = add_window(tcp, config.BRUTEFORCE_WINDOW_SECONDS)
    found = {}   # (src, dst, service) -> details

    # a) many new connections to a login port
    syns = tcp[is_syn(tcp["tcp_flags"]) & tcp["dport"].isin(list(config.BRUTEFORCE_PORTS))]
    counts = syns.groupby(["src_ip", "dst_ip", "dport", "window"]).size()
    for (src, dst, port, _win), n in counts[counts >= config.BRUTEFORCE_MIN_ATTEMPTS].items():
        part = syns[(syns["src_ip"] == src) & (syns["dst_ip"] == dst) & (syns["dport"] == port)]
        key = (src, dst, config.BRUTEFORCE_PORTS[int(port)])
        d = found.setdefault(key, {"t0": part["time"].min(), "t1": part["time"].max(),
                                   "attempts": len(part), "fails": 0, "port": int(port)})
        d["attempts"] = len(part)

    # b) many failed-login replies (server -> client)
    fails = tcp[is_failed_login_reply(tcp["payload"])]
    fcounts = fails.groupby(["dst_ip", "src_ip", "sport", "window"]).size()
    for (client, server, port, _win), n in fcounts[fcounts >= config.BRUTEFORCE_MIN_FAILED_LOGINS].items():
        part = fails[(fails["dst_ip"] == client) & (fails["src_ip"] == server) & (fails["sport"] == port)]
        service = {21: "FTP", 80: "HTTP"}.get(int(port), f"port {int(port)}")
        d = found.setdefault((client, server, service), {"t0": part["time"].min(), "t1": part["time"].max(),
                                                         "attempts": 0, "fails": 0, "port": int(port)})
        d["fails"] = len(part)
        d["t0"], d["t1"] = min(d["t0"], part["time"].min()), max(d["t1"], part["time"].max())

    alerts = []
    for (src, dst, service), d in found.items():
        dur = max(d["t1"] - d["t0"], 0.001)
        bits = []
        if d["attempts"]:
            bits.append(f"{d['attempts']} connection attempts to {service} (port {d['port']}) "
                        f"in {dur:.1f} s ({d['attempts'] / dur * 60:.0f}/min)")
        if d["fails"]:
            bits.append(f"{d['fails']} failed-login replies from server")
        # Did one attempt succeed? (FTP 230 = login successful, on the same service only)
        ok = tcp[(tcp["src_ip"] == dst) & (tcp["dst_ip"] == src) & (tcp["sport"] == 21)
                 & (d["port"] == 21) & tcp["payload"].str.startswith("230")]
        sev = "High"
        if not ok.empty:
            sev = "Critical"
            bits.append("a later reply shows LOGIN SUCCESSFUL - account may be compromised")
        alerts.append(_alert(d["t0"], d["t1"], "Brute Force", sev, src, dst, "; ".join(bits),
                             f"ip.src=={src} && ip.dst=={dst} && tcp.port=={d['port']}"))
    return alerts


# ---------------------------------------------------------------- 5. plaintext credentials

TELNET_IAC_RE = re.compile(r"\xff\xfa.*?\xff\xf0|\xff[\xfb-\xfe].|\xff[\xf0-\xfa]", re.DOTALL)
HTTP_BASIC_RE = re.compile(r"Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)", re.IGNORECASE)
FORM_USER_RE = re.compile(r"(?:^|[&?\s])(?:user(?:name)?|login|email|uname)=([^&\s]*)", re.IGNORECASE)
FORM_PASS_RE = re.compile(r"(?:^|[&?\s])(?:pass(?:word)?|pwd|passwd)=([^&\s]*)", re.IGNORECASE)


def _telnet_credentials(packets, client, server):
    """Replay a Telnet session: after the server prints 'login:' / 'Password:',
    collect the characters the client types until Enter."""
    user, password, mode, buf = None, None, None, ""
    for _, p in packets.iterrows():
        text = TELNET_IAC_RE.sub("", p["payload"])
        if not text:
            continue
        if p["src_ip"] == server:
            low = text.lower()
            if "password:" in low:
                mode, buf = "pass", ""
            elif "login:" in low or "username:" in low:
                mode, buf = "user", ""
        elif mode:
            for ch in text:
                if ch in "\r\n\x00":
                    if buf:
                        if mode == "user":
                            user = buf
                        else:
                            password = buf
                    mode, buf = None, ""
                    break
                if ch in "\x08\x7f":
                    buf = buf[:-1]
                elif ch.isprintable():
                    buf += ch
        if user and password:
            break
    return user, password


def detect_plaintext_credentials(df):
    """Usernames/passwords visible in unencrypted FTP, Telnet, HTTP, POP3 or IMAP traffic."""
    tcp = _tcp(df)
    ports = list(config.CREDENTIAL_PORTS)
    data = tcp[(tcp["payload"] != "") & (tcp["dport"].isin(ports) | tcp["sport"].isin(ports))]
    alerts, found = [], {}
    # Group packets into connections: (client ip, client port, server ip, server port)
    is_c2s = data["dport"].isin(ports)
    data = data.assign(
        client=data["src_ip"].where(is_c2s, data["dst_ip"]),
        cport=data["sport"].where(is_c2s, data["dport"]),
        server=data["dst_ip"].where(is_c2s, data["src_ip"]),
        sport_=data["dport"].where(is_c2s, data["sport"]),
    )
    for (client, cport, server, port), conn in data.groupby(["client", "cport", "server", "sport_"]):
        port = int(port)
        proto = config.CREDENTIAL_PORTS[port]
        to_server = conn[conn["src_ip"] == client]
        text = "".join(to_server["payload"])
        user = password = None
        method = ""
        if proto in ("FTP", "POP3"):
            u = re.search(r"^USER\s+(\S+)", text, re.MULTILINE | re.IGNORECASE)
            p = re.search(r"^PASS\s+(\S+)", text, re.MULTILINE | re.IGNORECASE)
            user, password = (u.group(1) if u else None), (p.group(1) if p else None)
            method = "USER/PASS commands"
        elif proto == "IMAP":
            m = re.search(r"^\S+\s+LOGIN\s+(\S+)\s+(\S+)", text, re.MULTILINE | re.IGNORECASE)
            if m:
                user, password = m.group(1).strip('"'), m.group(2).strip('"')
            method = "LOGIN command"
        elif proto == "Telnet":
            user, password = _telnet_credentials(conn, client, server)
            method = "typed at login prompt"
        elif proto == "HTTP":
            b = HTTP_BASIC_RE.search(text)
            if b:
                try:
                    decoded = base64.b64decode(b.group(1)).decode("latin-1")
                    user, _, password = decoded.partition(":")
                    method = "Authorization: Basic header (base64 is NOT encryption)"
                except (ValueError, UnicodeDecodeError):
                    pass
            if not password:
                fp = FORM_PASS_RE.search(text)
                if fp:
                    fu = FORM_USER_RE.search(text)
                    user = unquote_plus(fu.group(1)) if fu else None
                    password = unquote_plus(fp.group(1))
                    method = "login form field (POST/GET)"
        if not (user or password):
            continue
        found.setdefault((client, server, port), []).append(
            (to_server["time"].min(), to_server["time"].max(), user, password, method))

    # One alert per client -> server service, however many logins it contains
    for (client, server, port), logins in found.items():
        proto = config.CREDENTIAL_PORTS[port]
        users = sorted({u for _, _, u, _, _ in logins if u})
        _, _, user, password, method = logins[0]
        ev = (f"{proto} {method}: username='{user or '?'}', password='{mask_secret(password) or '?'}' "
              f"sent in clear text from {client} to {server}:{port}")
        if len(logins) > 1:
            ev += f"; {len(logins)} credential sets exposed in total (users: {', '.join(users[:5])})"
        alerts.append(_alert(min(l[0] for l in logins), max(l[1] for l in logins),
                             "Plaintext Credentials", "High", client, f"{server}:{port}", ev,
                             f"ip.addr=={client} && ip.addr=={server} && tcp.port=={port}"))
    return alerts


# ---------------------------------------------------------------- extras


def detect_dns_tunneling(df):
    """Many long or random-looking DNS names from one host to one domain."""
    dns = df[(df["protocol"] == "DNS") & (df["dns_qr"] == 0) & df["dns_qname"].notna()].copy()
    if dns.empty:
        return []
    labels = dns["dns_qname"].str.split(".")
    dns["base"] = labels.str[-2:].str.join(".")
    dns["sub"] = labels.str[:-2].str.join("")
    dns["entropy"] = dns["sub"].map(shannon_entropy)
    long_name = dns["dns_qname"].str.len() > config.DNS_MAX_QNAME_LENGTH
    random_name = (dns["sub"].str.len() >= config.DNS_MIN_ENTROPY_LENGTH) & \
                  (dns["entropy"] > config.DNS_MAX_LABEL_ENTROPY)
    sus = dns[long_name | random_name]
    alerts = []
    for (src, base), part in sus.groupby(["src_ip", "base"]):
        # Tunnels carry new data in every query, so the names are all different.
        # A browser re-querying the same CDN name is NOT a tunnel.
        unique_names = part["dns_qname"].nunique()
        if unique_names < config.DNS_MIN_SUSPICIOUS_QUERIES:
            continue
        example = part["dns_qname"].iloc[0]
        ev = (f"{unique_names} unique suspicious names ({len(part)} queries) for *.{base}; avg name length "
              f"{part['dns_qname'].str.len().mean():.0f} chars, max subdomain entropy "
              f"{part['entropy'].max():.2f} bits/char; e.g. {example[:70]}")
        sev = "High" if len(part) >= 50 else "Medium"
        alerts.append(_alert(part["time"].min(), part["time"].max(), "DNS Tunneling", sev, src, base, ev,
                             f'ip.src=={src} && dns.qry.name contains "{base}"'))
    return alerts


def detect_icmp_flood(df):
    """Very high rate of ping (echo request) packets to one target."""
    icmp = df[(df["protocol"] == "ICMP") & (df["icmp_type"] == 8)]
    alerts = []
    for dst, part in icmp.groupby("dst_ip"):
        peak = peak_rate(part["time"])
        if peak < config.ICMP_FLOOD_MIN_RATE:
            continue
        n_src = part["src_ip"].nunique()
        src = part["src_ip"].iloc[0] if n_src == 1 else f"{n_src} sources"
        ev = (f"peak {peak} echo requests/s (threshold {config.ICMP_FLOOD_MIN_RATE}); "
              f"{len(part)} requests in {part['time'].max() - part['time'].min():.1f} s; "
              f"avg size {part['length'].mean():.0f} bytes")
        alerts.append(_alert(part["time"].min(), part["time"].max(), "ICMP Flood", "High", src, dst, ev,
                             f"ip.dst=={dst} && icmp.type==8"))
    return alerts


def detect_suspicious_ports(df):
    """Connections to ports commonly used by backdoors, reverse shells and IRC botnets."""
    tcp_open = (df["protocol"] == "TCP") & is_syn(df["tcp_flags"])
    udp = df["protocol"] == "UDP"
    hits = df[(tcp_open | udp) & df["dport"].isin(list(config.SUSPICIOUS_PORTS))]
    alerts = []
    for (src, dst, port), part in hits.groupby(["src_ip", "dst_ip", "dport"]):
        port = int(port)
        conv = df[((df["src_ip"] == src) & (df["dst_ip"] == dst) & (df["dport"] == port))
                  | ((df["src_ip"] == dst) & (df["dst_ip"] == src) & (df["sport"] == port))]
        ev = (f"connection to well-known backdoor/C2 port {port}; {len(conv)} packets, "
              f"{int(conv['length'].sum())} bytes exchanged over "
              f"{conv['time'].max() - conv['time'].min():.1f} s")
        alerts.append(_alert(part["time"].min(), conv["time"].max(), "Suspicious Port", "Medium",
                             src, f"{dst}:{port}", ev, f"ip.addr=={src} && tcp.port=={port}"))
    return alerts


# ---------------------------------------------------------------- run everything

DETECTORS = [
    detect_port_scan,
    detect_syn_flood,
    detect_arp_spoof,
    detect_brute_force,
    detect_plaintext_credentials,
    detect_dns_tunneling,
    detect_icmp_flood,
    detect_suspicious_ports,
]


def run_all(df):
    """Run every detector and return one DataFrame of alerts, oldest first."""
    alerts = []
    if not df.empty:
        for detector in DETECTORS:
            alerts.extend(detector(df))
    out = pd.DataFrame(alerts, columns=[c for c in ALERT_COLUMNS if c != "time_utc"])
    out.insert(1, "time_utc", out["time"].map(
        lambda t: datetime.fromtimestamp(t, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")))
    rank = {s: i for i, s in enumerate(config.SEVERITY_LEVELS)}
    out = out.sort_values(["time", "severity"], key=lambda c: c.map(rank) if c.name == "severity" else c)
    return out.reset_index(drop=True)
