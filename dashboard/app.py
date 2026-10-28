"""
Checkpoint 6 - Streamlit dashboard.

Run from the project folder:
    streamlit run dashboard/app.py

Upload a PCAP (or pick a sample), then explore the traffic overview, the
alerts table, and the evidence behind each alert.
"""
import hashlib
import re
import sys
import tempfile
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

PROJECT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT / "src"))
import config  # noqa: E402
from main import analyze  # noqa: E402
from plot_style import INK_2, MUTED, SERIES, SEVERITY_COLORS  # noqa: E402

st.set_page_config(page_title="Cyber Threat Analyzer", page_icon="🛡️", layout="wide")

SAMPLE_DIRS = [PROJECT / "data" / "lab", PROJECT / "data" / "public", PROJECT / "data"]
SEVERITY_ORDER = list(reversed(config.SEVERITY_LEVELS))     # Critical first


@st.cache_data(show_spinner=False)
def run_analysis(data: bytes, name: str):
    """Analyze PCAP bytes. Cached by content, so re-filtering the page is instant."""
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / name
        path.write_bytes(data)
        packets, features, alerts, timings = analyze(path)
    packets = packets.assign(payload_len=packets["payload"].str.len()).drop(columns=["payload"])
    return packets, features, alerts, timings


def style_fig(fig, height=320):
    fig.update_layout(height=height, margin=dict(l=10, r=10, t=40, b=10), template="plotly_white",
                      font=dict(color=INK_2), legend_title_text="", colorway=SERIES)
    fig.update_xaxes(showgrid=False, linecolor=MUTED)
    return fig


# ---------------------------------------------------------------- sidebar: choose input

st.sidebar.title("🛡️ Cyber Threat Analyzer")
st.sidebar.caption("Analysis of Cyber Threats and Attacks in Data Traffic — BCS703 mini project")
# Optional link straight to a sample, e.g. http://localhost:8501/?sample=lab/mixed_attacks.pcap
wanted = st.query_params.get("sample")
source = st.sidebar.radio("Input", ["Upload a PCAP", "Use a sample PCAP"], index=1 if wanted else 0)
data, name = None, None
if source == "Upload a PCAP":
    up = st.sidebar.file_uploader("PCAP / PCAPNG file", type=["pcap", "pcapng", "cap"])
    if up is not None:
        data, name = up.getvalue(), up.name
else:
    samples = sorted({p for d in SAMPLE_DIRS if d.exists() for p in d.iterdir()
                      if p.suffix in {".pcap", ".pcapng", ".cap"}}, key=lambda p: (p.parent.name, p.name))
    labels = [f"{p.parent.name}/{p.name}" for p in samples]
    first = wanted if wanted in labels else "lab/mixed_attacks.pcap"
    default = labels.index(first) if first in labels else 0
    choice = st.sidebar.selectbox("Sample", labels, index=default)
    chosen = samples[labels.index(choice)]
    data, name = chosen.read_bytes(), chosen.name

st.sidebar.divider()
st.sidebar.info("**Ethics:** analyse only public datasets or traffic from your own isolated lab. "
                "Never capture networks you do not own. Passwords in alerts are masked.")

if data is None:
    st.title("Cyber Threat Analyzer")
    st.write("Upload a PCAP in the sidebar to begin, or switch to **Use a sample PCAP**.")
    st.stop()

with st.spinner(f"Parsing and analysing {name} ..."):
    packets, features, alerts, timings = run_analysis(data, name)

# ---------------------------------------------------------------- header metrics

st.title(f"Analysis: {name}")
st.caption(f"SHA-256 {hashlib.sha256(data).hexdigest()[:16]}…  ·  processed in {timings['total_s']:.2f} s "
           f"(parse {timings['parse_s']:.2f} s, detection {timings['detect_s']:.2f} s)")
duration = packets["time"].max() - packets["time"].min() if len(packets) else 0
c = st.columns(5)
c[0].metric("Packets", f"{len(packets):,}")
c[1].metric("Duration", f"{duration:,.0f} s")
c[2].metric("Hosts (src IPs)", packets["src_ip"].nunique())
c[3].metric("Alerts", len(alerts))
c[4].metric("Critical / High", int(alerts["severity"].isin(["Critical", "High"]).sum()))

tab_overview, tab_alerts, tab_drill, tab_packets = st.tabs(
    ["📊 Traffic overview", "🚨 Alerts", "🔍 Alert drill-down", "📦 Packets"])

# ---------------------------------------------------------------- overview

with tab_overview:
    left, right = st.columns(2)
    proto = packets["protocol"].value_counts().rename_axis("protocol").reset_index(name="packets")
    fig = px.bar(proto.sort_values("packets"), x="packets", y="protocol", orientation="h",
                 title="Protocol distribution", text="packets", color_discrete_sequence=[SERIES[0]])
    left.plotly_chart(style_fig(fig), width="stretch")

    talkers = (packets[packets["src_ip"].notna()].groupby("src_ip")
               .agg(packets=("length", "size"), bytes=("length", "sum")).nlargest(10, "packets").reset_index())
    fig = px.bar(talkers.sort_values("packets"), x="packets", y="src_ip", orientation="h",
                 title="Top 10 talkers (by packets sent)", hover_data=["bytes"],
                 color_discrete_sequence=[SERIES[0]])
    right.plotly_chart(style_fig(fig), width="stretch")

    t0 = packets["time"].min()
    span = max(duration, 1)
    bucket = 1 if span <= 900 else max(1, int(span // 600))
    pps = (((packets["time"] - t0) // bucket) * bucket).value_counts().sort_index()
    timeline = pd.DataFrame({"seconds": pps.index, "packets": pps.values / bucket})
    fig = px.line(timeline, x="seconds", y="packets", title=f"Packets per second (bucket = {bucket} s)",
                  color_discrete_sequence=[SERIES[0]], log_y=st.checkbox("Log scale", value=True))
    fig.update_traces(hovertemplate="t=%{x}s<br>%{y:.0f} pkt/s")
    st.plotly_chart(style_fig(fig, 300), width="stretch")

    if not alerts.empty:
        al = alerts.assign(seconds=alerts["time"] - t0)
        fig = px.scatter(al, x="seconds", y="attack_type", color="severity", symbol="severity",
                         color_discrete_map=SEVERITY_COLORS, category_orders={"severity": SEVERITY_ORDER},
                         hover_data={"src": True, "dst": True, "evidence": True, "seconds": ":.1f"},
                         title="When did each alert happen?")
        fig.update_traces(marker=dict(size=13, line=dict(width=2, color="white")))
        st.plotly_chart(style_fig(fig, 300), width="stretch")

# ---------------------------------------------------------------- alerts table

with tab_alerts:
    if alerts.empty:
        st.success("No threats detected in this capture.")
    else:
        f1, f2, f3 = st.columns([2, 2, 1.5])
        types = f1.multiselect("Attack type", sorted(alerts["attack_type"].unique()),
                               default=sorted(alerts["attack_type"].unique()))
        sevs = f2.multiselect("Severity", [s for s in SEVERITY_ORDER if s in set(alerts["severity"])],
                              default=[s for s in SEVERITY_ORDER if s in set(alerts["severity"])])
        ip_q = f3.text_input("Search IP / MAC")
        view = alerts[alerts["attack_type"].isin(types) & alerts["severity"].isin(sevs)]
        if ip_q:
            view = view[view["src"].str.contains(ip_q, regex=False) | view["dst"].str.contains(ip_q, regex=False)]
        st.caption(f"{len(view)} of {len(alerts)} alerts")

        def colour(sev):
            return f"background-color: {SEVERITY_COLORS.get(sev, '#fff')}33; font-weight: 600"

        cols = ["time_utc", "severity", "attack_type", "src", "dst", "evidence"]
        st.dataframe(view[cols].style.map(colour, subset=["severity"]), width="stretch",
                     hide_index=True, height=min(600, 38 + 35 * len(view)))
        counts = view.groupby(["attack_type", "severity"]).size().reset_index(name="alerts")
        fig = px.bar(counts, x="alerts", y="attack_type", color="severity", orientation="h",
                     color_discrete_map=SEVERITY_COLORS, category_orders={"severity": SEVERITY_ORDER},
                     title="Alerts by type and severity")
        st.plotly_chart(style_fig(fig, 280), width="stretch")
        st.download_button("⬇️ Download alerts (CSV)", view.to_csv(index=False), f"{Path(name).stem}_alerts.csv",
                           "text/csv")

# ---------------------------------------------------------------- drill-down

with tab_drill:
    if alerts.empty:
        st.info("No alerts to drill into.")
    else:
        options = [f"#{i}  {r.severity:<8} {r.attack_type} — {r.src} → {r.dst}" for i, r in alerts.iterrows()]
        pick = st.selectbox("Choose an alert", range(len(options)), format_func=lambda i: options[i])
        a = alerts.iloc[pick]
        st.subheader(f"{a['attack_type']}  ·  {a['severity']}")
        d1, d2, d3 = st.columns(3)
        d1.markdown(f"**Source**  \n`{a['src']}`")
        d2.markdown(f"**Target**  \n`{a['dst']}`")
        d3.markdown(f"**Time (UTC)**  \n{a['time_utc']}  (lasted {a['end_time'] - a['time']:.1f} s)")
        st.markdown("**Evidence**")
        st.info(a["evidence"])
        st.markdown("**Verify in Wireshark** — paste this display filter:")
        st.code(a["wireshark_filter"], language="text")

        # Packets that belong to this alert: same hosts, same time span
        src_ip = str(a["src"]).split(" ")[0]
        dst_ip = str(a["dst"]).split(":")[0]
        src_is_ip = bool(re.fullmatch(r"\d+\.\d+\.\d+\.\d+", src_ip))   # "4801 sources" is not an IP
        span = packets["time"].between(a["time"] - 1, a["end_time"] + 1)
        if a["attack_type"] == "ARP Spoofing":
            rel = packets[span & (packets["protocol"] == "ARP") & (packets["arp_psrc"] == a["dst"])]
        elif a["attack_type"] == "DNS Tunneling":      # target is a domain name, not an IP
            rel = packets[span & (packets["src_ip"] == src_ip)
                          & packets["dns_qname"].fillna("").str.endswith(a["dst"])]
        elif not src_is_ip:                            # spoofed flood: everything sent to the target
            rel = packets[span & (packets["dst_ip"] == dst_ip)]
        else:
            ips = [src_ip, dst_ip]
            rel = packets[span & packets["src_ip"].isin(ips) & packets["dst_ip"].isin(ips)]
        st.markdown(f"**Related packets:** {len(rel):,}")
        if len(rel):
            rt = rel.assign(seconds=(rel["time"] - rel["time"].min()).round(0))
            per_s = rt.groupby(["seconds", "protocol"]).size().reset_index(name="packets")
            fig = px.bar(per_s, x="seconds", y="packets", color="protocol", title="Related packets per second",
                         color_discrete_sequence=SERIES)
            st.plotly_chart(style_fig(fig, 260), width="stretch")
            show = ["time", "src_mac", "src_ip", "dst_ip", "protocol", "sport", "dport", "tcp_flags",
                    "length", "arp_op", "arp_psrc", "arp_hwsrc", "icmp_type", "dns_qname", "payload_len"]
            st.dataframe(rel[show].head(500), width="stretch", hide_index=True)

# ---------------------------------------------------------------- packets

with tab_packets:
    st.caption("Payload contents are hidden (only their length is shown) so credentials are never displayed.")
    st.dataframe(packets.head(5000), width="stretch", hide_index=True)
    if len(packets) > 5000:
        st.caption(f"Showing the first 5,000 of {len(packets):,} packets.")
    st.download_button("⬇️ Download features (CSV)", features.to_csv(index=False),
                       f"{Path(name).stem}_features.csv", "text/csv")
