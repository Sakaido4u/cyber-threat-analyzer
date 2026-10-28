"""
Checkpoint 7 - testing and evaluation.

Runs the analyzer on every PCAP, compares the alerts with the ground truth
(data/lab/labels.csv and data/public_labels.csv), measures processing time,
and draws the charts for the report.

Usage:
    python src/evaluate.py              -> full evaluation (includes a speed test)
    python src/evaluate.py --no-scale   -> skip the speed test (faster)

Outputs:
    reports/evaluation/results_per_pcap.csv
    reports/evaluation/results_per_attack.csv
    reports/evaluation/all_alerts.csv
    reports/evaluation/processing_time.csv
    reports/figures/*.png
"""
import argparse
import random
import sys
import time
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
import config  # noqa: E402
import generate_lab_pcaps as gen  # noqa: E402
import plot_style  # noqa: E402
from features import is_syn  # noqa: E402
from main import analyze  # noqa: E402
from parser import parse_pcap  # noqa: E402

PROJECT = Path(__file__).resolve().parent.parent
EVAL_DIR = PROJECT / "reports" / "evaluation"
FIG_DIR = PROJECT / "reports" / "figures"
TIME_TOLERANCE = 5.0     # seconds of slack when matching alert times to label times

plt = plot_style.plt


def collect_pcaps():
    """(path, labels DataFrame) for every PCAP we have ground truth for."""
    lab = pd.read_csv(PROJECT / "data" / "lab" / "labels.csv")
    pub = pd.read_csv(PROJECT / "data" / "public_labels.csv")
    items = [(p, lab) for p in sorted((PROJECT / "data" / "lab").glob("*.pcap"))]
    items += [(p, pub) for p in sorted((PROJECT / "data" / "public").iterdir())]
    items.append((PROJECT / "data" / "http.cap", pub))        # normal web browsing, no attacks
    return items


def matches(alert, label):
    """Does this alert describe this ground-truth attack?"""
    if alert["attack_type"] != label["attack_type"]:
        return False
    if str(label["dst"]) not in str(alert["dst"]):
        return False
    if label["src"] != "*" and str(label["src"]) not in str(alert["src"]):
        return False
    if pd.notna(label["start"]):
        if alert["end_time"] < label["start"] - TIME_TOLERANCE or alert["time"] > label["end"] + TIME_TOLERANCE:
            return False
    return True


def score(alerts, labels):
    """Mark each label detected/missed and each alert true/false positive."""
    labels = labels.copy()
    alerts = alerts.copy()
    labels["detected"] = pd.Series(
        [any(matches(a, l) for _, a in alerts.iterrows()) for _, l in labels.iterrows()],
        index=labels.index, dtype=bool)
    alerts["true_positive"] = pd.Series(
        [any(matches(a, l) for _, l in labels.iterrows()) for _, a in alerts.iterrows()],
        index=alerts.index, dtype=bool)
    return alerts, labels


def evaluate_all():
    per_pcap, all_alerts, all_labels = [], [], []
    for path, label_table in collect_pcaps():
        labels = label_table[label_table["pcap"] == path.name]
        packets, _, alerts, timings = analyze(path)
        alerts, labels = score(alerts, labels)
        alerts.insert(0, "pcap", path.name)
        all_alerts.append(alerts)
        all_labels.append(labels)
        tp = int(labels["detected"].sum())
        fp = int((~alerts["true_positive"]).sum())
        per_pcap.append({
            "pcap": path.name, "source": "public" if path.parent.name != "lab" else "lab (generated)",
            "packets": len(packets), "size_kb": round(path.stat().st_size / 1024, 1),
            "attacks_in_truth": len(labels), "detected": tp, "missed": len(labels) - tp,
            "alerts": len(alerts), "false_positives": fp, "time_s": round(timings["total_s"], 2),
        })
        print(f"  {path.name:<28} truth={len(labels):>2}  detected={tp:>2}  alerts={len(alerts):>2}  "
              f"FP={fp}  {timings['total_s']:.2f}s")
    alerts = pd.concat(all_alerts, ignore_index=True)
    labels = pd.concat(all_labels, ignore_index=True)
    alerts["true_positive"] = alerts["true_positive"].astype(bool)
    labels["detected"] = labels["detected"].astype(bool)
    return pd.DataFrame(per_pcap), alerts, labels


def per_attack_table(alerts, labels):
    rows = []
    for attack in sorted(set(labels["attack_type"]) | set(alerts["attack_type"])):
        lab = labels[labels["attack_type"] == attack]
        al = alerts[alerts["attack_type"] == attack]
        tp_alerts = int(al["true_positive"].sum())
        rows.append({
            "attack_type": attack, "ground_truth": len(lab), "detected": int(lab["detected"].sum()),
            "missed": int((~lab["detected"]).sum()),
            "detection_rate_%": round(100 * lab["detected"].mean(), 1) if len(lab) else None,
            "alerts": len(al), "false_positives": len(al) - tp_alerts,
            "precision_%": round(100 * tp_alerts / len(al), 1) if len(al) else None,
        })
    return pd.DataFrame(rows)


# ---------------------------------------------------------------- charts


def chart_detection(per_attack):
    df = per_attack[per_attack["ground_truth"] > 0].sort_values("ground_truth")
    fig, ax = plt.subplots(figsize=(8, 4.2))
    y = range(len(df))
    ax.barh(y, df["detected"], color=plot_style.SERIES[0], height=0.6, label="Detected")
    ax.barh(y, df["missed"], left=df["detected"], color=plot_style.SERIES[1], height=0.6, label="Missed",
            edgecolor=plot_style.SURFACE, linewidth=2)
    for i, (_, r) in enumerate(df.iterrows()):
        ax.text(r["ground_truth"] + 0.15, i, f"{r['detected']}/{r['ground_truth']}  ({r['detection_rate_%']:.0f}%)",
                va="center", color=plot_style.INK_2, fontsize=9)
    ax.set_yticks(list(y), df["attack_type"])
    ax.set_xlabel("Ground-truth attack instances")
    ax.set_xlim(0, df["ground_truth"].max() * 1.35)
    ax.grid(axis="y", visible=False)
    ax.set_title("Detection results per attack type (all PCAPs)")
    ax.legend(loc="lower right")
    plot_style.save(fig, FIG_DIR / "detection_per_attack.png")


def chart_traffic_timeline(pcap, labels):
    """Packets per second for the mixed-attack capture, attack periods shaded."""
    pk = parse_pcap(pcap)
    t0 = pk["time"].min()
    pps = ((pk["time"] - t0) // 1).value_counts().sort_index()
    fig, ax = plt.subplots(figsize=(11, 4.2))
    ax.plot(pps.index, pps.values, color=plot_style.SERIES[0], linewidth=1.5)
    ax.set_yscale("log")
    lab = labels[labels["pcap"] == pcap.name].drop_duplicates("attack_type", keep="first")
    for i, (_, l) in enumerate(lab.sort_values("start").iterrows()):
        s, e = l["start"] - t0, l["end"] - t0
        ax.axvspan(s, max(e, s + 3), color=plot_style.MUTED, alpha=0.15, linewidth=0)
        ax.text(s, ax.get_ylim()[1] * (0.55 if i % 2 else 0.3), l["attack_type"], fontsize=8,
                color=plot_style.INK_2, rotation=90, va="top", ha="right")
    ax.set_xlabel("Seconds since start of capture")
    ax.set_ylabel("Packets per second (log scale)")
    ax.set_title(f"Traffic over time - {pcap.name} (shaded = labelled attack)")
    plot_style.save(fig, FIG_DIR / "traffic_timeline_mixed.png")


def chart_slow_scan_windows():
    """Why the slow scan is missed, and how a longer window would catch it."""
    pk = parse_pcap(PROJECT / "data" / "lab" / "slow_port_scan.pcap")
    syn = pk[(pk["protocol"] == "TCP") & is_syn(pk["tcp_flags"])]
    rows = []
    for w in [10, 60, 120, 300, 600]:
        win = ((syn["time"] - pk["time"].min()) // w).astype(int)
        per = syn.assign(win=win).groupby(["src_ip", "dst_ip", "win"])["dport"].nunique()
        scanner = per.xs(gen.ATTACKER, level="src_ip").max()
        normal = per.drop(gen.ATTACKER, level="src_ip", errors="ignore").max()
        rows.append((f"{w} s", scanner, normal))
    df = pd.DataFrame(rows, columns=["window", "scanner", "normal"])
    fig, ax = plt.subplots(figsize=(8, 4.2))
    x = range(len(df))
    ax.bar([i - 0.2 for i in x], df["scanner"], width=0.38, color=plot_style.SERIES[1],
           label="Slow scanner (192.168.56.101)")
    ax.bar([i + 0.2 for i in x], df["normal"], width=0.38, color=plot_style.SERIES[0],
           label="Busiest normal host")
    ax.axhline(config.PORTSCAN_MIN_UNIQUE_PORTS, color=plot_style.INK_2, linestyle="--", linewidth=1.2)
    ax.text(-0.4, config.PORTSCAN_MIN_UNIQUE_PORTS + 0.8,
            f"alert threshold = {config.PORTSCAN_MIN_UNIQUE_PORTS} ports", ha="left",
            color=plot_style.INK_2, fontsize=9)
    for i, r in df.iterrows():
        ax.text(i - 0.2, r["scanner"] + 0.5, str(r["scanner"]), ha="center", fontsize=9, color=plot_style.INK_2)
    ax.set_xticks(list(x), df["window"])
    ax.set_xlabel("Time-window length")
    ax.set_ylabel("Max distinct ports in one window")
    ax.grid(axis="x", visible=False)
    ax.set_title("Slow port scan (1 port / 15 s) vs window length")
    ax.legend(loc="upper left")
    plot_style.save(fig, FIG_DIR / "slow_scan_window_sensitivity.png")
    return df


def scale_test():
    """Processing time vs capture size, using normal traffic of increasing length."""
    out = PROJECT / "data" / "scale"
    out.mkdir(parents=True, exist_ok=True)
    rows = []
    for seconds in [60, 300, 900, 1800]:
        path = out / f"normal_{seconds}s.pcap"
        if not path.exists():
            tr = gen.Trace(random.Random(seconds))
            gen.normal_background(tr, 0, seconds)
            tr.save(path)
        packets, _, alerts, t = analyze(path)
        rows.append({"pcap": path.name, "packets": len(packets),
                     "size_mb": round(path.stat().st_size / 1e6, 2), "parse_s": round(t["parse_s"], 2),
                     "features_s": round(t["features_s"], 2), "detect_s": round(t["detect_s"], 2),
                     "total_s": round(t["total_s"], 2), "alerts": len(alerts)})
        print(f"  {path.name:<20} {len(packets):>7} packets  {t['total_s']:.2f}s  alerts={len(alerts)}")
    df = pd.DataFrame(rows)
    fig, ax = plt.subplots(figsize=(8, 4.2))
    ax.plot(df["packets"], df["total_s"], color=plot_style.SERIES[0], marker="o", markersize=8,
            markeredgecolor=plot_style.SURFACE, markeredgewidth=2)
    for _, r in df.iterrows():
        ax.annotate(f"{r['total_s']:.1f} s\n({r['size_mb']} MB)", (r["packets"], r["total_s"]),
                    textcoords="offset points", xytext=(-8, 10), ha="right", fontsize=8,
                    color=plot_style.INK_2)
    ax.set_xlabel("Packets in capture")
    ax.set_ylabel("Total processing time (s)")
    ax.set_ylim(0, df["total_s"].max() * 1.3)
    ax.set_xlim(0, df["packets"].max() * 1.08)
    ax.set_title("Processing time vs capture size")
    plot_style.save(fig, FIG_DIR / "processing_time.png")
    rate = df["packets"].sum() / df["total_s"].sum()
    print(f"  average throughput: {rate:,.0f} packets/s")
    return df


def chart_severity(alerts):
    order = [s for s in reversed(config.SEVERITY_LEVELS) if s in set(alerts["severity"])]
    counts = alerts["severity"].value_counts().reindex(order)
    fig, ax = plt.subplots(figsize=(6, 3.2))
    ax.bar(counts.index, counts.values, color=[plot_style.SEVERITY_COLORS[s] for s in counts.index],
           width=0.6)
    for i, v in enumerate(counts.values):
        ax.text(i, v + 0.3, str(v), ha="center", color=plot_style.INK_2)
    ax.set_ylabel("Alerts")
    ax.grid(axis="x", visible=False)
    ax.set_title("Alerts by severity (all PCAPs)")
    plot_style.save(fig, FIG_DIR / "alerts_by_severity.png")


def main():
    ap = argparse.ArgumentParser(description="Evaluate detectors against ground truth")
    ap.add_argument("--no-scale", action="store_true", help="skip the processing-time test")
    args = ap.parse_args()
    plot_style.apply()
    EVAL_DIR.mkdir(parents=True, exist_ok=True)

    print("[1] Running analyzer on every PCAP ...")
    per_pcap, alerts, labels = evaluate_all()
    per_attack = per_attack_table(alerts, labels)
    per_pcap.to_csv(EVAL_DIR / "results_per_pcap.csv", index=False)
    per_attack.to_csv(EVAL_DIR / "results_per_attack.csv", index=False)
    alerts.to_csv(EVAL_DIR / "all_alerts.csv", index=False)
    labels.to_csv(EVAL_DIR / "ground_truth_scored.csv", index=False)

    total, found = len(labels), int(labels["detected"].sum())
    tp = int(alerts["true_positive"].sum())
    print("\nPer-attack results:")
    print(per_attack.to_string(index=False))
    print(f"\nOVERALL: detection rate {found}/{total} = {100 * found / total:.1f}%  |  "
          f"alerts {len(alerts)}, true {tp}, false {len(alerts) - tp}  |  "
          f"precision {100 * tp / max(len(alerts), 1):.1f}%")
    normal = per_pcap[per_pcap["attacks_in_truth"] == 0]
    print(f"Attack-free PCAPs: {len(normal)}, false alerts on them: {int(normal['alerts'].sum())}")

    print("\n[2] Charts ...")
    chart_detection(per_attack)
    chart_severity(alerts)
    chart_traffic_timeline(PROJECT / "data" / "lab" / "mixed_attacks.pcap", labels)
    slow = chart_slow_scan_windows()
    slow.to_csv(EVAL_DIR / "slow_scan_windows.csv", index=False)

    if not args.no_scale:
        print("\n[3] Processing-time test ...")
        t = time.perf_counter()
        scale_test().to_csv(EVAL_DIR / "processing_time.csv", index=False)
        print(f"  (speed test took {time.perf_counter() - t:.0f}s)")
    print(f"\n[OK] Results in {EVAL_DIR} and charts in {FIG_DIR}")


if __name__ == "__main__":
    main()
