"""
Checkpoint 5 - machine-learning comparison (Random Forest vs rule-based).

Mode 1 (default, works offline):
    Flow features are computed per (source IP, destination IP, 10 s window) from
    the generated lab PCAPs. The Random Forest TRAINS on data/lab (seed 1) and is
    TESTED on data/lab_test (seed 2, generated automatically) - different random
    traffic, so it is never tested on what it learned from. The rule-based
    detectors are scored on the exact same test flows.

    python src/ml_compare.py

Mode 2 (real labelled dataset):
    Download CIC-IDS2017 "MachineLearningCSV" files from
    https://www.unb.ca/cic/datasets/ids-2017.html and pass one or more CSVs:

    python src/ml_compare.py --cic data/cic/Wednesday-workingHours.pcap_ISCX.csv

Outputs: reports/evaluation/ml_*.csv and reports/figures/ml_*.png
"""
import argparse
import subprocess
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, precision_recall_fscore_support
from sklearn.model_selection import train_test_split

sys.path.insert(0, str(Path(__file__).resolve().parent))
import config  # noqa: E402
import generate_lab_pcaps as gen  # noqa: E402
import plot_style  # noqa: E402
from features import (add_window, is_fin, is_pure_ack, is_rst, is_syn, is_synack,  # noqa: E402
                      shannon_entropy)
from main import analyze  # noqa: E402

PROJECT = Path(__file__).resolve().parent.parent
EVAL_DIR = PROJECT / "reports" / "evaluation"
FIG_DIR = PROJECT / "reports" / "figures"
WINDOW = config.WINDOW_SECONDS
# Attacks a flow-statistics model can see. ARP spoofing (layer 2, no IP flow) and
# plaintext credentials (needs payload inspection) are out of reach for flow-based ML.
CLASSES = ["Normal", "Port Scan", "SYN Flood", "Brute Force", "DNS Tunneling", "ICMP Flood", "Suspicious Port"]
LOCAL_HOSTS = set(gen.MACS)
plt = plot_style.plt

FEATURES = ["packets", "bytes", "mean_len", "duration", "pkt_rate", "unique_dports", "unique_sports",
            "syn", "ack", "rst", "fin", "psh", "rst_received", "synack_received", "icmp_echo",
            "dns_queries", "avg_qname_len", "max_qname_entropy", "payload_bytes",
            "dst_syn_total", "dst_unique_srcs", "min_dport"]


def _sub_entropy(name):
    if not isinstance(name, str):
        return 0.0
    return shannon_entropy("".join(name.split(".")[:-2]))


def flow_windows(packets):
    """One row per (src, dst, 10 s window) with statistics a model can learn from."""
    ip = packets[packets["src_ip"].notna() & packets["dst_ip"].notna()].copy()
    ip = add_window(ip, WINDOW)
    f = ip["tcp_flags"]
    ip["syn"], ip["ack"], ip["rst"], ip["fin"] = is_syn(f), is_pure_ack(f), is_rst(f), is_fin(f)
    ip["psh"] = f.str.contains("P")
    ip["synack"] = is_synack(f)
    ip["icmp_echo"] = ip["icmp_type"].fillna(-1) == 8
    ip["dns_q"] = (ip["protocol"] == "DNS") & (ip["dns_qr"].fillna(-1) == 0)
    ip["qlen"] = ip["dns_qname"].str.len().where(ip["dns_q"])
    ip["qent"] = ip["dns_qname"].where(ip["dns_q"]).map(_sub_entropy)
    ip["pay"] = ip["payload"].str.len()

    key = ["src_ip", "dst_ip", "window"]
    g = ip.groupby(key).agg(
        window_start=("window_start", "first"), packets=("length", "size"), bytes=("length", "sum"),
        mean_len=("length", "mean"), t_min=("time", "min"), t_max=("time", "max"),
        unique_dports=("dport", "nunique"), unique_sports=("sport", "nunique"),
        syn=("syn", "sum"), ack=("ack", "sum"), rst=("rst", "sum"), fin=("fin", "sum"),
        psh=("psh", "sum"), icmp_echo=("icmp_echo", "sum"), dns_queries=("dns_q", "sum"),
        avg_qname_len=("qlen", "mean"), max_qname_entropy=("qent", "max"),
        payload_bytes=("pay", "sum"), min_dport=("dport", "min"),
    ).reset_index()
    g["duration"] = g["t_max"] - g["t_min"]
    g["pkt_rate"] = g["packets"] / WINDOW

    # How did the other side answer? (RST = closed port, SYN/ACK = open port)
    rev = ip.groupby(["dst_ip", "src_ip", "window"]).agg(rst_received=("rst", "sum"),
                                                         synack_received=("synack", "sum"))
    rev.index.names = key
    g = g.merge(rev.reset_index(), on=key, how="left")
    # Context about the destination: is it being hit by many SYNs from many hosts?
    ctx = ip[ip["syn"]].groupby(["dst_ip", "window"]).agg(dst_syn_total=("syn", "size"),
                                                         dst_unique_srcs=("src_ip", "nunique"))
    g = g.merge(ctx.reset_index(), on=["dst_ip", "window"], how="left")
    g[FEATURES] = g[FEATURES].astype(float).fillna(0)
    return g


def assign(flows, events):
    """Give each flow the attack type of the first event (label or alert) that covers it."""
    out = pd.Series("Normal", index=flows.index, dtype=object)
    drop = pd.Series(False, index=flows.index)
    w0, w1 = flows["window_start"], flows["window_start"] + WINDOW
    for _, e in events.iterrows():
        when = (w1 >= e["start"] - 1) & (w0 <= e["end"] + 1)
        if e["src"] == "*":
            who = ~flows["src_ip"].isin(LOCAL_HOSTS)
        else:
            who = flows["src_ip"] == e["src"]
        if e["attack_type"] == "DNS Tunneling":
            m = when & who & (flows["dns_queries"] > 0)
        elif e["attack_type"] == "SYN Flood":
            m = when & who & (flows["dst_ip"] == e["dst"]) & (flows["syn"] > 0) & (flows["ack"] == 0)
        else:
            m = when & who & (flows["dst_ip"] == e["dst"])
        if e["attack_type"] in CLASSES:
            out[m & (out == "Normal")] = e["attack_type"]
        else:
            drop |= m          # flows of attacks flow-ML cannot see are left out of scoring
    drop &= out == "Normal"
    return out, drop


def alerts_as_events(alerts):
    ev = alerts.rename(columns={"time": "start", "end_time": "end"})[["attack_type", "src", "dst", "start", "end"]]
    ev = ev.copy()
    ev["src"] = ev["src"].where(ev["src"].str.match(r"^\d+\.\d+\.\d+\.\d+$"), "*")
    ev["dst"] = ev["dst"].str.split(":").str[0]
    return ev


def build_dataset(folder):
    labels = pd.read_csv(folder / "labels.csv")
    parts = []
    for pcap in sorted(folder.glob("*.pcap")):
        packets, _, alerts, _ = analyze(pcap)
        flows = flow_windows(packets)
        lab = labels[labels["pcap"] == pcap.name]
        flows["label"], drop_l = assign(flows, lab)
        flows["rule_pred"], _ = assign(flows, alerts_as_events(alerts))
        flows["pcap"] = pcap.name
        parts.append(flows[~drop_l])
        print(f"  {pcap.name:<28} {len(flows):>6} flows")
    return pd.concat(parts, ignore_index=True)


def metrics(y_true, y_pred, name):
    p, r, f, _ = precision_recall_fscore_support(y_true, y_pred, labels=CLASSES[1:], average="macro",
                                                 zero_division=0)
    attack_true, attack_pred = y_true != "Normal", y_pred != "Normal"
    normal = ~attack_true
    return {
        "method": name,
        "accuracy_%": round(100 * accuracy_score(y_true, y_pred), 2),
        "macro_precision_%": round(100 * p, 2), "macro_recall_%": round(100 * r, 2),
        "macro_f1_%": round(100 * f, 2),
        "attack_flows_detected_%": round(100 * (attack_pred & attack_true).sum() / attack_true.sum(), 2),
        "false_positive_flows": int((attack_pred & normal).sum()),
        "false_positive_rate_%": round(100 * (attack_pred & normal).sum() / normal.sum(), 3),
    }


def per_class(y_true, y_pred, name):
    p, r, f, s = precision_recall_fscore_support(y_true, y_pred, labels=CLASSES, zero_division=0)
    return pd.DataFrame({"method": name, "class": CLASSES, "precision_%": (100 * p).round(1),
                         "recall_%": (100 * r).round(1), "f1_%": (100 * f).round(1), "support": s})


def plot_confusions(y_true, preds, names, path, classes=CLASSES):
    fig, axes = plt.subplots(1, len(preds), figsize=(6.4 * len(preds), 5.6))
    axes = np.atleast_1d(axes)
    for ax, y_pred, name in zip(axes, preds, names):
        cm = confusion_matrix(y_true, y_pred, labels=classes)
        pct = cm / np.maximum(cm.sum(axis=1, keepdims=True), 1)
        ax.imshow(pct, cmap="Blues", vmin=0, vmax=1)
        for i in range(len(classes)):
            for j in range(len(classes)):
                if cm[i, j]:
                    ax.text(j, i, str(cm[i, j]), ha="center", va="center", fontsize=8,
                            color="white" if pct[i, j] > 0.55 else plot_style.INK)
        ax.set_xticks(range(len(classes)), classes, rotation=40, ha="right")
        ax.set_yticks(range(len(classes)), classes)
        ax.set_xlabel("Predicted")
        ax.set_ylabel("Actual (ground truth)")
        ax.grid(False)
        ax.set_title(name)
    plot_style.save(fig, path)


def plot_importance(model, names, path):
    imp = pd.Series(model.feature_importances_, index=names).sort_values().tail(12)
    fig, ax = plt.subplots(figsize=(7, 4.4))
    ax.barh(imp.index, imp.values, color=plot_style.SERIES[0], height=0.6)
    ax.set_xlabel("Importance (mean decrease in impurity)")
    ax.grid(axis="y", visible=False)
    ax.set_title("Random Forest - most useful flow features")
    plot_style.save(fig, path)


def run_lab():
    train_dir, test_dir = PROJECT / "data" / "lab", PROJECT / "data" / "lab_test"
    if not (test_dir / "labels.csv").exists():
        print("[i] Generating independent TEST dataset (seed 2) ...")
        subprocess.run([sys.executable, str(PROJECT / "src" / "generate_lab_pcaps.py"),
                        "--seed", "2", "--out", str(test_dir)], check=True)
    print("[1] Training flows (seed 1):")
    train = build_dataset(train_dir)
    print("[2] Test flows (seed 2):")
    test = build_dataset(test_dir)
    print(f"\nTrain: {len(train)} flows | Test: {len(test)} flows")
    print("Test class counts:", test["label"].value_counts().to_dict())

    model = RandomForestClassifier(n_estimators=200, class_weight="balanced", random_state=42, n_jobs=-1)
    t = time.perf_counter()
    model.fit(train[FEATURES], train["label"])
    train_s = time.perf_counter() - t
    test["rf_pred"] = model.predict(test[FEATURES])

    y = test["label"].to_numpy()
    summary = pd.DataFrame([metrics(y, test["rule_pred"].to_numpy(), "Rule-based (detectors.py)"),
                            metrics(y, test["rf_pred"].to_numpy(), "Random Forest (ml_compare.py)")])
    classes = pd.concat([per_class(y, test["rule_pred"].to_numpy(), "Rule-based"),
                         per_class(y, test["rf_pred"].to_numpy(), "Random Forest")])
    summary.to_csv(EVAL_DIR / "ml_vs_rules_summary.csv", index=False)
    classes.to_csv(EVAL_DIR / "ml_vs_rules_per_class.csv", index=False)
    print(f"\nRandom Forest trained in {train_s:.1f}s")
    print("\n=== Rule-based vs Random Forest (test set) ===")
    print(summary.T.to_string(header=False))
    print("\nPer class:")
    print(classes.to_string(index=False))

    # Where do they disagree? Useful for the report discussion.
    slow = test[test["pcap"] == "slow_port_scan.pcap"]
    slow_scan = slow[slow["label"] == "Port Scan"]
    print(f"\nSlow scan flows: {len(slow_scan)} | rules caught {int((slow_scan['rule_pred'] == 'Port Scan').sum())}"
          f" | RF caught {int((slow_scan['rf_pred'] == 'Port Scan').sum())}")
    fp = test[(test["label"] == "Normal") & (test["rf_pred"] != "Normal")]
    if len(fp):
        print("RF false positives (first 5):")
        print(fp[["pcap", "src_ip", "dst_ip", "window", "packets", "rf_pred"]].head().to_string(index=False))

    plot_confusions(y, [test["rule_pred"].to_numpy(), test["rf_pred"].to_numpy()],
                    ["Rule-based detectors", "Random Forest"], FIG_DIR / "ml_confusion_matrices.png")
    plot_importance(model, FEATURES, FIG_DIR / "ml_feature_importance.png")


def run_cic(paths, max_rows):
    frames = []
    for p in paths:
        df = pd.read_csv(p, low_memory=False)
        df.columns = df.columns.str.strip()
        frames.append(df)
    df = pd.concat(frames, ignore_index=True)
    if len(df) > max_rows:
        df = df.sample(max_rows, random_state=42)
    y = df.pop("Label").astype(str).str.strip()
    X = df.select_dtypes("number").replace([np.inf, -np.inf], np.nan)
    keep = X.notna().all(axis=1)
    X, y = X[keep], y[keep]
    print(f"[i] CIC-IDS2017: {len(X)} flows, {X.shape[1]} features, classes: {y.value_counts().to_dict()}")
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.3, stratify=y, random_state=42)
    model = RandomForestClassifier(n_estimators=100, class_weight="balanced", random_state=42, n_jobs=-1)
    model.fit(Xtr, ytr)
    pred = model.predict(Xte)
    classes = sorted(y.unique(), key=lambda c: (c != "BENIGN", c))
    p, r, f, s = precision_recall_fscore_support(yte, pred, labels=classes, zero_division=0)
    rep = pd.DataFrame({"class": classes, "precision_%": (100 * p).round(2), "recall_%": (100 * r).round(2),
                        "f1_%": (100 * f).round(2), "support": s})
    print(f"Accuracy: {100 * accuracy_score(yte, pred):.2f}%")
    print(rep.to_string(index=False))
    rep.to_csv(EVAL_DIR / "ml_cic_ids2017_results.csv", index=False)
    plot_confusions(yte.to_numpy(), [pred], ["Random Forest on CIC-IDS2017"],
                    FIG_DIR / "ml_cic_confusion.png", classes=classes)
    plot_importance(model, list(X.columns), FIG_DIR / "ml_cic_feature_importance.png")


def main():
    ap = argparse.ArgumentParser(description="Random Forest vs rule-based comparison")
    ap.add_argument("--cic", nargs="+", help="CIC-IDS2017 MachineLearningCSV file(s)")
    ap.add_argument("--max-rows", type=int, default=300_000)
    args = ap.parse_args()
    plot_style.apply()
    EVAL_DIR.mkdir(parents=True, exist_ok=True)
    if args.cic:
        run_cic(args.cic, args.max_rows)
    else:
        run_lab()


if __name__ == "__main__":
    main()
