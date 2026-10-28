"""
Draws the system architecture diagram for the report.

Usage:
    python src/draw_architecture.py      -> saves reports/architecture.png
"""
from pathlib import Path

import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch

OUT = Path("reports") / "architecture.png"

# Colours: grey = input/output, blue = processing, red = detection, light = support
GREY, BLUE, RED, LIGHT = "#e8e8e8", "#d6e6f5", "#f7d9d4", "#f5f5f0"
EDGE = "#333333"

BOX_W, BOX_H = 2.2, 1.6
MAIN_Y = 3.4
STEP = 2.65


def box(ax, x, y, title, lines, color, w=BOX_W, h=BOX_H, dashed=False):
    ax.add_patch(FancyBboxPatch(
        (x, y), w, h, boxstyle="round,pad=0.05,rounding_size=0.12",
        facecolor=color, edgecolor=EDGE, linewidth=1.4,
        linestyle="--" if dashed else "-"))
    ax.text(x + w / 2, y + h - 0.32, title, ha="center", va="center",
            fontsize=11, fontweight="bold")
    ax.text(x + w / 2, y + (h - 0.45) / 2, "\n".join(lines), ha="center",
            va="center", fontsize=8.5, linespacing=1.4)


def arrow(ax, start, end, dashed=False, label=None):
    ax.add_patch(FancyArrowPatch(
        start, end, arrowstyle="-|>", mutation_scale=16, color=EDGE,
        linewidth=1.4, linestyle="--" if dashed else "-"))
    if label:
        mx, my = (start[0] + end[0]) / 2, (start[1] + end[1]) / 2
        ax.text(mx + 0.08, my, label, fontsize=8, style="italic", va="center")


def main():
    fig, ax = plt.subplots(figsize=(16, 6.2))
    ax.set_xlim(0, 16.2)
    ax.set_ylim(0, 6.2)
    ax.axis("off")

    main_boxes = [
        ("Input", ["PCAP file (public dataset)", "or live capture", "(Npcap, own lab only)"], GREY),
        ("Parser", ["parser.py (Scapy)", "per-packet fields:", "time, IPs, ports, flags,", "ARP / DNS / payload"], BLUE),
        ("Feature Extractor", ["features.py (pandas)", "per-source, per-window:", "pkt rate, unique ports,", "SYN/ACK ratio, fails"], BLUE),
        ("Detectors", ["detectors.py", "port scan | SYN flood", "ARP spoof | brute force", "plaintext creds | extras"], RED),
        ("Alerts", ["time, type, severity,", "source, target,", "evidence", "-> alerts.csv / .json"], RED),
        ("Presentation", ["dashboard/app.py", "(Streamlit) +", "main.py console output", "+ report charts"], GREY),
    ]
    xs = [0.2 + i * STEP for i in range(len(main_boxes))]
    for x, (title, lines, color) in zip(xs, main_boxes):
        box(ax, x, MAIN_Y, title, lines, color)
    for i in range(len(xs) - 1):
        arrow(ax, (xs[i] + BOX_W + 0.05, MAIN_Y + BOX_H / 2),
              (xs[i + 1] - 0.05, MAIN_Y + BOX_H / 2))

    # Intermediate data products shown above the arrows
    ax.text((xs[1] + BOX_W + xs[2]) / 2, MAIN_Y + BOX_H + 0.25, "packets.csv",
            ha="center", fontsize=8, style="italic")
    ax.text((xs[2] + BOX_W + xs[3]) / 2, MAIN_Y + BOX_H + 0.25, "features.csv",
            ha="center", fontsize=8, style="italic")

    # Support row
    low_y, low_h = 0.5, 1.35
    box(ax, xs[2], low_y, "ML (optional)", ["ml_compare.py", "Random Forest on", "CIC-IDS2017 flows"],
        LIGHT, h=low_h, dashed=True)
    box(ax, xs[3], low_y, "config.py", ["all thresholds", "in one place"], LIGHT, h=low_h)
    box(ax, xs[4], low_y, "Evaluation", ["evaluate.py", "detection rate, FP,", "precision / recall"], LIGHT, h=low_h)
    box(ax, xs[5], low_y, "Ground truth", ["dataset labels", "(known attacks)"], LIGHT, h=low_h)

    cx = BOX_W / 2
    arrow(ax, (xs[2] + cx, MAIN_Y - 0.05), (xs[2] + cx, low_y + low_h + 0.05), dashed=True)
    arrow(ax, (xs[3] + cx, low_y + low_h + 0.05), (xs[3] + cx, MAIN_Y - 0.05), label="thresholds")
    arrow(ax, (xs[4] + cx, MAIN_Y - 0.05), (xs[4] + cx, low_y + low_h + 0.05))
    arrow(ax, (xs[5] - 0.05, low_y + low_h / 2), (xs[4] + BOX_W + 0.05, low_y + low_h / 2))

    ax.text(8.1, 6.0, "Cyber Threat Analyzer - System Architecture", ha="center",
            fontsize=14, fontweight="bold")

    OUT.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(OUT, dpi=200, bbox_inches="tight")
    print(f"[OK] Saved {OUT}")


if __name__ == "__main__":
    main()
