"""Render the published entropy measurements (optional matplotlib==3.9.2).

SPDX-License-Identifier: GPL-2.0-only
Usage: python render_entropy.py
"""
import json
from pathlib import Path
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

root = Path(__file__).resolve().parent
data = json.loads((root / "analysis/findings.json").read_text(encoding="utf-8"))
windows = data["entropy_windows_64k"]
assert sum(row["length"] for row in windows) == data["decoded_size"]
assert all(0 <= row["bits_per_byte"] <= 8 for row in windows)
plt.rcParams.update({"svg.fonttype": "none", "svg.hashsalt": "k3ii-v112", "font.size": 11})
for suffix, size, ticks in [("", (10, 3), [0, 4, 8, 12, 16]), ("-mobile", (3.6, 2.6), [0, 8, 16])]:
    fig, ax = plt.subplots(figsize=size, layout="constrained")
    x = [(row["offset"] + row["length"] / 2) / (1024 ** 2) for row in windows]
    ax.plot(x, [row["bits_per_byte"] for row in windows], color="#20638d", linewidth=1.5)
    ax.set(xlabel="Decoded file offset (MiB)", ylabel="Entropy (bit/byte)", xlim=(0, 16.06), ylim=(0, 8.15))
    ax.set_xticks(ticks)
    ax.set_yticks([0, 4, 8])
    ax.grid(axis="y", color="#d8dfe5", linewidth=.6)
    ax.spines[["top", "right"]].set_visible(False)
    output = root / f"assets/entropy{suffix}.svg"
    fig.savefig(output, metadata={"Date": None, "Description": "Shannon entropy in 64 KiB windows, K-3 II v1.12 decoded firmware. Source: analysis/findings.json"})
    output.write_text("\n".join(line.rstrip() for line in output.read_text(encoding="utf-8").splitlines()) + "\n", encoding="utf-8")
    plt.close(fig)
