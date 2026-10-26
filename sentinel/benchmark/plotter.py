"""Renders comparative benchmark charts for single open-weight models vs Sentinel Jury."""

from __future__ import annotations
import json
from pathlib import Path
from typing import Any, Dict

import matplotlib
matplotlib.use("Agg")  # Headless rendering
import matplotlib.pyplot as plt
import numpy as np


class BenchmarkPlotter:
    """Generates visual charts demonstrating the measurable gain of the Jury harness."""

    @classmethod
    def plot_results(
        cls,
        results_path: str = "benchmark/results.json",
        output_image: str = "benchmark/benchmark_chart.png",
    ) -> Path:
        p = Path(results_path)
        if not p.exists():
            raise FileNotFoundError(f"Results file not found: {p}")

        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)

        metrics = data.get("metrics", {})
        if not metrics:
            raise ValueError("No metrics found in results JSON.")

        models = list(metrics.keys())
        precisions = [metrics[m]["precision"] * 100 for m in models]
        recalls = [metrics[m]["recall"] * 100 for m in models]
        f1_scores = [metrics[m]["f1_score"] * 100 for m in models]
        fprs = [metrics[m]["false_positive_rate"] * 100 for m in models]

        # Short clean names for chart
        short_labels = []
        for m in models:
            if "Injection" in m:
                short_labels.append("Juror 1 (Llama-3.2)")
            elif "Auth" in m:
                short_labels.append("Juror 2 (Qwen-2.5)")
            elif "Supply" in m:
                short_labels.append("Juror 3 (SmolLM-2)")
            elif "Jury" in m:
                short_labels.append("Sentinel Jury (Judge)")
            else:
                short_labels.append(m[:18])

        # Modern high-res aesthetic chart
        plt.style.use("seaborn-v0_8-whitegrid" if "seaborn-v0_8-whitegrid" in plt.style.available else "default")
        fig, axes = plt.subplots(1, 2, figsize=(14, 6), dpi=200)

        x = np.arange(len(models))
        width = 0.25

        # --- Subplot 1: Precision, Recall, F1 ---
        ax1 = axes[0]
        rects1 = ax1.bar(x - width, precisions, width, label="Precision", color="#3b82f6")
        rects2 = ax1.bar(x, recalls, width, label="Recall", color="#10b981")
        rects3 = ax1.bar(x + width, f1_scores, width, label="F1-Score", color="#8b5cf6")

        ax1.set_ylabel("Score (%)", fontsize=11, fontweight="bold")
        ax1.set_title("Detection Accuracy & Balance: Single Models vs. Jury", fontsize=13, fontweight="bold", pad=12)
        ax1.set_xticks(x)
        ax1.set_xticklabels(short_labels, rotation=15, ha="right", fontsize=9, fontweight="bold")
        ax1.set_ylim(0, 115)
        ax1.legend(loc="upper left", frameon=True)

        # Value labels on bars
        for rect in rects3:
            h = rect.get_height()
            ax1.annotate(
                f"{h:.1f}%",
                xy=(rect.get_x() + rect.get_width() / 2, h),
                xytext=(0, 3),
                textcoords="offset points",
                ha="center",
                va="bottom",
                fontsize=8,
                fontweight="bold",
            )

        # --- Subplot 2: False Positive Rate (The False Alarm Eliminator) ---
        ax2 = axes[1]
        colors = ["#f87171" if "Jury" not in label else "#10b981" for label in short_labels]
        rects_fpr = ax2.bar(short_labels, fprs, width=0.45, color=colors)

        ax2.set_ylabel("False Positive Rate (%)", fontsize=11, fontweight="bold")
        ax2.set_title("Hallucination & False Alarm Reduction", fontsize=13, fontweight="bold", pad=12)
        ax2.set_xticks(range(len(short_labels)))
        ax2.set_xticklabels(short_labels, rotation=15, ha="right", fontsize=9, fontweight="bold")
        ax2.set_ylim(0, max(max(fprs) * 1.3, 30))

        for rect in rects_fpr:
            h = rect.get_height()
            ax2.annotate(
                f"{h:.1f}%",
                xy=(rect.get_x() + rect.get_width() / 2, h),
                xytext=(0, 3),
                textcoords="offset points",
                ha="center",
                va="bottom",
                fontsize=9,
                fontweight="bold",
            )

        fig.suptitle(
            "Sentinel Open-Weight Jury Benchmark: Ground-Truth Security Evaluation",
            fontsize=15,
            fontweight="heavy",
            y=0.98,
        )
        plt.tight_layout()

        out = Path(output_image)
        out.parent.mkdir(parents=True, exist_ok=True)
        plt.savefig(out, bbox_inches="tight")
        plt.close()

        print(f"[Sentinel Bench] Chart saved to {out}")
        return out
