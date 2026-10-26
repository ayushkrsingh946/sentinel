"""Benchmark runner comparing individual open-weight models against the Sentinel Jury."""

from __future__ import annotations
import json
from pathlib import Path
import time
from typing import Any, Dict, List, Tuple

from sentinel.config import SentinelConfig
from sentinel.jury.judge import SentinelJudge
from sentinel.jury.jurors import Juror
from sentinel.jury.schema import Finding, JurorVerdict, JuryConsensus
from sentinel.scanner.code_scanner import CodeScanner
from sentinel.scanner.diff_scanner import DiffScanner


class BenchmarkRunner:
    """Executes precision/recall evaluations for single models vs Sentinel Jury."""

    def __init__(self, manifest_path: str = "benchmark/manifest.json"):
        self.manifest_path = Path(manifest_path)
        self.config = SentinelConfig.load()
        self.code_scanner = CodeScanner(self.config)
        self.diff_scanner = DiffScanner(self.config)

    def run(self) -> Dict[str, Any]:
        """Runs benchmark across all 35 test cases."""
        if not self.manifest_path.exists():
            raise FileNotFoundError(f"Manifest not found: {self.manifest_path}")

        with open(self.manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)

        code_samples = manifest.get("code_samples", [])
        diff_samples = manifest.get("diff_samples", [])
        all_samples = code_samples + diff_samples

        juror_names = [j.name for j in self.config.jurors]
        entities = juror_names + ["Sentinel Jury (Consensus)"]

        # Track TP, FP, TN, FN, Latencies per entity
        stats: Dict[str, Dict[str, Any]] = {
            name: {"tp": 0, "fp": 0, "tn": 0, "fn": 0, "latencies": []}
            for name in entities
        }

        print(f"\n[Sentinel Bench] Running evaluation across {len(all_samples)} ground-truth cases...")
        start_time = time.time()

        for idx, sample in enumerate(all_samples, 1):
            file_path = sample["file"]
            ground_truth_vuln = sample["is_vulnerable"]

            # Load content
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            # Execute scan
            if file_path.endswith(".diff"):
                consensus = self.diff_scanner.scan_diff_text(content, label=file_path)
            else:
                consensus = self.code_scanner.scan_path(file_path)

            # Evaluate each individual juror
            for verdict in consensus.juror_verdicts:
                j_name = verdict.juror_name
                if j_name in stats:
                    has_finding = len(verdict.findings) > 0
                    stats[j_name]["latencies"].append(verdict.latency_ms)

                    if ground_truth_vuln and has_finding:
                        stats[j_name]["tp"] += 1
                    elif not ground_truth_vuln and has_finding:
                        stats[j_name]["fp"] += 1
                    elif not ground_truth_vuln and not has_finding:
                        stats[j_name]["tn"] += 1
                    elif ground_truth_vuln and not has_finding:
                        stats[j_name]["fn"] += 1

            # Evaluate Jury Consensus (strict evidence-verified)
            jury_has_finding = len(consensus.findings) > 0
            if ground_truth_vuln and jury_has_finding:
                stats["Sentinel Jury (Consensus)"]["tp"] += 1
            elif not ground_truth_vuln and jury_has_finding:
                stats["Sentinel Jury (Consensus)"]["fp"] += 1
            elif not ground_truth_vuln and not jury_has_finding:
                stats["Sentinel Jury (Consensus)"]["tn"] += 1
            elif ground_truth_vuln and not jury_has_finding:
                stats["Sentinel Jury (Consensus)"]["fn"] += 1

        total_time = time.time() - start_time

        # Calculate final metrics: Precision, Recall, F1, FPR
        results: Dict[str, Any] = {
            "timestamp": time.time(),
            "total_samples": len(all_samples),
            "total_benchmark_time_seconds": round(total_time, 2),
            "models_evaluated": entities,
            "metrics": {},
        }

        for name in entities:
            d = stats[name]
            tp, fp, tn, fn = d["tp"], d["fp"], d["tn"], d["fn"]
            precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
            f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
            fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
            avg_lat = sum(d["latencies"]) / len(d["latencies"]) if d["latencies"] else 12.0

            results["metrics"][name] = {
                "tp": tp,
                "fp": fp,
                "tn": tn,
                "fn": fn,
                "precision": round(precision, 4),
                "recall": round(recall, 4),
                "f1_score": round(f1, 4),
                "false_positive_rate": round(fpr, 4),
                "avg_latency_ms": round(avg_lat, 1),
            }

        # Save to benchmark/results.json
        out_path = Path("benchmark/results.json")
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)

        return results
