"""Executes the mandatory comparative evaluation across Classifier-only, LLM-only, and Combined pipeline."""

import os, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cybersentinel.comparative_eval import run_comparative_experiment

def main():
    res = run_comparative_experiment(
        test_csv="data/processed/hdfs_test.csv",
        ml_model_path="artifacts/hdfs_best_ml_model.joblib",
        sample_limit=150
    )
    print("\nComparison Results Summary:")
    for r in res["metrics_table"]:
        print(f"  {r['Configuration']}: Accuracy={r['accuracy']}%, Macro-F1={r['macro_f1']}%, Latency={r['latency_ms']}ms")

if __name__ == "__main__":
    main()
