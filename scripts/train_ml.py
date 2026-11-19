"""Runs ML training and evaluation across HDFS and BGL datasets."""

import os, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cybersentinel.ml_classifiers import run_ml_benchmark

def main():
    hdfs_res = run_ml_benchmark(dataset="hdfs")
    bgl_res = run_ml_benchmark(dataset="bgl")
    print("\n================ ML Training & Evaluation Complete ================")
    print("HDFS Best:", hdfs_res["best_model"], "Test F1:", hdfs_res["test_metrics"]["macro_f1"])
    print("BGL Best:", bgl_res["best_model"], "Test F1:", bgl_res["test_metrics"]["macro_f1"])

if __name__ == "__main__":
    main()
