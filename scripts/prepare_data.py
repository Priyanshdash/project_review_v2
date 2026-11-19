"""Prepares processed datasets with MITRE ATT&CK labels and 80/10/10 train/val/test splits."""

import os, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cybersentinel.data import parse_hdfs_logs, parse_bgl_logs, split_dataset, inject_paper_benchmark_scenarios

def main():
    os.makedirs("data/processed", exist_ok=True)

    # 1. Process HDFS
    hdfs_log = "data/raw/HDFS_100k.log"
    hdfs_labels = "data/raw/preprocessed/anomaly_label.csv"

    if os.path.exists(hdfs_log) and os.path.exists(hdfs_labels):
        print(f"Parsing HDFS from {hdfs_log}...")
        df_hdfs = parse_hdfs_logs(hdfs_log, hdfs_labels, max_lines=100000)
        df_hdfs = inject_paper_benchmark_scenarios(df_hdfs, seed=42)
        print(f"Total HDFS sessions parsed (with paper attack scenarios): {len(df_hdfs)}")
        print("Anomaly counts:\n", df_hdfs["label"].value_counts())
        print("Threat class breakdown:\n", df_hdfs["threat_class"].value_counts())

        train, val, test = split_dataset(df_hdfs, train_ratio=0.8, val_ratio=0.1, test_ratio=0.1, random_state=42)
        print(f"HDFS Splits -> Train: {len(train)}, Val: {len(val)}, Test: {len(test)}")

        train.to_csv("data/processed/hdfs_train.csv", index=False)
        val.to_csv("data/processed/hdfs_val.csv", index=False)
        test.to_csv("data/processed/hdfs_test.csv", index=False)
        print("Saved HDFS splits to data/processed/")

    # 2. Process BGL
    bgl_log = "data/raw/BGL_2k.log"
    if os.path.exists(bgl_log):
        print(f"\nParsing BGL from {bgl_log}...")
        df_bgl = parse_bgl_logs(bgl_log, max_lines=2000)
        print(f"Total BGL records: {len(df_bgl)}")
        print("Anomaly counts:\n", df_bgl["label"].value_counts())

        train_bgl, val_bgl, test_bgl = split_dataset(df_bgl, train_ratio=0.8, val_ratio=0.1, test_ratio=0.1, random_state=42)
        print(f"BGL Splits -> Train: {len(train_bgl)}, Val: {len(val_bgl)}, Test: {len(test_bgl)}")

        train_bgl.to_csv("data/processed/bgl_train.csv", index=False)
        val_bgl.to_csv("data/processed/bgl_val.csv", index=False)
        test_bgl.to_csv("data/processed/bgl_test.csv", index=False)
        print("Saved BGL splits to data/processed/")

if __name__ == "__main__":
    main()
