"""Traditional Machine Learning Classification Pipeline for CyberSentinel-LLM.
Trains and compares baseline classifiers: Random Forest, Gradient Boosting, Logistic Regression.
Computes comprehensive metrics: Accuracy, Precision, Recall, Macro-F1, Weighted-F1, ROC-AUC,
Confusion Matrices, Training Time, and Inference Latency.
"""

from __future__ import annotations
import os
import time
import json
import joblib
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.ensemble import RandomForestClassifier, HistGradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix, classification_report
)

from .features import LogFeatureExtractor
from .data import THREAT_CLASSES, THREAT_TO_ID, ID_TO_THREAT


class MLThreatClassifier:
    """Trains, validates, and tests traditional ML classifiers for binary and multi-class cyber threat detection."""

    def __init__(self, model_type: str = "rf", is_multiclass: bool = False, random_state: int = 42):
        self.model_type = model_type.lower()
        self.is_multiclass = is_multiclass
        self.random_state = random_state
        self.feature_extractor = LogFeatureExtractor(max_features=500, d_t=16)

        if self.model_type == "rf":
            self.model = RandomForestClassifier(
                n_estimators=100, max_depth=20, random_state=random_state, class_weight="balanced"
            )
        elif self.model_type in ["gb", "gradient_boosting"]:
            self.model = HistGradientBoostingClassifier(
                max_iter=100, random_state=random_state
            )
        elif self.model_type in ["lr", "logistic_regression"]:
            self.model = LogisticRegression(
                max_iter=1000, random_state=random_state, class_weight="balanced"
            )
        else:
            raise ValueError(f"Unsupported model type: {model_type}")

    def fit(self, train_df: pd.DataFrame) -> dict:
        """Fits feature extractor and classifier on training data only."""
        t0 = time.time()
        X_train = self.feature_extractor.fit_transform(
            train_df["text"].tolist(), train_df["timestamp"].tolist()
        )
        target_col = "threat_id" if self.is_multiclass else "label"
        y_train = train_df[target_col].values

        self.model.fit(X_train, y_train)
        train_time = time.time() - t0
        return {"train_time_sec": train_time, "num_samples": len(train_df)}

    def predict(self, texts: list[str], timestamps: list[float] | None = None) -> tuple[np.ndarray, np.ndarray, float]:
        """Transforms inputs, predicts classes and probabilities, and measures inference latency."""
        t0 = time.time()
        X = self.feature_extractor.transform(texts, timestamps)
        preds = self.model.predict(X)
        if hasattr(self.model, "predict_proba"):
            probs = self.model.predict_proba(X)
        else:
            probs = np.zeros((len(preds), len(np.unique(preds))))
        latency_ms = ((time.time() - t0) / max(len(texts), 1)) * 1000.0
        return preds, probs, latency_ms

    def evaluate(self, df: pd.DataFrame) -> dict:
        """Evaluates model performance across standard metrics."""
        target_col = "threat_id" if self.is_multiclass else "label"
        y_true = df[target_col].values
        preds, probs, latency_ms = self.predict(df["text"].tolist(), df["timestamp"].tolist())

        acc = float(accuracy_score(y_true, preds))
        prec = float(precision_score(y_true, preds, average="macro", zero_division=0))
        rec = float(recall_score(y_true, preds, average="macro", zero_division=0))
        macro_f1 = float(f1_score(y_true, preds, average="macro", zero_division=0))
        weighted_f1 = float(f1_score(y_true, preds, average="weighted", zero_division=0))

        # ROC-AUC calculation
        roc_auc = 0.0
        try:
            if not self.is_multiclass:
                if probs.shape[1] > 1:
                    roc_auc = float(roc_auc_score(y_true, probs[:, 1]))
                else:
                    roc_auc = float(roc_auc_score(y_true, preds))
            else:
                roc_auc = float(roc_auc_score(y_true, probs, multi_class="ovr", average="macro"))
        except Exception:
            roc_auc = 0.0

        cm = confusion_matrix(y_true, preds).tolist()
        report = classification_report(y_true, preds, output_dict=True, zero_division=0)

        return {
            "model_type": self.model_type,
            "is_multiclass": self.is_multiclass,
            "accuracy": acc,
            "precision": prec,
            "recall": rec,
            "macro_f1": macro_f1,
            "weighted_f1": weighted_f1,
            "roc_auc": roc_auc,
            "inference_latency_ms": latency_ms,
            "confusion_matrix": cm,
            "per_class_report": report
        }

    def save(self, filepath: str) -> None:
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        joblib.dump({"model": self.model, "extractor": self.feature_extractor, "multiclass": self.is_multiclass}, filepath)

    @classmethod
    def load(cls, filepath: str) -> MLThreatClassifier:
        obj = joblib.load(filepath)
        inst = cls(model_type="rf", is_multiclass=obj.get("multiclass", False))
        inst.model = obj["model"]
        inst.feature_extractor = obj["extractor"]
        return inst


def run_ml_benchmark(dataset: str = "hdfs", results_dir: str = "results", artifacts_dir: str = "artifacts") -> dict:
    """Trains and compares Random Forest, Gradient Boosting, and Logistic Regression on dataset splits.
    Saves metrics, confusion matrix plots, and the best model checkpoint.
    """
    os.makedirs(results_dir, exist_ok=True)
    os.makedirs(artifacts_dir, exist_ok=True)

    train_df = pd.read_csv(f"data/processed/{dataset}_train.csv")
    val_df = pd.read_csv(f"data/processed/{dataset}_val.csv")
    test_df = pd.read_csv(f"data/processed/{dataset}_test.csv")

    candidates = ["rf", "gb", "lr"]
    comparison = []
    trained_models = {}

    print(f"\n================ Running ML Benchmark for {dataset.upper()} ================")
    best_val_f1 = -1.0
    best_model_name = None

    for m_type in candidates:
        print(f"Training {m_type.upper()}...")
        clf = MLThreatClassifier(model_type=m_type, is_multiclass=False, random_state=42)
        fit_info = clf.fit(train_df)

        val_metrics = clf.evaluate(val_df)
        print(f"  Validation -> Acc: {val_metrics['accuracy']:.4f}, Macro-F1: {val_metrics['macro_f1']:.4f}, ROC-AUC: {val_metrics['roc_auc']:.4f}, Latency: {val_metrics['inference_latency_ms']:.2f}ms")

        trained_models[m_type] = clf
        comparison.append({
            "model": m_type.upper(),
            "train_time_s": round(fit_info["train_time_sec"], 3),
            "val_accuracy": round(val_metrics["accuracy"] * 100, 2),
            "val_precision": round(val_metrics["precision"] * 100, 2),
            "val_recall": round(val_metrics["recall"] * 100, 2),
            "val_macro_f1": round(val_metrics["macro_f1"] * 100, 2),
            "val_roc_auc": round(val_metrics["roc_auc"] * 100, 2),
            "latency_ms": round(val_metrics["inference_latency_ms"], 2)
        })

        if val_metrics["macro_f1"] > best_val_f1:
            best_val_f1 = val_metrics["macro_f1"]
            best_model_name = m_type

    # Save comparison table
    comp_df = pd.DataFrame(comparison)
    comp_path = os.path.join(results_dir, f"{dataset}_ml_comparison.csv")
    comp_df.to_csv(comp_path, index=False)
    print(f"\nModel selection based on Validation Macro-F1: Selected Best Model = {best_model_name.upper()}")

    # Evaluate best model on Test Set
    best_clf = trained_models[best_model_name]
    test_metrics = best_clf.evaluate(test_df)
    print(f"\n=== Best Model ({best_model_name.upper()}) Final Test Evaluation ===")
    print(f"Test Accuracy: {test_metrics['accuracy']*100:.2f}%")
    print(f"Test Precision: {test_metrics['precision']*100:.2f}%")
    print(f"Test Recall: {test_metrics['recall']*100:.2f}%")
    print(f"Test Macro-F1: {test_metrics['macro_f1']*100:.2f}%")
    print(f"Test ROC-AUC: {test_metrics['roc_auc']*100:.2f}%")
    print(f"Test Latency: {test_metrics['inference_latency_ms']:.2f} ms/sample")

    # Save best model
    best_model_path = os.path.join(artifacts_dir, f"{dataset}_best_ml_model.joblib")
    best_clf.save(best_model_path)
    print(f"Saved best model checkpoint to {best_model_path}")

    # Save detailed test metrics
    test_metrics_path = os.path.join(results_dir, f"{dataset}_test_metrics.json")
    with open(test_metrics_path, "w") as f:
        json.dump(test_metrics, f, indent=2)

    # Plot Confusion Matrix
    cm = np.array(test_metrics["confusion_matrix"])
    plt.figure(figsize=(6, 5))
    plt.imshow(cm, interpolation="nearest", cmap=plt.cm.Blues)
    plt.title(f"{dataset.upper()} Confusion Matrix ({best_model_name.upper()})")
    plt.colorbar()
    tick_marks = np.arange(len(cm))
    plt.xticks(tick_marks, ["Normal", "Anomaly"])
    plt.yticks(tick_marks, ["Normal", "Anomaly"])

    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):
            plt.text(j, i, format(cm[i, j], "d"),
                     horizontalalignment="center",
                     color="white" if cm[i, j] > cm.max() / 2 else "black")

    plt.ylabel("True Label")
    plt.xlabel("Predicted Label")
    plt.tight_layout()
    cm_plot_path = os.path.join(results_dir, f"{dataset}_confusion_matrix.png")
    plt.savefig(cm_plot_path, dpi=200)
    plt.close()
    print(f"Saved confusion matrix plot to {cm_plot_path}")

    return {
        "dataset": dataset,
        "best_model": best_model_name,
        "test_metrics": test_metrics,
        "comparison_table": comp_df.to_dict(orient="records")
    }
