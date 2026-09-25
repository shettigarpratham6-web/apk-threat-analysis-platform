"""
Training script for Random Forest Static Malware Classifier.

Uses the Drebin static APK feature dataset (215 static features: permissions,
API calls, intent filters, and suspicious paths/commands).
Trains a RandomForestClassifier with balanced class weights, evaluates on an
independent 80/20 stratified test split, computes comprehensive classification metrics,
and saves the trained model, feature order, and feature importance rankings.
"""

import argparse
import json
import os
import sys
from typing import Dict, Any, Tuple

import joblib
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split


def parse_args():
    parser = argparse.ArgumentParser(description="Train Static APK Random Forest Classifier")
    parser.add_argument(
        "--dataset",
        type=str,
        default=os.path.join("datasets", "Android Malware Analysis CSV Dataset", "drebin_dataset.csv"),
        help="Path to the static APK feature CSV dataset",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default=os.path.join("ml", "models"),
        help="Directory to save trained model and metadata artifacts",
    )
    parser.add_argument(
        "--keep-duplicates",
        action="store_true",
        default=False,
        help="If set, keep duplicate feature vectors (default False: deduplicates to prevent data leakage)",
    )
    parser.add_argument(
        "--n-estimators",
        type=int,
        default=200,
        help="Number of trees in Random Forest (default: 200)",
    )
    parser.add_argument(
        "--random-state",
        type=int,
        default=42,
        help="Random state seed (default: 42)",
    )
    return parser.parse_args()


def load_and_preprocess_dataset(
    dataset_path: str, keep_duplicates: bool = False
) -> Tuple[pd.DataFrame, pd.Series, list, Dict[str, Any]]:
    """
    Loads and inspects the dataset, maps labels, cleans non-numeric values,
    handles duplicates, and extracts feature matrix X and target y.
    """
    if not os.path.exists(dataset_path):
        raise FileNotFoundError(f"Dataset file not found at: {dataset_path}")

    print(f"Loading dataset from: {dataset_path}")
    df = pd.read_csv(dataset_path, low_memory=False)

    # 1. Identify label column
    label_candidates = [c for c in df.columns if c.lower() in ("class", "label", "target")]
    if not label_candidates:
        raise ValueError(f"Could not identify label column in dataset columns: {list(df.columns[:10])}")
    label_col = label_candidates[0]

    raw_sample_count = len(df)
    raw_feature_count = len(df.columns) - 1

    # Raw label distribution
    raw_class_counts = df[label_col].value_counts().to_dict()
    print("\n" + "=" * 60)
    print("STEP 1: DATASET INSPECTION")
    print("=" * 60)
    print(f"CSV Path:                {dataset_path}")
    print(f"Raw Sample Count:        {raw_sample_count}")
    print(f"Raw Feature Count:       {raw_feature_count}")
    print(f"Label Column:            '{label_col}'")
    print(f"Raw Class Distribution:  {raw_class_counts}")

    # Map labels: B (Benign) = 0, S (Malware/Suspicious) = 1
    # Check for numeric or string labels
    unique_labels = df[label_col].unique()
    label_map = {}
    if set(unique_labels).issubset({"B", "S"}):
        label_map = {"B": 0, "S": 1}
    elif set(unique_labels).issubset({0, 1}):
        label_map = {0: 0, 1: 1}
    else:
        # Generic heuristic: 'benign' -> 0, 'malware'/'malicious' -> 1
        for val in unique_labels:
            val_str = str(val).lower()
            if "benign" in val_str or val_str in ("0", "b", "safe"):
                label_map[val] = 0
            else:
                label_map[val] = 1

    print(f"Class Label Mapping:     {label_map} (Benign=0, Malware=1)")
    y_raw = df[label_col].map(label_map)

    # 2. Preprocess feature columns
    feature_cols = [c for c in df.columns if c != label_col]

    # Remove irrelevant identifier/leakage columns if any exist (e.g. ID, sha256, filename, hash)
    irrelevant_keywords = ("hash", "sha256", "md5", "filename", "filepath", "package_id", "app_id")
    cleaned_features = [
        c for c in feature_cols
        if not any(k == c.lower() or f"{k}_" in c.lower() or f"_{k}" in c.lower() for k in irrelevant_keywords)
    ]
    removed_cols = set(feature_cols) - set(cleaned_features)
    if removed_cols:
        print(f"Removed identifier columns: {removed_cols}")

    X = df[cleaned_features].copy()

    # Clean non-numeric / missing entries (e.g. '?' in TelephonyManager.getSimCountryIso)
    non_numeric_found = {}
    for col in X.columns:
        if X[col].dtype == object or str(X[col].dtype).startswith("string") or str(X[col].dtype).startswith("str"):
            mask = ~X[col].astype(str).str.match(r"^-?\d+$")
            if mask.any():
                problematic = X.loc[mask, col].unique().tolist()
                non_numeric_found[col] = problematic
        X[col] = pd.to_numeric(X[col].astype(str).str.strip().replace("?", 0), errors="coerce").fillna(0).astype(int)

    if non_numeric_found:
        print(f"Cleaned non-numeric/missing values in columns: {non_numeric_found}")

    # Check duplicates and label conflicts
    df_processed = X.copy()
    df_processed["__target__"] = y_raw

    exact_duplicates = int(df_processed.duplicated().sum())
    feature_duplicates = int(df_processed.duplicated(subset=cleaned_features).sum())

    print("\n" + "=" * 60)
    print("STEP 2: PREPROCESSING & DUPLICATE HANDLING")
    print("=" * 60)
    print(f"Exact Duplicate Rows:    {exact_duplicates}")
    print(f"Feature Duplicate Rows:  {feature_duplicates}")

    if not keep_duplicates:
        # Check conflicting feature rows (ambiguous samples with both B and S labels)
        label_variance = df_processed.groupby(cleaned_features)["__target__"].transform("nunique")
        conflict_count = int((label_variance > 1).sum())
        print(f"Conflicting Label Rows:  {conflict_count}")
        if conflict_count > 0:
            df_processed = df_processed[label_variance == 1]
            print(f"Removed ambiguous conflicting rows (same features, contradictory labels).")

        # Drop exact duplicate rows to strictly prevent data leakage across train/test splits
        df_processed = df_processed.drop_duplicates(subset=cleaned_features)
        print(f"Deduplicated feature vectors to prevent train/test data leakage.")
    else:
        print("Note: Keeping duplicate rows as requested (--keep-duplicates).")

    X_final = df_processed[cleaned_features].copy()
    y_final = df_processed["__target__"].copy()

    final_class_counts = y_final.value_counts().to_dict()
    benign_count = final_class_counts.get(0, 0)
    malware_count = final_class_counts.get(1, 0)

    print(f"Final Samples for Model: {len(X_final)}")
    print(f"  - Benign (0):          {benign_count} ({benign_count / len(X_final) * 100:.2f}%)")
    print(f"  - Malware (1):         {malware_count} ({malware_count / len(X_final) * 100:.2f}%)")
    print(f"Final Features:          {len(cleaned_features)}")

    dataset_summary = {
        "dataset_path": dataset_path,
        "raw_samples": raw_sample_count,
        "raw_features": raw_feature_count,
        "raw_distribution": raw_class_counts,
        "preprocessed_samples": len(X_final),
        "preprocessed_features": len(cleaned_features),
        "preprocessed_distribution": {
            "benign_0": benign_count,
            "malware_1": malware_count,
        },
        "deduplicated": not keep_duplicates,
        "label_mapping": label_map,
    }

    return X_final, y_final, cleaned_features, dataset_summary


def train_and_evaluate(
    X: pd.DataFrame,
    y: pd.Series,
    feature_names: list,
    n_estimators: int = 200,
    random_state: int = 42,
) -> Tuple[RandomForestClassifier, Dict[str, Any], pd.DataFrame]:
    """
    Splits data 80/20 stratified, trains RandomForestClassifier,
    calculates Accuracy, Precision, Recall, F1, Confusion Matrix, FPR, FNR,
    and calculates feature importances.
    """
    print("\n" + "=" * 60)
    print("STEP 3: STRATIFIED TRAIN/TEST SPLIT & MODEL TRAINING")
    print("=" * 60)

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.20,
        random_state=random_state,
        stratify=y,
    )

    print(f"Train set: {len(X_train)} samples (Benign: {(y_train == 0).sum()}, Malware: {(y_train == 1).sum()})")
    print(f"Test set:  {len(X_test)} samples (Benign: {(y_test == 0).sum()}, Malware: {(y_test == 1).sum()})")

    # Train Random Forest Classifier
    rf = RandomForestClassifier(
        n_estimators=n_estimators,
        random_state=random_state,
        n_jobs=-1,
        class_weight="balanced",
    )

    print(f"\nTraining RandomForestClassifier(n_estimators={n_estimators}, random_state={random_state}, class_weight='balanced')...")
    rf.fit(X_train, y_train)
    print("Training completed successfully.")

    # Predictions & Probabilities on unobserved Test set
    y_pred = rf.predict(X_test)
    y_prob = rf.predict_proba(X_test)[:, 1]

    # Metrics
    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred)
    rec = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    roc_auc = roc_auc_score(y_test, y_prob)

    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel()

    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0

    print("\n" + "=" * 60)
    print("STEP 4: EVALUATION METRICS (ACTUAL TEST RESULTS)")
    print("=" * 60)
    print(f"Accuracy:                {acc:.4f} ({acc * 100:.2f}%)")
    print(f"Precision:               {prec:.4f} ({prec * 100:.2f}%)")
    print(f"Recall (Sensitivity):    {rec:.4f} ({rec * 100:.2f}%)")
    print(f"F1-Score:                {f1:.4f} ({f1 * 100:.2f}%)")
    print(f"ROC-AUC:                 {roc_auc:.4f}")
    print(f"False Positive Rate:     {fpr:.4f} ({fpr * 100:.2f}%)")
    print(f"False Negative Rate:     {fnr:.4f} ({fnr * 100:.2f}%)")
    print("\nConfusion Matrix:")
    print(f"  True Negatives (TN):   {tn}")
    print(f"  False Positives (FP):  {fp}")
    print(f"  False Negatives (FN):  {fn}")
    print(f"  True Positives (TP):   {tp}")

    metrics_dict = {
        "accuracy": round(float(acc), 4),
        "precision": round(float(prec), 4),
        "recall": round(float(rec), 4),
        "f1_score": round(float(f1), 4),
        "roc_auc": round(float(roc_auc), 4),
        "false_positive_rate": round(float(fpr), 4),
        "false_negative_rate": round(float(fnr), 4),
        "confusion_matrix": {
            "true_negatives": int(tn),
            "false_positives": int(fp),
            "false_negatives": int(fn),
            "true_positives": int(tp),
        },
        "train_samples": len(X_train),
        "test_samples": len(X_test),
        "hyperparameters": {
            "n_estimators": n_estimators,
            "random_state": random_state,
            "class_weight": "balanced",
            "n_jobs": -1,
        },
    }

    # Feature Importance
    importances = rf.feature_importances_
    fi_df = pd.DataFrame({
        "feature": feature_names,
        "importance": importances,
    }).sort_values(by="importance", ascending=False).reset_index(drop=True)
    fi_df["rank"] = fi_df.index + 1

    print("\n" + "=" * 60)
    print("STEP 5: TOP 15 IMPORTANT STATIC FEATURES")
    print("=" * 60)
    for idx, row in fi_df.head(15).iterrows():
        print(f"  {row['rank']:2d}. {row['feature']:<38} : {row['importance']:.5f}")

    return rf, metrics_dict, fi_df


def save_artifacts(
    rf: RandomForestClassifier,
    feature_names: list,
    metrics: Dict[str, Any],
    dataset_summary: Dict[str, Any],
    fi_df: pd.DataFrame,
    output_dir: str,
):
    """
    Saves the trained model, feature order JSON, feature importance rankings (JSON, CSV, PNG),
    and training evaluation summary.
    """
    os.makedirs(output_dir, exist_ok=True)

    model_path = os.path.join(output_dir, "static_malware_random_forest.pkl")
    features_path = os.path.join(output_dir, "static_feature_names.json")
    importance_json_path = os.path.join(output_dir, "feature_importance.json")
    importance_csv_path = os.path.join(output_dir, "feature_importance.csv")
    importance_plot_path = os.path.join(output_dir, "feature_importance.png")
    metrics_path = os.path.join(output_dir, "evaluation_metrics.json")

    print("\n" + "=" * 60)
    print("STEP 6: SAVING ARTIFACTS")
    print("=" * 60)

    # 1. Save Trained Model
    joblib.dump(rf, model_path)
    print(f"Saved trained model to:           {model_path}")

    # 2. Save Feature Names and Order
    with open(features_path, "w", encoding="utf-8") as f:
        json.dump(feature_names, f, indent=2)
    print(f"Saved feature names and order to: {features_path}")

    # 3. Save Feature Importance Data
    fi_records = fi_df.to_dict(orient="records")
    with open(importance_json_path, "w", encoding="utf-8") as f:
        json.dump(fi_records, f, indent=2)
    fi_df.to_csv(importance_csv_path, index=False)
    print(f"Saved feature importance list to: {importance_json_path} & {importance_csv_path}")

    # 4. Save Feature Importance Plot
    plt.figure(figsize=(10, 8))
    top_20 = fi_df.head(20).copy()
    sns.barplot(data=top_20, x="importance", y="feature", hue="feature", palette="viridis", legend=False)
    plt.title("Top 20 Static APK Threat Features (Random Forest Importance)", fontsize=13, fontweight="bold")
    plt.xlabel("Gini Feature Importance", fontsize=11)
    plt.ylabel("Static Feature (Permissions, APIs, Intents)", fontsize=11)
    plt.tight_layout()
    plt.savefig(importance_plot_path, dpi=300)
    plt.close()
    print(f"Saved feature importance plot to: {importance_plot_path}")

    # 5. Save Evaluation Metrics & Summary
    full_metrics = {
        "dataset_summary": dataset_summary,
        "evaluation_metrics": metrics,
        "top_10_features": fi_records[:10],
    }
    with open(metrics_path, "w", encoding="utf-8") as f:
        json.dump(full_metrics, f, indent=2)
    print(f"Saved evaluation metrics to:      {metrics_path}")
    print("=" * 60)
    print("TRAINING AND ARTIFACT PERSISTENCE COMPLETE!")
    print("=" * 60)


def main():
    args = parse_args()
    X, y, feature_names, dataset_summary = load_and_preprocess_dataset(
        args.dataset, keep_duplicates=args.keep_duplicates
    )
    rf, metrics, fi_df = train_and_evaluate(
        X,
        y,
        feature_names,
        n_estimators=args.n_estimators,
        random_state=args.random_state,
    )
    save_artifacts(
        rf,
        feature_names,
        metrics,
        dataset_summary,
        fi_df,
        args.output_dir,
    )


if __name__ == "__main__":
    main()
