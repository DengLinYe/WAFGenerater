import json
from pathlib import Path


def evaluate_localization_results(result_file, print_report=True):
    result_file = Path(result_file)
    if not result_file.exists():
        print(f"[Error] 找不到结果文件: {result_file}")
        return None

    with open(result_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    tp = tn = fp = fn = 0
    for req in data:
        is_actually_malicious = req["type"] == "anomalous"
        prediction_dict = req.get("prediction", {})
        if prediction_dict == "QUOTA_EXHAUSTED":
            continue
        predicted_malicious = any(val == 1 for val in prediction_dict.values())

        if is_actually_malicious and predicted_malicious:
            tp += 1
        elif not is_actually_malicious and not predicted_malicious:
            tn += 1
        elif not is_actually_malicious and predicted_malicious:
            fp += 1
        elif is_actually_malicious and not predicted_malicious:
            fn += 1

    total = tp + tn + fp + fn
    if total == 0:
        print("[Warning] 无有效样本可评估。")
        return None

    accuracy = (tp + tn) / total
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0

    metrics = {
        "total_processed": total,
        "TP": tp,
        "TN": tn,
        "FP": fp,
        "FN": fn,
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
    }

    if print_report:
        print(f"Total Processed: {total}")
        print(f"True Positives (TP): {tp}")
        print(f"True Negatives (TN): {tn}")
        print(f"False Positives (FP): {fp}")
        print(f"False Negatives (FN): {fn}")
        print("-" * 20)
        print(f"Accuracy:  {accuracy:.2%}")
        print(f"Precision: {precision:.2%}")
        print(f"Recall:    {recall:.2%}")

    return metrics
