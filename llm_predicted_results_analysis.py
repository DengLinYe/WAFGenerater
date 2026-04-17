import json
import os


def evaluate_results(result_file):
    if not os.path.exists(result_file):
        print("Error: File not found.")
        return

    with open(result_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    TP = 0
    TN = 0
    FP = 0
    FN = 0

    for req in data:
        is_actually_malicious = req["type"] == "anomalous"

        prediction_dict = req.get("prediction", {})
        if prediction_dict == "QUOTA_EXHAUSTED":
            continue

        predicted_malicious = any(val == 1 for val in prediction_dict.values())

        if is_actually_malicious and predicted_malicious:
            TP += 1
        elif not is_actually_malicious and not predicted_malicious:
            TN += 1
        elif not is_actually_malicious and predicted_malicious:
            FP += 1
        elif is_actually_malicious and not predicted_malicious:
            FN += 1

    total = TP + TN + FP + FN
    if total == 0:
        return

    accuracy = (TP + TN) / total
    precision = TP / (TP + FP) if (TP + FP) > 0 else 0
    recall = TP / (TP + FN) if (TP + FN) > 0 else 0

    print(f"Total Processed: {total}")
    print(f"True Positives (TP): {TP}")
    print(f"True Negatives (TN): {TN}")
    print(f"False Positives (FP): {FP}")
    print(f"False Negatives (FN): {FN}")
    print("-" * 20)
    print(f"Accuracy:  {accuracy:.2%}")
    print(f"Precision: {precision:.2%}")
    print(f"Recall:    {recall:.2%}")


if __name__ == "__main__":
    evaluate_results(".\\llm_output\\llm_predicted_results.json")
