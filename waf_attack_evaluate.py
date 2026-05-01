import json
import os
import random
from datetime import datetime
from urllib.parse import urlsplit

import requests

TOTAL_REQUESTS = 1000
MAX_PER_CLASS = TOTAL_REQUESTS // 2
RANDOM_SEED = 42
TIMEOUT_SECONDS = 8
WAF_BASE_URL = "http://localhost:8080"
NORMAL_FILE = ".\\data\\HTTP_DATASET_CSIC_2010\\normalTrafficTest.txt"
ANOMALOUS_FILE = ".\\data\\HTTP_DATASET_CSIC_2010\\anomalousTrafficTest.txt"
OUTPUT_DIR = ".\\output\\waf_eval"

def split_http_requests(filename):
    if not os.path.exists(filename):
        return []
    with open(filename, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()
    requests_raw = []
    current = []
    for line in lines:
        if line.startswith(("GET ", "POST ", "PUT ", "DELETE ", "PATCH ", "HEAD ", "OPTIONS ")):
            if current:
                requests_raw.append("".join(current))
            current = [line]
        else:
            current.append(line)
    if current:
        requests_raw.append("".join(current))
    return requests_raw

def parse_raw_request(raw_request):
    lines = raw_request.splitlines()
    if not lines:
        return None
    request_line = lines[0].strip().split()
    if len(request_line) < 2:
        return None
    method = request_line[0].upper()
    raw_target = request_line[1]
    parsed = urlsplit(raw_target)
    target = parsed.path or "/"
    if parsed.query:
        target = f"{target}?{parsed.query}"
    headers = {}
    body_lines = []
    in_body = False
    for line in lines[1:]:
        if not in_body:
            if line.strip() == "":
                in_body = True
                continue
            if ":" in line:
                k, v = line.split(":", 1)
                key = k.strip()
                if key.lower() not in {"host", "content-length"}:
                    headers[key] = v.strip()
        else:
            body_lines.append(line)
    body = "\n".join(body_lines) if body_lines else None
    return {"method": method, "target": target, "headers": headers, "body": body}

def build_samples(filename, label, max_count):
    raw_requests = split_http_requests(filename)
    parsed_samples = []
    for idx, raw in enumerate(raw_requests):
        parsed = parse_raw_request(raw)
        if not parsed:
            continue
        parsed_samples.append(
            {
                "id": f"CSIC_{label}_{idx}",
                "type": label,
                "request": parsed,
            }
        )
    random.shuffle(parsed_samples)
    return parsed_samples[:max_count]

def send_to_waf(sample, session):
    req = sample["request"]
    url = f"{WAF_BASE_URL}{req['target']}"

    headers = req.get("headers", {})
    if req["method"] == "POST" and req["body"]:
        if "Content-Type" not in headers:
            headers["Content-Type"] = "application/x-www-form-urlencoded"

    try:
        req_obj = requests.Request(
            method=req["method"],
            url=url,
            headers=req["headers"],
            data=req["body"],
        )
        prepared = req_obj.prepare()
        prepared.url = url
        
        response = session.send(prepared, timeout=TIMEOUT_SECONDS)
        blocked = response.status_code == 403
        return {
            "status_code": response.status_code,
            "predicted_malicious": blocked,
            "error": None,
        }
    except Exception as e:
        return {
            "status_code": None,
            "predicted_malicious": False,
            "error": str(e),
        }

def evaluate(records):
    tp = tn = fp = fn = 0
    fail_count = 0
    for r in records:
        if r["error"] is not None:
            fail_count += 1
            continue
        actual_malicious = r["type"] == "anomalous"
        predicted_malicious = r["predicted_malicious"]
        if actual_malicious and predicted_malicious:
            tp += 1
        elif not actual_malicious and not predicted_malicious:
            tn += 1
        elif not actual_malicious and predicted_malicious:
            fp += 1
        else:
            fn += 1
    total = tp + tn + fp + fn
    accuracy = (tp + tn) / total if total else 0.0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    return {
        "total_processed": total,
        "failed_requests": fail_count,
        "TP": tp,
        "TN": tn,
        "FP": fp,
        "FN": fn,
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
    }

def main():
    random.seed(RANDOM_SEED)
    normal_samples = build_samples(NORMAL_FILE, "normal", MAX_PER_CLASS)
    anomalous_samples = build_samples(ANOMALOUS_FILE, "anomalous", MAX_PER_CLASS)
    dataset = normal_samples + anomalous_samples
    random.shuffle(dataset)

    if not dataset:
        print("[Error] 没有可用样本，请检查 data 路径。")
        return

    print(f"[Info] 样本总数: {len(dataset)} (normal={len(normal_samples)}, anomalous={len(anomalous_samples)})")
    print(f"[Info] 目标WAF: {WAF_BASE_URL}")

    records = []
    with requests.Session() as session:
        for i, sample in enumerate(dataset, start=1):
            result = send_to_waf(sample, session)
            records.append(
                {
                    "id": sample["id"],
                    "type": sample["type"],
                    "method": sample["request"]["method"],
                    "target": sample["request"]["target"],
                    "status_code": result["status_code"],
                    "predicted_malicious": result["predicted_malicious"],
                    "error": result["error"],
                }
            )
            if i % 50 == 0 or i == len(dataset):
                print(f"[Progress] {i}/{len(dataset)}")

    metrics = evaluate(records)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    output_path = os.path.join(OUTPUT_DIR, f"waf_eval_{stamp}.json")
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump({"config": {
            "TOTAL_REQUESTS": TOTAL_REQUESTS,
            "MAX_PER_CLASS": MAX_PER_CLASS,
            "RANDOM_SEED": RANDOM_SEED,
            "WAF_BASE_URL": WAF_BASE_URL,
            "TIMEOUT_SECONDS": TIMEOUT_SECONDS,
        }, "metrics": metrics, "records": records}, f, indent=2, ensure_ascii=False)

    print("\n[Summary]")
    print(f"Total Processed: {metrics['total_processed']}")
    print(f"Failed Requests: {metrics['failed_requests']}")
    print(f"True Positives (TP): {metrics['TP']}")
    print(f"True Negatives (TN): {metrics['TN']}")
    print(f"False Positives (FP): {metrics['FP']}")
    print(f"False Negatives (FN): {metrics['FN']}")
    print("-" * 20)
    print(f"Accuracy:  {metrics['accuracy']:.2%}")
    print(f"Precision: {metrics['precision']:.2%}")
    print(f"Recall:    {metrics['recall']:.2%}")
    print(f"[Info] 结果文件: {output_path}")

if __name__ == "__main__":
    main()