import json
import os
import random
import re
from datetime import datetime
from urllib.parse import urlsplit

import requests

EVAL_DATA_SOURCE = "raw"
MSU_JSON_DIR = ".\\output\\msu"
MSU_JSON_FILE = "csic_msu_data_max.json"

TOTAL_REQUESTS = 1000
MAX_PER_CLASS = TOTAL_REQUESTS // 2
RANDOM_SEED = 42
TIMEOUT_SECONDS = 8
WAF_BASE_URL = "http://localhost:8080"
NORMAL_FILE = ".\\data\\HTTP_DATASET_CSIC_2010\\normalTrafficTest.txt"
ANOMALOUS_FILE = ".\\data\\HTTP_DATASET_CSIC_2010\\anomalousTrafficTest.txt"
OUTPUT_DIR = ".\\output\\waf_eval"

ANOMALOUS_FILTER_KEYWORDS = ()
# ANOMALOUS_FILTER_KEYWORDS = (
#     "union", "select", "script", "alert", "or ", "and ", "drop",
#     "passwd", "%27", "%22", "1=1", "<", ">", "%3e", "%3c",
# )

_METHODS_NO_REQUEST_BODY = frozenset({"GET", "HEAD", "OPTIONS", "TRACE"})

_HEADER_MSU_RE = re.compile(r"^[A-Za-z][A-Za-z0-9\-]+:\s")


def _append_to_query_string(target, extra):
    if not extra:
        return target
    extra = extra.strip()
    if not extra:
        return target
    if "?" in target:
        return f"{target}&{extra}"
    return f"{target}?{extra}"


def _normalized_anomalous_keywords():
    kw = ANOMALOUS_FILTER_KEYWORDS or ()
    if isinstance(kw, str):
        kw = (kw,)
    return kw


def _is_kv_param_msu(msu):
    if "=" not in msu:
        return False
    key, _val = msu.split("=", 1)
    key = key.strip()
    return bool(key) and (":" not in key)


def _target_path_and_query_for_local(target):
    if target.startswith(("http://", "https://")):
        p = urlsplit(target)
        path = p.path or "/"
        if p.query:
            return f"{path}?{p.query}"
        return path
    return target


def msu_list_to_request(msu_list):
    if not msu_list or len(msu_list) < 2:
        return None
    method = msu_list[0].upper()
    path_seg = msu_list[1]
    i = 2
    query_parts = []
    while i < len(msu_list) and _is_kv_param_msu(msu_list[i]) and not _HEADER_MSU_RE.match(
        msu_list[i]
    ):
        query_parts.append(msu_list[i])
        i += 1
    if query_parts:
        target = f"{path_seg}?{'&'.join(query_parts)}"
    else:
        target = path_seg
    target = _target_path_and_query_for_local(target)

    headers = {}
    while i < len(msu_list) and _HEADER_MSU_RE.match(msu_list[i]):
        line = msu_list[i]
        k, _, v = line.partition(": ")
        key = k.strip()
        if key.lower() not in {"host", "content-length"}:
            headers[key] = v.strip()
        i += 1

    body_parts = msu_list[i:]
    if method in _METHODS_NO_REQUEST_BODY:
        if body_parts:
            target = _append_to_query_string(target, "&".join(body_parts))
        body = None
    elif body_parts:
        body = "&".join(body_parts)
    else:
        body = None

    return {"method": method, "target": target, "headers": headers, "body": body}


def find_msu_json_file():
    if MSU_JSON_FILE:
        if os.path.isfile(MSU_JSON_FILE):
            return os.path.abspath(MSU_JSON_FILE)
        joined = os.path.join(MSU_JSON_DIR, MSU_JSON_FILE)
        if os.path.isfile(joined):
            return os.path.abspath(joined)
        return None
    if not os.path.isdir(MSU_JSON_DIR):
        return None
    candidates = [
        os.path.join(MSU_JSON_DIR, f)
        for f in os.listdir(MSU_JSON_DIR)
        if f.endswith(".json")
    ]
    if not candidates:
        return None
    return max(candidates, key=os.path.getmtime)


def build_samples_from_msu_json(json_path):
    with open(json_path, "r", encoding="utf-8") as f:
        rows = json.load(f)
    keywords = _normalized_anomalous_keywords()
    normals = []
    anoms = []
    for row in rows:
        typ = row.get("type")
        msu_list = row.get("msu_list") or []
        if not msu_list:
            continue
        if typ == "anomalous" and keywords:
            blob = "\n".join(msu_list).lower()
            if not any(k.lower() in blob for k in keywords):
                continue
        parsed = msu_list_to_request(msu_list)
        if not parsed:
            continue
        item = {
            "id": row.get("id", ""),
            "type": typ,
            "request": parsed,
        }
        if typ == "normal":
            normals.append(item)
        elif typ == "anomalous":
            anoms.append(item)
    random.shuffle(normals)
    random.shuffle(anoms)
    return normals, anoms


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
    if method in _METHODS_NO_REQUEST_BODY:
        if body_lines:
            merged = "&".join(
                ln.strip() for ln in body_lines if ln.strip()
            )
            if merged:
                target = _append_to_query_string(target, merged)
        body = None
    else:
        body = "\n".join(body_lines) if body_lines else None
    return {"method": method, "target": target, "headers": headers, "body": body}

def build_samples(filename, label, max_count):
    raw_requests = split_http_requests(filename)
    keywords = _normalized_anomalous_keywords()
    parsed_samples = []
    for idx, raw in enumerate(raw_requests):
        if label == "anomalous" and keywords:
            if not any(k.lower() in raw.lower() for k in keywords):
                continue
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

    headers = dict(req.get("headers") or {})
    method = req["method"]
    if method in _METHODS_NO_REQUEST_BODY:
        for _hk in list(headers.keys()):
            if _hk.lower() in ("content-type", "content-length"):
                del headers[_hk]
        payload = None
    else:
        if method == "POST" and req["body"]:
            if "Content-Type" not in headers:
                headers["Content-Type"] = "application/x-www-form-urlencoded"
        payload = req["body"]

    try:
        req_obj = requests.Request(
            method=method,
            url=url,
            headers=headers,
            data=payload,
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
    filter_keywords = _normalized_anomalous_keywords()
    msu_json_path = None

    if EVAL_DATA_SOURCE == "msu_json":
        msu_json_path = find_msu_json_file()
        if not msu_json_path:
            print(
                f"[Error] 未找到 MSU JSON：请检查 MSU_JSON_FILE（当前: {MSU_JSON_FILE!r}）、"
                f"目录 {MSU_JSON_DIR}，或先运行 data_process。"
            )
            return
        normal_samples, anomalous_samples = build_samples_from_msu_json(msu_json_path)
    else:
        normal_samples = build_samples(NORMAL_FILE, "normal", MAX_PER_CLASS)
        anomalous_samples = build_samples(ANOMALOUS_FILE, "anomalous", MAX_PER_CLASS)

    dataset = normal_samples + anomalous_samples
    random.shuffle(dataset)

    if not dataset:
        print("[Error] 没有可用样本，请检查数据源路径或 JSON 内容。")
        return

    print(f"[Info] 数据源: {EVAL_DATA_SOURCE}")
    if msu_json_path:
        print(f"[Info] MSU JSON: {msu_json_path}")
        print("[Info] msu_json 模式：使用 JSON 内全部可解析请求")
    elif EVAL_DATA_SOURCE == "raw":
        print(
            f"[Info] raw 模式：每类最多 {MAX_PER_CLASS} 条（TOTAL_REQUESTS={TOTAL_REQUESTS}）"
        )
    print(f"[Info] 样本总数: {len(dataset)} (normal={len(normal_samples)}, anomalous={len(anomalous_samples)})")
    if filter_keywords:
        print(f"[Info] 已对 anomalous 启用关键词筛选 ({len(filter_keywords)} 条关键词)")
    else:
        print("[Info] 未对 anomalous 做关键词筛选")
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
            "EVAL_DATA_SOURCE": EVAL_DATA_SOURCE,
            "MSU_JSON_FILE_USED": msu_json_path,
            "TOTAL_REQUESTS": TOTAL_REQUESTS,
            "MAX_PER_CLASS": MAX_PER_CLASS,
            "TOTAL_REQUESTS_scope": (
                "raw_only"
                if EVAL_DATA_SOURCE == "raw"
                else "unused_in_msu_json_mode"
            ),
            "dataset_total": len(dataset),
            "dataset_normal_count": len(normal_samples),
            "dataset_anomalous_count": len(anomalous_samples),
            "RANDOM_SEED": RANDOM_SEED,
            "WAF_BASE_URL": WAF_BASE_URL,
            "TIMEOUT_SECONDS": TIMEOUT_SECONDS,
            "ANOMALOUS_FILTER_KEYWORDS": list(filter_keywords),
            "anomalous_keyword_filter_enabled": bool(filter_keywords),
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