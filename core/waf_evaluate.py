import json
import random
import re
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit

import requests

import config

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


def _normalized_anomalous_keywords(filter_keywords=None):
    kw = filter_keywords if filter_keywords is not None else config.ANOMALOUS_FILTER_KEYWORDS
    kw = kw or ()
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


def find_msu_json_file(msu_json_dir=None, msu_json_file=None):
    msu_json_dir = Path(msu_json_dir or config.MSU_OUTPUT_DIR)
    msu_json_file = msu_json_file if msu_json_file is not None else config.MSU_JSON_FILE

    if msu_json_file:
        direct = Path(msu_json_file)
        if direct.is_file():
            return str(direct.resolve())
        joined = msu_json_dir / msu_json_file
        if joined.is_file():
            return str(joined.resolve())
        return None

    if not msu_json_dir.is_dir():
        return None
    candidates = list(msu_json_dir.glob("*.json"))
    if not candidates:
        return None
    return str(max(candidates, key=lambda p: p.stat().st_mtime))


def build_samples_from_msu_json(json_path, filter_keywords=None):
    with open(json_path, "r", encoding="utf-8") as f:
        rows = json.load(f)
    keywords = _normalized_anomalous_keywords(filter_keywords)
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
        item = {"id": row.get("id", ""), "type": typ, "request": parsed}
        if typ == "normal":
            normals.append(item)
        elif typ == "anomalous":
            anoms.append(item)
    random.shuffle(normals)
    random.shuffle(anoms)
    return normals, anoms


def split_http_requests(filename):
    filename = Path(filename)
    if not filename.exists():
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
            merged = "&".join(ln.strip() for ln in body_lines if ln.strip())
            if merged:
                target = _append_to_query_string(target, merged)
        body = None
    else:
        body = "\n".join(body_lines) if body_lines else None
    return {"method": method, "target": target, "headers": headers, "body": body}


def build_samples(filename, label, max_count, filter_keywords=None):
    raw_requests = split_http_requests(filename)
    keywords = _normalized_anomalous_keywords(filter_keywords)
    parsed_samples = []
    for idx, raw in enumerate(raw_requests):
        if label == "anomalous" and keywords:
            if not any(k.lower() in raw.lower() for k in keywords):
                continue
        parsed = parse_raw_request(raw)
        if not parsed:
            continue
        parsed_samples.append(
            {"id": f"CSIC_{label}_{idx}", "type": label, "request": parsed}
        )
    random.shuffle(parsed_samples)
    return parsed_samples[:max_count]


def send_to_waf(sample, session, waf_base_url=None, timeout_seconds=None):
    waf_base_url = waf_base_url or config.WAF_BASE_URL
    timeout_seconds = timeout_seconds if timeout_seconds is not None else config.TIMEOUT_SECONDS
    req = sample["request"]
    url = f"{waf_base_url}{req['target']}"

    headers = dict(req.get("headers") or {})
    method = req["method"]
    if method in _METHODS_NO_REQUEST_BODY:
        for hk in list(headers.keys()):
            if hk.lower() in ("content-type", "content-length"):
                del headers[hk]
        payload = None
    else:
        if method == "POST" and req["body"]:
            if "Content-Type" not in headers:
                headers["Content-Type"] = "application/x-www-form-urlencoded"
        payload = req["body"]

    try:
        req_obj = requests.Request(method=method, url=url, headers=headers, data=payload)
        prepared = req_obj.prepare()
        prepared.url = url
        response = session.send(prepared, timeout=timeout_seconds)
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


def run_waf_evaluation(
    eval_data_source=None,
    normal_file=None,
    anomalous_file=None,
    msu_json_dir=None,
    msu_json_file=None,
    total_requests=None,
    random_seed=None,
    waf_base_url=None,
    timeout_seconds=None,
    output_dir=None,
    filter_keywords=None,
):
    eval_data_source = eval_data_source or config.EVAL_DATA_SOURCE
    normal_file = Path(normal_file or config.NORMAL_FILE)
    anomalous_file = Path(anomalous_file or config.ANOMALOUS_FILE)
    total_requests = total_requests if total_requests is not None else config.TOTAL_REQUESTS
    random_seed = random_seed if random_seed is not None else config.RANDOM_SEED
    waf_base_url = waf_base_url or config.WAF_BASE_URL
    timeout_seconds = timeout_seconds if timeout_seconds is not None else config.TIMEOUT_SECONDS
    output_dir = Path(output_dir or config.WAF_EVAL_DIR)
    max_per_class = total_requests // 2

    random.seed(random_seed)
    filter_keywords = _normalized_anomalous_keywords(filter_keywords)
    msu_json_path = None

    if eval_data_source == "msu_json":
        msu_json_path = find_msu_json_file(msu_json_dir, msu_json_file)
        if not msu_json_path:
            print(
                f"[Error] 未找到 MSU JSON：请检查 MSU_JSON_FILE（当前: {config.MSU_JSON_FILE!r}）、"
                f"目录 {config.MSU_OUTPUT_DIR}，或先运行 data_process。"
            )
            return {"output_path": None, "metrics": None}
        normal_samples, anomalous_samples = build_samples_from_msu_json(
            msu_json_path, filter_keywords
        )
    else:
        normal_samples = build_samples(normal_file, "normal", max_per_class, filter_keywords)
        anomalous_samples = build_samples(
            anomalous_file, "anomalous", max_per_class, filter_keywords
        )

    dataset = normal_samples + anomalous_samples
    random.shuffle(dataset)

    if not dataset:
        print("[Error] 没有可用样本，请检查数据源路径或 JSON 内容。")
        return {"output_path": None, "metrics": None}

    print(f"[Info] 数据源: {eval_data_source}")
    if msu_json_path:
        print(f"[Info] MSU JSON: {msu_json_path}")
        print("[Info] msu_json 模式：使用 JSON 内全部可解析请求")
    elif eval_data_source == "raw":
        print(f"[Info] raw 模式：每类最多 {max_per_class} 条（TOTAL_REQUESTS={total_requests}）")
    print(
        f"[Info] 样本总数: {len(dataset)} "
        f"(normal={len(normal_samples)}, anomalous={len(anomalous_samples)})"
    )
    if filter_keywords:
        print(f"[Info] 已对 anomalous 启用关键词筛选 ({len(filter_keywords)} 条关键词)")
    else:
        print("[Info] 未对 anomalous 做关键词筛选")
    print(f"[Info] 目标WAF: {waf_base_url}")

    records = []
    with requests.Session() as session:
        for i, sample in enumerate(dataset, start=1):
            result = send_to_waf(sample, session, waf_base_url, timeout_seconds)
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
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / f"waf_eval_{stamp}.json"
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(
            {
                "config": {
                    "EVAL_DATA_SOURCE": eval_data_source,
                    "MSU_JSON_FILE_USED": msu_json_path,
                    "TOTAL_REQUESTS": total_requests,
                    "MAX_PER_CLASS": max_per_class,
                    "TOTAL_REQUESTS_scope": (
                        "raw_only" if eval_data_source == "raw" else "unused_in_msu_json_mode"
                    ),
                    "dataset_total": len(dataset),
                    "dataset_normal_count": len(normal_samples),
                    "dataset_anomalous_count": len(anomalous_samples),
                    "RANDOM_SEED": random_seed,
                    "WAF_BASE_URL": waf_base_url,
                    "TIMEOUT_SECONDS": timeout_seconds,
                    "ANOMALOUS_FILTER_KEYWORDS": list(filter_keywords),
                    "anomalous_keyword_filter_enabled": bool(filter_keywords),
                },
                "metrics": metrics,
                "records": records,
            },
            f,
            indent=2,
            ensure_ascii=False,
        )

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

    return {"output_path": str(output_path), "metrics": metrics}
