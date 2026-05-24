import json
import random
from pathlib import Path
from urllib.parse import unquote_to_bytes

import config


def _iterative_smart_unquote(value, max_rounds=None):
    if max_rounds is None:
        max_rounds = config.MAX_URL_DECODE_ROUNDS
    cur_str = value
    for _ in range(max_rounds):
        raw_bytes = unquote_to_bytes(cur_str.replace("+", " "))
        try:
            nxt_str = raw_bytes.decode("utf-8")
        except UnicodeDecodeError:
            nxt_str = raw_bytes.decode("latin-1")
        if nxt_str == cur_str:
            break
        cur_str = nxt_str
    return cur_str


def _is_kv_param_msu(msu):
    if "=" not in msu:
        return False
    key, _val = msu.split("=", 1)
    key = key.strip()
    return bool(key) and (":" not in key)


def collect_decoded_param_fields(msu_list, max_rounds=None):
    out = {}
    for msu in msu_list:
        if not _is_kv_param_msu(msu):
            continue
        key, val = msu.split("=", 1)
        key = key.strip()
        decoded = _iterative_smart_unquote(val, max_rounds)
        if decoded != val:
            out[f"{key}_decode"] = decoded
    return out


def parse_http_to_msu(raw_request):
    msu_list = []
    lines = raw_request.strip().split("\n")
    if not lines:
        return msu_list

    request_line = lines[0].strip().split()
    if len(request_line) >= 2:
        msu_list.append(request_line[0])
        url_str = request_line[1]
        if "?" in url_str:
            path_part, query_part = url_str.split("?", 1)
            msu_list.append(path_part)
            if query_part:
                for q in query_part.split("&"):
                    if q:
                        msu_list.append(q)
        else:
            msu_list.append(url_str)

    is_body = False
    for line in lines[1:]:
        line = line.strip()
        if not is_body:
            if not line:
                is_body = True
            else:
                msu_list.append(line)
        else:
            if not line:
                continue
            if "&" in line and "=" in line:
                for p in line.split("&"):
                    if p:
                        msu_list.append(p)
            else:
                msu_list.append(line)

    return msu_list


def process_csic(filename, label, max_count=None, filter_keywords=None):
    filename = Path(filename)
    max_count = max_count if max_count is not None else config.MAX_DATA_COUNT
    keywords = filter_keywords if filter_keywords is not None else config.ANOMALOUS_FILTER_KEYWORDS
    keywords = keywords or ()
    if isinstance(keywords, str):
        keywords = (keywords,)

    if not filename.exists():
        return []

    with open(filename, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()

    requests = []
    current_req = []
    for line in lines:
        if line.startswith(("GET ", "POST ", "PUT ", "DELETE ")):
            if current_req:
                requests.append("".join(current_req))
            current_req = [line]
        else:
            current_req.append(line)
    if current_req:
        requests.append("".join(current_req))

    processed_data = []
    for idx, req_str in enumerate(requests):
        req_str = req_str.strip()
        if not req_str:
            continue

        if label == "anomalous" and keywords:
            req_lower = req_str.lower()
            if not any(k.lower() in req_lower for k in keywords):
                continue

        msu_array = parse_http_to_msu(req_str)
        if not msu_array:
            continue

        row = {"id": f"CSIC_{label}_{idx}", "type": label, "msu_list": msu_array}
        decoded_fields = collect_decoded_param_fields(msu_array)
        if decoded_fields:
            row["decoded_params"] = decoded_fields
        processed_data.append(row)

        if len(processed_data) >= max_count:
            break

    return processed_data


def run_data_process(
    normal_file=None,
    anomalous_file=None,
    output_path=None,
    max_count=None,
    filter_keywords=None,
):
    normal_file = Path(normal_file or config.NORMAL_FILE)
    anomalous_file = Path(anomalous_file or config.ANOMALOUS_FILE)
    output_path = Path(output_path or config.MSU_OUTPUT_PATH)

    normal_data = process_csic(normal_file, "normal", max_count, filter_keywords)
    anomalous_data = process_csic(anomalous_file, "anomalous", max_count, filter_keywords)

    final_data = normal_data + anomalous_data
    random.shuffle(final_data)

    if not final_data:
        print("[Warning] 未生成任何 MSU 数据，请检查 dataset 路径。")
        return {"output_path": None, "count": 0}

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(final_data, f, indent=2, ensure_ascii=False)

    print(f"[Summary] 已写入 {len(final_data)} 条 MSU 数据 -> {output_path}")
    print(f"  normal={len(normal_data)}  anomalous={len(anomalous_data)}")
    return {"output_path": str(output_path), "count": len(final_data)}
