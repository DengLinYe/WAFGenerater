import json
import os
import random
from urllib.parse import unquote_to_bytes

MAX_DATA_COUNT = 500
OUTPUT_PATH = ".\\output\\msu\\csic_msu_data_max.json"
MAX_URL_DECODE_ROUNDS = 16


# ANOMALOUS_FILTER_KEYWORDS = (
#     "union", "select", "script", "alert", "or ", "and ", "drop",
#     "passwd", "%27", "%22", "1=1", "<", ">", "%3e", "%3c",
# )
ANOMALOUS_FILTER_KEYWORDS = ()

def _iterative_smart_unquote(value, max_rounds=MAX_URL_DECODE_ROUNDS):
    cur_str = value
    for _ in range(max_rounds):
        raw_bytes = unquote_to_bytes(cur_str.replace('+', ' '))
        
        try:
            nxt_str = raw_bytes.decode('utf-8')
        except UnicodeDecodeError:
            nxt_str = raw_bytes.decode('latin-1')
        
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

def collect_decoded_param_fields(msu_list):
    out = {}
    for msu in msu_list:
        if not _is_kv_param_msu(msu):
            continue
        key, val = msu.split("=", 1)
        key = key.strip()
        
        decoded = _iterative_smart_unquote(val)
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
                queries = query_part.split("&")
                for q in queries:
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
                body_params = line.split("&")
                for p in body_params:
                    if p:
                        msu_list.append(p)
            else:
                msu_list.append(line)

    return msu_list

def process_csic(filename, label):
    if not os.path.exists(filename):
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
    keywords = ANOMALOUS_FILTER_KEYWORDS or ()
    if isinstance(keywords, str):
        keywords = (keywords,)

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

        if len(processed_data) >= MAX_DATA_COUNT:
            break

    return processed_data

if __name__ == "__main__":
    normal_file = ".\\data\\HTTP_DATASET_CSIC_2010\\normalTrafficTest.txt"
    anomalous_file = ".\\data\\HTTP_DATASET_CSIC_2010\\anomalousTrafficTest.txt"

    normal_data = process_csic(normal_file, "normal")
    anomalous_data = process_csic(anomalous_file, "anomalous")

    final_data = normal_data + anomalous_data
    random.shuffle(final_data)

    if final_data:
        with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
            json.dump(final_data, f, indent=2, ensure_ascii=False)