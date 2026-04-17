import json
import os


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


def process_csic_robust(filename, label):
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
    juicy_keywords = [
        "union",
        "select",
        "script",
        "alert",
        "or ",
        "and ",
        "drop",
        "passwd",
        "%27",
        "%22",
        "1=1",
        "<",
        ">",
    ]

    for idx, req_str in enumerate(requests):
        req_str = req_str.strip()
        if not req_str:
            continue

        if label == "anomalous":
            req_lower = req_str.lower()
            if not any(k in req_lower for k in juicy_keywords):
                continue

        msu_array = parse_http_to_msu(req_str)
        if not msu_array:
            continue

        processed_data.append(
            {"id": f"CSIC_{label}_{idx}", "type": label, "msu_list": msu_array}
        )

        if len(processed_data) >= 50:
            break

    return processed_data


if __name__ == "__main__":
    normal_file = ".\\HTTP_DATASET_CSIC_2010\\normalTrafficTest.txt"
    anomalous_file = ".\\HTTP_DATASET_CSIC_2010\\anomalousTrafficTest.txt"
    output_file = ".\\msu\\csic_msu_data.json"

    normal_data = process_csic_robust(normal_file, "normal")
    anomalous_data = process_csic_robust(anomalous_file, "anomalous")

    final_data = normal_data + anomalous_data

    if final_data:
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(final_data, f, indent=2, ensure_ascii=False)
