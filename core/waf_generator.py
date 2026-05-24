import json
import re
from datetime import datetime
from pathlib import Path
from urllib.parse import unquote_to_bytes

import config

HTTP_METHODS = {"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"}
_HEADER_RE = re.compile(r"^[A-Za-z][A-Za-z0-9\-]+:\s")
_URL_PATH_RE = re.compile(r"^(?:https?://[^/]+)?(/.*)$")


def _sanitize_rx_for_modsecurity(pattern):
    if not pattern or not str(pattern).strip():
        return "."
    s = str(pattern)
    while s:
        tail = len(s) - 1
        n = 0
        while tail >= 0 and s[tail] == "\\":
            n += 1
            tail -= 1
        if n % 2 == 0:
            return s if s else "."
        s = s[:-1]
    return "."


def _escape_pattern_for_seclang_rx_quotes(pc_regex):
    return pc_regex.replace('"', '\\"')


def _validate_pc_regex(pc_regex):
    try:
        re.compile(pc_regex)
    except re.error:
        return False
    return True


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


def _classify_msu(msu, method):
    if msu in HTTP_METHODS:
        return None
    if msu.startswith("http://") or msu.startswith("https://") or msu.startswith("/"):
        return "REQUEST_FILENAME"
    if _HEADER_RE.match(msu):
        return "REQUEST_HEADERS"
    if "=" in msu:
        return "ARGS_POST" if method == "POST" else "ARGS_GET"
    return None


def _extract_payload(msu, variable, decoded_params=None):
    if variable in ("ARGS_GET", "ARGS_POST") and "=" in msu:
        key, val = msu.split("=", 1)
        decoded_key = f"{key.strip()}_decode"
        if decoded_params and decoded_key in decoded_params:
            return decoded_params[decoded_key]
        return _iterative_smart_unquote(val)
    if variable == "REQUEST_HEADERS" and ": " in msu:
        return _iterative_smart_unquote(msu.split(": ", 1)[1])
    if variable == "REQUEST_FILENAME":
        m = _URL_PATH_RE.match(msu)
        if m:
            return _iterative_smart_unquote(m.group(1))
    return _iterative_smart_unquote(msu)


def extract_malicious_payloads(results):
    entries = []
    for req in results:
        prediction = req.get("prediction", {})
        msu_list = req.get("msu_list", [])
        decoded_params = req.get("decoded_params", {})
        method = msu_list[0] if msu_list else "GET"
        for msu, label in prediction.items():
            if label != 1:
                continue
            variable = _classify_msu(msu, method)
            if variable is None:
                continue
            payload = _extract_payload(msu, variable, decoded_params)
            if payload:
                entries.append({"payload": payload, "variable": variable})
    return entries


def edit_distance(a, b):
    m, n = len(a), len(b)
    dp = list(range(n + 1))
    for i in range(1, m + 1):
        prev = dp[0]
        dp[0] = i
        for j in range(1, n + 1):
            temp = dp[j]
            dp[j] = prev if a[i - 1] == b[j - 1] else 1 + min(prev, dp[j], dp[j - 1])
            prev = temp
    return dp[n]


def lcs_two(a, b):
    m, n = len(a), len(b)
    dp = [[0] * (n + 1) for _ in range(m + 1)]
    for i in range(1, m + 1):
        for j in range(1, n + 1):
            if a[i - 1] == b[j - 1]:
                dp[i][j] = dp[i - 1][j - 1] + 1
            else:
                dp[i][j] = max(dp[i - 1][j], dp[i][j - 1])
    result = []
    i, j = m, n
    while i > 0 and j > 0:
        if a[i - 1] == b[j - 1]:
            result.append(a[i - 1])
            i -= 1
            j -= 1
        elif dp[i - 1][j] >= dp[i][j - 1]:
            i -= 1
        else:
            j -= 1
    return "".join(reversed(result))


def lcs_multiple(strings):
    if not strings:
        return ""
    strings = sorted(strings, key=len)
    result = strings[0]
    for s in strings[1:]:
        result = lcs_two(result, s)
        if not result:
            break
    return result


def build_regex(lcs, all_payloads):
    if not lcs:
        return None

    segments = []
    current_segment = lcs[0]
    break_chars = {"'", '"', "(", ")", ";", "=", ",", "<", ">", "-", "/"}

    for i in range(1, len(lcs)):
        is_contiguous = True
        target_sub = current_segment + lcs[i]
        if lcs[i - 1] in break_chars or lcs[i] in break_chars:
            is_contiguous = False
        else:
            for payload in all_payloads:
                if target_sub not in payload:
                    is_contiguous = False
                    break
        if is_contiguous:
            current_segment += lcs[i]
        else:
            segments.append(current_segment)
            current_segment = lcs[i]

    segments.append(current_segment)
    escaped_segments = [re.escape(seg) for seg in segments if seg]
    regex_str = ".*".join(escaped_segments) if escaped_segments else None
    if regex_str:
        regex_str = re.sub(r"[^\x00-\x7F]", ".", regex_str)
    return regex_str


def _find_representative(members):
    if len(members) == 1:
        return members[0]
    best_avg = None
    best_rep = members[0]
    for candidate in members:
        others = [m for m in members if m != candidate]
        avg = sum(edit_distance(candidate, o) for o in others) / len(others)
        if best_avg is None or avg < best_avg:
            best_avg = avg
            best_rep = candidate
    return best_rep


def hierarchical_cluster(payloads, merge_threshold=None):
    if merge_threshold is None:
        merge_threshold = config.MERGE_THRESHOLD
    groups = [{"members": [p], "rep": p} for p in payloads]

    while True:
        n = len(groups)
        if n <= 1:
            break

        best_dist = None
        best_i = best_j = -1

        for i in range(n):
            for j in range(i + 1, n):
                rep_i, rep_j = groups[i]["rep"], groups[j]["rep"]
                d = edit_distance(rep_i, rep_j)
                threshold = merge_threshold * (len(rep_i) + len(rep_j))
                if d <= threshold:
                    if best_dist is None or d < best_dist:
                        best_dist = d
                        best_i, best_j = i, j

        if best_i == -1:
            break

        merged = groups[best_i]["members"] + groups[best_j]["members"]
        new_rep = _find_representative(merged)
        groups = [g for k, g in enumerate(groups) if k not in (best_i, best_j)]
        groups.append({"members": merged, "rep": new_rep})

    return groups


def generate_rules(results, rule_id_start=None):
    if rule_id_start is None:
        rule_id_start = config.RULE_ID_START

    entries = extract_malicious_payloads(results)
    if not entries:
        return []

    by_variable = {}
    for e in entries:
        by_variable.setdefault(e["variable"], []).append(e["payload"])

    rules = []
    rule_id = rule_id_start

    for variable, payloads in sorted(by_variable.items()):
        if config.NORMALIZE_LOWERCASE:
            payloads = [p.strip().lower() for p in payloads]
        else:
            payloads = [p.strip() for p in payloads]
        unique_payloads = list(dict.fromkeys(payloads))
        clusters = hierarchical_cluster(unique_payloads)

        for cluster in clusters:
            members = [m.strip() for m in cluster["members"]]
            lcs = lcs_multiple(members)
            regex = build_regex(lcs, members)
            if not regex:
                regex = re.escape(cluster["rep"])
            regex = _sanitize_rx_for_modsecurity(regex)
            if not _validate_pc_regex(regex):
                regex = "."
            rules.append(
                {
                    "id": rule_id,
                    "variable": variable,
                    "regex": regex,
                    "lcs": lcs,
                    "cluster_size": len(members),
                    "members": members,
                }
            )
            rule_id += 1

    return rules


def format_seclang(rule):
    parts = ["t:none"]
    parts += ["t:urlDecodeUni"] * config.WAF_URL_DECODE_TRANSFORMS
    if config.NORMALIZE_LOWERCASE:
        parts.append("t:lowercase")
    if config.NORMALIZE_WHITESPACE:
        parts.append("t:compressWhitespace")
    transforms = ",".join(parts)
    action = (
        f"id:{rule['id']},phase:2,deny,status:403,log,{transforms},"
        f"msg:'Auto-generated WAF rule (cluster_size={rule['cluster_size']})'"
    )
    regex = _sanitize_rx_for_modsecurity(rule["regex"])
    if regex.endswith("\\") and not regex.endswith("\\\\"):
        regex += "\\"
    if not _validate_pc_regex(regex):
        regex = "."
    regex = _escape_pattern_for_seclang_rx_quotes(regex)
    return f'SecRule {rule["variable"]} "@rx {regex}" "{action}"'


def find_latest_result(result_dir=None):
    result_dir = Path(result_dir or config.LLM_RESULTS_DIR)
    if not result_dir.exists():
        return None
    candidates = [
        f for f in result_dir.iterdir()
        if f.name.startswith("llm_predicted_results_") and f.suffix == ".json"
    ]
    if not candidates:
        return None
    return str(max(candidates, key=lambda p: p.name))


def run_rule_generation(input_file=None, output_dir=None):
    if input_file is None:
        input_file = find_latest_result()
        if input_file is None:
            print(f"[Error] 在 {config.LLM_RESULTS_DIR} 中未找到任何结果文件")
            return {"conf_path": None, "json_path": None, "rule_count": 0}
        print(f"[Info] 使用最新结果文件: {input_file}")

    input_file = Path(input_file)
    output_dir = Path(output_dir or config.WAF_RULES_DIR)

    if not input_file.exists():
        print(f"[Error] 找不到文件: {input_file}")
        return {"conf_path": None, "json_path": None, "rule_count": 0}

    with open(input_file, "r", encoding="utf-8") as f:
        results = json.load(f)

    print(f"[Info] 已加载 {len(results)} 条预测结果，开始生成 WAF 规则...")
    rules = generate_rules(results)

    if not rules:
        print("[Warning] 未提取到任何恶意载荷，无规则生成。")
        return {"conf_path": None, "json_path": None, "rule_count": 0}

    output_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_conf = output_dir / f"waf_rules_{stamp}.conf"
    output_json = output_dir / f"waf_rules_{stamp}.json"

    with open(output_conf, "w", encoding="utf-8") as f:
        f.write("# Auto-generated WAF rules\n")
        f.write(f"# Source : {input_file}\n")
        f.write(f"# Generated: {datetime.now().isoformat()}\n\n")
        for rule in rules:
            f.write(format_seclang(rule) + "\n")

    with open(output_json, "w", encoding="utf-8") as f:
        json.dump(rules, f, indent=2, ensure_ascii=False)

    by_variable_count = {}
    for rule in rules:
        by_variable_count[rule["variable"]] = by_variable_count.get(rule["variable"], 0) + 1

    print(f"\n[Summary] 共生成 {len(rules)} 条规则")
    print("  按变量统计:")
    for variable in sorted(by_variable_count):
        print(f"    {variable}: {by_variable_count[variable]}")
    print(f"\n[Info] 规则已保存至:")
    print(f"  {output_conf}")
    print(f"  {output_json}")

    return {
        "conf_path": str(output_conf),
        "json_path": str(output_json),
        "rule_count": len(rules),
    }
