import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

from openai import APIError, OpenAI

import config

try:
    from tqdm import tqdm
except ImportError:
    tqdm = None

SYSTEM_PROMPT = """Your primary objective is to act as an expert Web Application Firewall (WAF). Your task is to analyze HTTP request segments to pinpoint malicious payloads and anomalies.
The input JSON object contains `msu_list` (Minimal Semantic Units) and optionally `decoded_params`: a dictionary whose keys follow `<param_name>_decode` and values are decoded parameter payloads for obfuscated inputs (matching the preprocessor output).
Keys in your response must be ONLY the exact strings appearing in `msu_list`; do not emit keys from `decoded_params`. Use decoded values solely to infer whether the corresponding MSU (same parameter in `key=value` form within `msu_list`) should be flagged.
Evaluate each MSU in `msu_list` with a value of 1 (malicious/anomalous) or 0 (benign).
CORE ANALYSIS CRITERIA:
1. Decoded Fields Utilization: When `decoded_params` is present (e.g. `pwd_decode`, `nombre_decode`), use it to detect SQLi/XSS probes hidden by URL-encoding; assign the verdict to the original `key=value` MSU entry in `msu_list`.
2. Suspicious Paths: Flag directory traversal attempts (e.g., `../`) and requests targeting known vulnerable default directories or administrative interfaces (e.g., `/IISSamples/`, `/admin/`, `.bak` files).
3. General Threat Detection: Apply standard WAF security heuristics to identify syntax breakers and payload signatures within the MSUs.
FORMAT REQUIREMENTS:
Return ONLY a valid JSON dictionary. Do NOT wrap the JSON in markdown blocks (e.g., ```json). Do NOT provide any explanations, comments, or introductory text. The output must be strictly parseable by standard JSON libraries."""


def _get_client():
    return OpenAI(
        api_key=config.DASHSCOPE_API_KEY,
        base_url="https://dashscope.aliyuncs.com/compatible-mode/v1",
    )


def build_llm_input(req):
    body = {"msu_list": req["msu_list"]}
    decoded = req.get("decoded_params")
    if decoded:
        body["decoded_params"] = decoded
    return body


def locate_payload_with_llm(llm_input, model_name=None):
    if model_name is None:
        model_name = config.MODEL_NAME
    if isinstance(llm_input, list):
        llm_input = {"msu_list": llm_input}

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {
            "role": "user",
            "content": """Input: ["POST", "/tiendal", "/<marquee loop=1 width=0 onfinish=alert(1)>", "/anadir.jsp", "id=2", "nombre=Iber", "precio=5003", "cantidad=64", "B1=Entrar"]""",
        },
        {
            "role": "assistant",
            "content": """{"POST": 0, "/tiendal": 0, "/<marquee loop=1 width=0 onfinish=alert(1)>": 1, "/anadir.jsp": 0, "id=2": 0, "nombre=Iber": 0, "precio=5003": 0, "cantidad=64": 0, "B1=Entrar": 0}""",
        },
        {
            "role": "user",
            "content": """User Input: {"msu_list": ["GET", "/shop", "pwd=foo%2527"], "decoded_params": {"pwd_decode": "foo'"}}""",
        },
        {
            "role": "assistant",
            "content": """{"GET": 0, "/shop": 0, "pwd=foo%2527": 1}""",
        },
        {
            "role": "user",
            "content": f"User Input: {json.dumps(llm_input, ensure_ascii=False)}",
        },
    ]

    client = _get_client()
    try:
        completion = client.chat.completions.create(
            model=model_name,
            messages=messages,
            response_format={"type": "json_object"},
            stream=False,
        )
        result_text = completion.choices[0].message.content
        return json.loads(result_text)
    except APIError as e:
        error_msg = str(e)
        if "403" in error_msg and "AllocationQuota" in error_msg:
            print("\n[Error] 免费额度已完全耗尽!")
            return "QUOTA_EXHAUSTED"
        print(f"[Error] API 调用失败 (非额度问题): {e}")
        return None
    except Exception as e:
        print(f"[Error] 代码或网络解析异常: {e}")
        return None


def _request_predicted_malicious(prediction_dict):
    if not isinstance(prediction_dict, dict):
        return False
    return any(v == 1 for v in prediction_dict.values())


def _summarize_localization(results):
    tp = tn = fp = fn = 0
    fp_ids = []
    fn_ids = []
    for req in results:
        actually_malicious = req.get("type") == "anomalous"
        pred = req.get("prediction", {})
        predicted_malicious = _request_predicted_malicious(pred)
        if actually_malicious and predicted_malicious:
            tp += 1
        elif not actually_malicious and not predicted_malicious:
            tn += 1
        elif not actually_malicious and predicted_malicious:
            fp += 1
            fp_ids.append(req.get("id"))
        elif actually_malicious and not predicted_malicious:
            fn += 1
            fn_ids.append(req.get("id"))
    total = tp + tn + fp + fn
    accuracy = (tp + tn) / total if total else 0.0
    return {
        "accuracy": accuracy,
        "fp_ids": fp_ids,
        "fn_ids": fn_ids,
        "TP": tp,
        "TN": tn,
        "FP": fp,
        "FN": fn,
        "total": total,
    }


def run_localization(
    dataset_path=None,
    output_dir=None,
    model_name=None,
    max_workers=None,
):
    dataset_path = Path(dataset_path or config.MSU_OUTPUT_PATH)
    output_dir = Path(output_dir or config.LLM_RESULTS_DIR)
    model_name = model_name or config.MODEL_NAME
    max_workers = max_workers or config.LLM_MAX_WORKERS

    if not dataset_path.exists():
        print(f"[Error] 找不到数据文件: {dataset_path}")
        return {"output_path": None, "count": 0}

    output_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = output_dir / f"llm_predicted_results_{stamp}.json"

    with open(dataset_path, "r", encoding="utf-8") as f:
        dataset = json.load(f)

    n_total = len(dataset)
    print(f"[Info] 开始调用 {model_name} 进行恶意载荷定位，共 {n_total} 条")

    results = []
    quota_exhausted = False
    completed = 0
    failed_ids = []
    tqdm_disable = tqdm is None
    total_start_time = time.time()

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_req = {
            executor.submit(
                locate_payload_with_llm, build_llm_input(req), model_name
            ): req
            for req in dataset
        }

        progress = None
        if not tqdm_disable:
            progress = tqdm(
                total=n_total,
                desc="LLM localize",
                unit="req",
                file=sys.stderr,
                dynamic_ncols=True,
                smoothing=0.05,
            )

        for future in as_completed(future_to_req):
            req = future_to_req[future]
            try:
                predicted_json = future.result()
                if predicted_json == "QUOTA_EXHAUSTED":
                    print("[Warning] 额度耗尽，停止提交新任务。", file=sys.stderr)
                    quota_exhausted = True
                    executor.shutdown(wait=False, cancel_futures=True)
                elif predicted_json:
                    req["prediction"] = predicted_json
                    results.append(req)
                else:
                    failed_ids.append(req.get("id"))
            except Exception as exc:
                failed_ids.append(req.get("id"))
                print(f"[Error] ID:{req['id']} 异常: {exc}", file=sys.stderr)

            completed += 1
            elapsed = time.time() - total_start_time
            if tqdm_disable:
                rate = elapsed / completed
                eta_s = rate * max(0, n_total - completed)
                filled = min(40, int(40 * completed / max(1, n_total)))
                bar = "=" * filled + "-" * (40 - filled)
                sys.stderr.write(
                    f"\r[{bar}] {completed}/{n_total} ETA {eta_s:.0f}s "
                )
                sys.stderr.flush()
            elif progress:
                progress.update(1)
                eta_s = (elapsed / completed) * max(0, n_total - completed)
                progress.set_postfix(
                    {"ETA_s": f"{eta_s:.0f}", "elapsed_s": f"{elapsed:.1f}"},
                    refresh=True,
                )

            if quota_exhausted:
                break

        if tqdm_disable:
            sys.stderr.write("\n")
            sys.stderr.flush()
        elif progress:
            progress.close()

    total_wall = time.time() - total_start_time
    avg_each = total_wall / completed if completed else 0.0

    if not results:
        print("\n[Warning] 未获得任何有效结果，文件未保存。")
        print(f"  总耗时: {total_wall:.2f}s  平均每条完成耗时: {avg_each:.2f}s")
        return {"output_path": None, "count": 0, "metrics": None}

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    metrics = _summarize_localization(results)
    print(f"\n[Summary] 成功写入 {len(results)} 条 -> {output_file}")
    print(f"  请求级准确率 (仅成功返回的 {metrics['total']} 条): {metrics['accuracy']:.2%}")
    print(f"  TP={metrics['TP']} TN={metrics['TN']} FP={metrics['FP']} FN={metrics['FN']}")
    print(f"  误报 (正常判恶) ID: {metrics['fp_ids']}")
    print(f"  漏报 (异常未判恶) ID: {metrics['fn_ids']}")
    print(f"  总耗时: {total_wall:.2f}s  平均每条完成耗时: {avg_each:.2f}s")
    if failed_ids:
        print(f"  [Note] API/解析失败 {len(failed_ids)} 条，未计入上表。")
        print(f"  失败 ID: {failed_ids}")
    if quota_exhausted:
        print("[Warning] 额度已耗尽，请更换 API Key 后处理未完成数据。", file=sys.stderr)

    return {
        "output_path": str(output_file),
        "count": len(results),
        "metrics": metrics,
    }
