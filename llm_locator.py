import json
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from openai import APIError, OpenAI

API_KEY = os.getenv("DASHSCOPE_API_KEY")
MODEL_NAME = "qwen-plus"

SYSTEM_PROMPT = """Your task is to locate malicious payloads in an HTTP request.
The HTTP request will be divided into minimal semantic units (MSUs), and the input is an array of strings, where each string represents an MSU of the HTTP request.
The output should be a dictionary in JSON format, where the key is a string from the input array, and the value is 0 or 1. A value of 0 indicates that the unit does not contain malicious payloads, and a value of 1 means otherwise.
Please return ONLY the JSON dictionary, without any markdown formatting or explanations."""

client = OpenAI(
    api_key=API_KEY,
    base_url="https://dashscope.aliyuncs.com/compatible-mode/v1",
)


def locate_payload_with_llm(msu_list):
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
            "content": f"User Input: {json.dumps(msu_list, ensure_ascii=False)}",
        },
    ]

    try:
        completion = client.chat.completions.create(
            model=MODEL_NAME,
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
        else:
            print(f"[Error] API 调用失败 (非额度问题): {e}")
            return None
    except Exception as e:
        print(f"[Error] 代码或网络解析异常: {e}")
        return None


if __name__ == "__main__":
    input_file = ".\\msu\\csic_msu_data.json"
    output_file = ".\\llm_output\\llm_predicted_results.json"

    if not os.path.exists(input_file):
        print(f"[Error] 找不到数据文件: {input_file}")
        exit()

    with open(input_file, "r", encoding="utf-8") as f:
        dataset = json.load(f)

    print(f"[Info] 开始调用 {MODEL_NAME} 进行恶意载荷定位...")
    print(f"[Info] 共计需处理请求数量: {len(dataset)}\n")

    results = []
    quota_exhausted = False

    total_start_time = time.time()

    with ThreadPoolExecutor(max_workers=5) as executor:
        future_to_req = {
            executor.submit(locate_payload_with_llm, req["msu_list"]): req
            for req in dataset
        }

        for future in as_completed(future_to_req):
            req = future_to_req[future]
            try:
                predicted_json = future.result()

                if predicted_json == "QUOTA_EXHAUSTED":
                    print("[Warning] 额度耗尽，停止提交新任务。")
                    quota_exhausted = True
                    executor.shutdown(wait=False, cancel_futures=True)
                    break

                if predicted_json:
                    req["prediction"] = predicted_json
                    results.append(req)
                    malicious_items = [k for k, v in predicted_json.items() if v == 1]
                    if malicious_items:
                        print(
                            f"    [Info] ID:{req['id']} 识别到恶意参数: {malicious_items}"
                        )
                    else:
                        print(f"    [Info] ID:{req['id']} 未检测到异常载荷。")
                else:
                    print(f"    [Info] ID:{req['id']} 预测失败。")

            except Exception as exc:
                print(f"    [Error] ID:{req['id']} 产生异常: {exc}")

    total_end_time = time.time()

    if results:
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        print(f"\n[Info] 任务结束。成功生成 {len(results)} 条结果。")
        print(f"[Info] 总耗时: {total_end_time - total_start_time:.2f} 秒！")
        print(f"[Info] 数据已保存至: {output_file}")
        if quota_exhausted:
            print("[Warning] 额度已耗尽，请更换 API Key 后继续处理剩余数据。")
    else:
        print("\n[Warning] 未获得任何有效结果，文件未保存。")
