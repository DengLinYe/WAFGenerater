import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import config
from core.localization import run_localization
from core.results_analysis import evaluate_localization_results
from core.waf_evaluate import run_waf_evaluation
from core.waf_generator import run_rule_generation
from data.data_process import run_data_process
from waf_test.deploy import deploy_rules, init_environment


def run_pipeline():
    steps = config.PIPELINE_STEPS
    ctx = {}

    print("=" * 60)
    print("  恶意载荷定位及自动 WAF 规则转化 — 完整流水线")
    print("=" * 60)

    if steps.get("data_process", True):
        print("\n>>> [1/6] 数据预处理")
        result = run_data_process()
        ctx["msu_path"] = result.get("output_path")
        if not ctx["msu_path"]:
            print("[Error] 数据预处理失败，流水线终止。")
            return ctx

    if steps.get("llm_localization", True):
        print("\n>>> [2/6] LLM 恶意载荷定位")
        if not config.DASHSCOPE_API_KEY:
            print("[Error] 未设置 DASHSCOPE_API_KEY 环境变量，流水线终止。")
            return ctx
        result = run_localization(dataset_path=ctx.get("msu_path"))
        ctx["llm_result_path"] = result.get("output_path")
        if not ctx["llm_result_path"]:
            print("[Error] LLM 定位失败，流水线终止。")
            return ctx

    if steps.get("results_analysis", True):
        print("\n>>> [3/6] 定位结果评估")
        llm_path = ctx.get("llm_result_path")
        if llm_path:
            evaluate_localization_results(llm_path)
        else:
            print("[Warning] 跳过：无 LLM 结果文件。")

    if steps.get("rule_generation", True):
        print("\n>>> [4/6] WAF 规则生成")
        result = run_rule_generation(input_file=ctx.get("llm_result_path"))
        ctx["rule_conf_path"] = result.get("conf_path")
        if not ctx["rule_conf_path"]:
            print("[Error] 规则生成失败，流水线终止。")
            return ctx

    if steps.get("rule_deploy", True):
        print("\n>>> [5/6] 规则部署到 WAF 靶场")
        init_environment()
        deployed = deploy_rules(rule_file_path=ctx.get("rule_conf_path"))
        ctx["deployed"] = deployed
        if not deployed:
            print("[Warning] 规则部署失败，仍将尝试 WAF 评估（若靶机已在运行）。")

    if steps.get("waf_evaluation", True):
        print("\n>>> [6/6] WAF 拦截效果评估")
        result = run_waf_evaluation()
        ctx["waf_eval_path"] = result.get("output_path")

    print("\n" + "=" * 60)
    print("  流水线执行完毕")
    print("=" * 60)
    return ctx


if __name__ == "__main__":
    run_pipeline()
