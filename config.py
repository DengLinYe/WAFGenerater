import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent

# ---------------------------------------------------------------------------
# 数据集路径（原始 HTTP 流量，目录名为 dataset）
# ---------------------------------------------------------------------------
DATASET_DIR = PROJECT_ROOT / "dataset" / "HTTP_DATASET_CSIC_2010"
NORMAL_FILE = DATASET_DIR / "normalTrafficTest.txt"
ANOMALOUS_FILE = DATASET_DIR / "anomalousTrafficTest.txt"

# ---------------------------------------------------------------------------
# 输出目录
# ---------------------------------------------------------------------------
OUTPUT_DIR = PROJECT_ROOT / "output"
MSU_OUTPUT_DIR = OUTPUT_DIR / "msu"
MSU_OUTPUT_PATH = MSU_OUTPUT_DIR / "csic_msu_data_max.json"
LLM_RESULTS_DIR = OUTPUT_DIR / "llm_results"
WAF_RULES_DIR = OUTPUT_DIR / "waf_rules"
WAF_EVAL_DIR = OUTPUT_DIR / "waf_eval"

# ---------------------------------------------------------------------------
# 数据预处理
# ---------------------------------------------------------------------------
MAX_DATA_COUNT = 500
MAX_URL_DECODE_ROUNDS = 16
ANOMALOUS_FILTER_KEYWORDS = ()
# ANOMALOUS_FILTER_KEYWORDS = (
#     "union", "select", "script", "alert", "or ", "and ", "drop",
#     "passwd", "%27", "%22", "1=1", "<", ">", "%3e", "%3c",
# )

# ---------------------------------------------------------------------------
# LLM 恶意载荷定位
# ---------------------------------------------------------------------------
DASHSCOPE_API_KEY = os.getenv("DASHSCOPE_API_KEY")
MODEL_NAME = "qwen-plus"
LLM_MAX_WORKERS = 10

# ---------------------------------------------------------------------------
# WAF 规则生成
# ---------------------------------------------------------------------------
MERGE_THRESHOLD = 0.25
RULE_ID_START = 9000000
WAF_URL_DECODE_TRANSFORMS = 4
NORMALIZE_LOWERCASE = True
NORMALIZE_WHITESPACE = True

# ---------------------------------------------------------------------------
# WAF 靶场
# ---------------------------------------------------------------------------
WAF_TEST_DIR = PROJECT_ROOT / "waf_test"
WAF_BASE_URL = "http://localhost:8080"
WAF_PORT = 8080

# ---------------------------------------------------------------------------
# WAF 拦截评估
# ---------------------------------------------------------------------------
EVAL_DATA_SOURCE = "raw"
MSU_JSON_FILE = "csic_msu_data_max.json"
TOTAL_REQUESTS = 1000
RANDOM_SEED = 42
TIMEOUT_SECONDS = 8

# ---------------------------------------------------------------------------
# 主流水线步骤开关
# ---------------------------------------------------------------------------
PIPELINE_STEPS = {
    "data_process": True,
    "llm_localization": True,
    "results_analysis": True,
    "rule_generation": True,
    "rule_deploy": True,
    "waf_evaluation": True,
}
