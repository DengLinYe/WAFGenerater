# 恶意载荷定位及自动WAF规则转化

> - 基于论文：Li P, Mei F, Wang Y, et al. Achieving Interpretable DL-based Web Attack Detection through Malicious Payload Localization[J].
> - 包含数据筛选、LLM恶意载荷定位、WAF规则自动生成以及在Dockers环境下的WAF靶场中部署规则并测试的相关代码

## 一、项目结构

```
MaliciousPayloadLocationAndWAFGenerater/
│
├── README.md                          # 项目简介
├── requirements.txt                   # Python 依赖（openai、requests 等）
├── .gitignore
│
├── data_process.py                    # [1] 数据预处理：HTTP → MSU JSON
├── llm_locator.py                     # [2] LLM 恶意载荷定位（通义 qwen-plus）
├── llm_predicted_results_analysis.py  # [3] 定位结果评估（TP/TN/FP/FN）
├── waf_generator.py                   # [4] 聚类 + SecLang 规则生成
├── waf_attack_evaluate.py             # [5] 向 WAF 靶机发请求，评估拦截效果
└── waf_test/                          # 本地 WAF 靶场（Coraza + Caddy）
    └── waf_controller.py              # 控制台：初始化 Docker、部署规则、启停靶机
```



## 二、环境与运行

1. 根据`requirements.txt`部署虚拟环境即可，此外还需要安装配置 `Docker`

2. 一般流程：

   1. 进入虚拟环境

   2. 执行`data_process.py`，可以通过设置以下四个核心配置变量从而实现不同的筛选逻辑：

      ```python
      MAX_DATA_COUNT = 500	# 筛选的数据量（这是常规和异常单类流量的数量，总量将乘以2）
      OUTPUT_PATH = ".\\output\\msu\\csic_msu_data_max.json"	# 保存的路径
      MAX_URL_DECODE_ROUNDS = 16	# 解码轮次上限，不建议修改
      # ANOMALOUS_FILTER_KEYWORDS = (
      #     "union", "select", "script", "alert", "or ", "and ", "drop",
      #     "passwd", "%27", "%22", "1=1", "<", ">", "%3e", "%3c",
      # )
      ANOMALOUS_FILTER_KEYWORDS = ()	# 筛选关键词配置
      ```

   3. 执行`llm_locator.py`以调用大模型进行定位，需要自行配置阿里云百炼平台的`API_KEY`：

      ```python
      API_KEY = os.getenv("DASHSCOPE_API_KEY")
      MODEL_NAME = "qwen-plus"	# 模型选择
      DATASET_PATH = ".\\output\\msu\\csic_msu_data_max.json"	# 读取的数据文件
      ```

   4. 执行`waf_generator.py`以生成`SecLang` 规则；

   5. 执行`waf_controller.py`配置并管理`Docker`容器；

   6. 执行`waf_attack_evaluate.py`并测试，以下变量可修改配置：

      ```python
      EVAL_DATA_SOURCE = "raw"	# 测试类型标识，这里是原始数据测试
      MSU_JSON_DIR = ".\\output\\msu"	# 定位文件目录
      MSU_JSON_FILE = "csic_msu_data_max.json"	# 定位文件名称
      
      TOTAL_REQUESTS = 1000	# 总的测试请求数量
      MAX_PER_CLASS = TOTAL_REQUESTS // 2	# 每一种（正常、异常）流量的数量
      RANDOM_SEED = 42	# 随机种子
      TIMEOUT_SECONDS = 8	# 超时时间
      WAF_BASE_URL = "http://localhost:8080"	# 本地靶机开放地址
      NORMAL_FILE = ".\\data\\HTTP_DATASET_CSIC_2010\\normalTrafficTest.txt"	# 正常流量数据文件
      ANOMALOUS_FILE = ".\\data\\HTTP_DATASET_CSIC_2010\\anomalousTrafficTest.txt"	# 异常流量数据文件
      OUTPUT_DIR = ".\\output\\waf_eval"	# 报告输出文件
      
      ANOMALOUS_FILTER_KEYWORDS = ()	# 筛选配置
      # ANOMALOUS_FILTER_KEYWORDS = (
      #     "union", "select", "script", "alert", "or ", "and ", "drop",
      #     "passwd", "%27", "%22", "1=1", "<", ">", "%3e", "%3c",
      # )
      ```

      
