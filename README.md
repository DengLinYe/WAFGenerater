# 恶意载荷定位及自动WAF规则生成

> - 基于论文：Li P, Mei F, Wang Y, et al. Achieving Interpretable DL-based Web Attack Detection through Malicious Payload Localization[J].
> - 包含数据筛选、LLM恶意载荷定位、WAF规则自动生成以及在 Docker 环境下的 WAF 靶场中部署规则并测试的相关代码

## 一、项目结构

```
MaliciousPayloadLocationAndWAFGenerater/
│
├── config.py                          # 全局配置
├── main.py                            # 完整流水线入口
├── waf_controller.py                  # WAF 靶场控制台
├── requirements.txt
│
├── data/                              # 数据处理模块
│   └── data_process.py
│
├── core/                              # 核心业务模块
│   ├── localization.py                # LLM 恶意载荷定位
│   ├── results_analysis.py            # 定位结果评估
│   ├── waf_generator.py               # 聚类 + SecLang 规则生成
│   └── waf_evaluate.py                # WAF 拦截效果评估
│
├── waf_test/                          # WAF 靶场
│   └── deploy.py
│
├── dataset/                           # 原始 HTTP 数据集（需自行放置）
│   └── HTTP_DATASET_CSIC_2010/
│
└── output/                            # 流水线中间产物与结果
    ├── msu/
    ├── llm_results/
    ├── waf_rules/
    └── waf_eval/

```

## 二、环境与运行

1. 根据 `requirements.txt` 部署虚拟环境，并安装配置 `Docker`。
2. 将 CSIC 2010 数据集放入 `dataset/HTTP_DATASET_CSIC_2010/`。
3. 配置 LLM API Key：

   ```
   set DASHSCOPE_API_KEY=your_api_key_here   # Windows CMD
   # $env:DASHSCOPE_API_KEY="your_api_key"   # PowerShell
   ```
4. 运行方式：

     - **完整流水线**：修改 `config.py` 中的参数与 `PIPELINE_STEPS` 开关，然后执行：

       ```
       python main.py
       ```
     - **WAF 靶场管理**（初始化环境、部署规则、启停容器）：
       
       ```bash
       python waf_controller.py
       ```
5. 主要配置项见 `config.py`，包括：

     - `MAX_DATA_COUNT`：每类样本数量上限

     - `ANOMALOUS_FILTER_KEYWORDS`：异常流量关键词筛选

     - `MODEL_NAME`：LLM 模型名称

     - `EVAL_DATA_SOURCE`：WAF 评估数据源（`raw` / `msu_json`）

     - `TOTAL_REQUESTS`：WAF 评估请求总数（raw 模式下每类一半）

     - `PIPELINE_STEPS`：控制 `main.py` 各步骤是否执行
