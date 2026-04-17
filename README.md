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