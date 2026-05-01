import os
import subprocess
import time
import glob

# 配置路径
WAF_TEST_DIR = os.path.dirname(os.path.abspath(__file__))
RULES_DIR = os.path.join(os.path.dirname(WAF_TEST_DIR), "output", "waf_rules")

DOCKERFILE_CONTENT = """FROM docker.m.daocloud.io/library/caddy:builder AS builder
ENV GOPROXY=https://goproxy.cn,direct
RUN xcaddy build --with github.com/corazawaf/coraza-caddy/v2

FROM docker.m.daocloud.io/library/caddy:latest
COPY --from=builder /usr/bin/caddy /usr/bin/caddy
"""

DOCKER_COMPOSE_CONTENT = """services:
  caddy-waf:
    build: .
    container_name: local-waf-target
    ports:
      - "8080:8080"
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile
      - ./active_rules.conf:/etc/caddy/active_rules.conf
    restart: unless-stopped
"""

CADDYFILE_CONTENT = """{
    # 保证 WAF 拦截器在最前排
    order coraza_waf first
}

:8080 {
    coraza_waf {
        directives `
            SecRuleEngine On
            SecRequestBodyAccess On
            
            SecRule REQUEST_HEADERS:Content-Type "application/x-www-form-urlencoded" "id:'200002',phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=URLENCODED"
            
            Include /etc/caddy/active_rules.conf
        `
    }
    respond "Backend response: WAF Passed! No malicious payload detected." 200
}
"""

def init_environment():
    """初始化基础配置文件"""
    print("[*] 正在初始化 WAF 测试环境...")
    compose_path = os.path.join(WAF_TEST_DIR, "docker-compose.yml")
    caddy_path = os.path.join(WAF_TEST_DIR, "Caddyfile")
    dockerfile_path = os.path.join(WAF_TEST_DIR, "Dockerfile")

    if not os.path.exists(dockerfile_path):
        with open(dockerfile_path, "w") as f:
            f.write(DOCKERFILE_CONTENT)
        print("  [+] 创建 Dockerfile 成功")

    if not os.path.exists(compose_path):
        with open(compose_path, "w") as f:
            f.write(DOCKER_COMPOSE_CONTENT)
        print("  [+] 创建 docker-compose.yml 成功")

    if not os.path.exists(caddy_path):
        with open(caddy_path, "w") as f:
            f.write(CADDYFILE_CONTENT)
        print("  [+] 创建 Caddyfile 成功")
        
    active_rules_path = os.path.join(WAF_TEST_DIR, "active_rules.conf")
    if not os.path.exists(active_rules_path):
        with open(active_rules_path, "w") as f:
            f.write("# 初始化空规则文件\n")

def find_latest_rule_file():
    """查找最新生成的规则文件"""
    if not os.path.exists(RULES_DIR):
        return None
    list_of_files = glob.glob(os.path.join(RULES_DIR, "*.conf"))
    if not list_of_files:
        return None
    latest_file = max(list_of_files, key=os.path.getctime)
    return latest_file

def deploy_rules(rule_file_path=None):
    """将指定规则部署到靶机并重启"""
    if not rule_file_path:
        print("[!] 未指定规则文件，尝试查找最新生成的规则...")
        rule_file_path = find_latest_rule_file()
        if not rule_file_path:
            print("[-] 错误：未找到任何规则文件！请先运行生成脚本。")
            return

    if not os.path.exists(rule_file_path):
        print(f"[-] 错误：指定的规则文件不存在：{rule_file_path}")
        return

    print(f"[*] 准备部署规则: {rule_file_path}")
    
    active_rules_path = os.path.join(WAF_TEST_DIR, "active_rules.conf")
    try:
        with open(rule_file_path, 'r', encoding='utf-8') as src:
            content = src.read()
        with open(active_rules_path, 'w', encoding='utf-8') as dst:
            dst.write(content)
        print("  [+] 规则文件已替换")
    except Exception as e:
        print(f"[-] 复制规则文件失败: {e}")
        return

    print("[*] 正在构建并启动 WAF 靶机容器 (首次编译可能需要1-3分钟，请耐心等待)...")
    try:
        subprocess.run(["docker-compose", "down"], cwd=WAF_TEST_DIR, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["docker-compose", "up", "-d", "--build"], cwd=WAF_TEST_DIR, check=True)
        print("  [+] 容器构建及启动成功")
        
        time.sleep(2)
        import requests
        try:
            res = requests.get("http://localhost:8080", timeout=3)
            if res.status_code == 200:
                print("\n[SUCCESS] WAF 靶机已上线！当前运行端口: 8080")
            else:
                print(f"\n[WARNING] WAF 靶机可能已上线，但返回了异常状态码: {res.status_code}")
        except:
             print("\n[WARNING] 无法访问靶机端口 8080，请检查 Docker 状态。")
             
    except Exception as e:
        print(f"[-] 启动容器失败: {e}")

def display_menu():
    print("\n" + "="*40)
    print("      WAF 测试靶机控制台")
    print("="*40)
    print("1. 初始化测试环境 (生成 Dockerfile/YML/配置)")
    print("2. 部署最新生成的 WAF 规则并重启靶机")
    print("3. 手动输入规则路径并部署")
    print("4. 停止并清理 WAF 靶机")
    print("0. 退出")
    print("="*40)

if __name__ == "__main__":
    while True:
        display_menu()
        choice = input("请选择操作 [0-4]: ").strip()
        
        if choice == '1':
            init_environment()
        elif choice == '2':
            deploy_rules()
        elif choice == '3':
            custom_path = input("请输入 .conf 规则文件的绝对或相对路径: ").strip()
            deploy_rules(custom_path)
        elif choice == '4':
            print("[*] 正在停止并移除容器...")
            subprocess.run(["docker-compose", "down"], cwd=WAF_TEST_DIR)
            print("[+] 靶机已清理")
        elif choice == '0':
            print("退出控制台。")
            break
        else:
            print("无效输入，请重新选择。")