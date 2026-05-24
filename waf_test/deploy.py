import glob
import subprocess
import time
from pathlib import Path

import config

DOCKERFILE_CONTENT = """FROM docker.m.daocloud.io/library/caddy:builder AS builder
ENV GOPROXY=https://mirrors.aliyun.com/goproxy/,direct GOSUMDB=off
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


def _waf_test_dir():
    path = Path(config.WAF_TEST_DIR)
    path.mkdir(parents=True, exist_ok=True)
    return path


def init_environment():
    print("[*] 正在初始化 WAF 测试环境...")
    waf_test_dir = _waf_test_dir()
    compose_path = waf_test_dir / "docker-compose.yml"
    caddy_path = waf_test_dir / "Caddyfile"
    dockerfile_path = waf_test_dir / "Dockerfile"

    if not dockerfile_path.exists():
        dockerfile_path.write_text(DOCKERFILE_CONTENT, encoding="utf-8")
        print("  [+] 创建 Dockerfile 成功")

    if not compose_path.exists():
        compose_path.write_text(DOCKER_COMPOSE_CONTENT, encoding="utf-8")
        print("  [+] 创建 docker-compose.yml 成功")

    if not caddy_path.exists():
        caddy_path.write_text(CADDYFILE_CONTENT, encoding="utf-8")
        print("  [+] 创建 Caddyfile 成功")

    active_rules_path = waf_test_dir / "active_rules.conf"
    if not active_rules_path.exists():
        active_rules_path.write_text("# 初始化空规则文件\n", encoding="utf-8")


def find_latest_rule_file(rules_dir=None):
    rules_dir = Path(rules_dir or config.WAF_RULES_DIR)
    if not rules_dir.exists():
        return None
    list_of_files = glob.glob(str(rules_dir / "*.conf"))
    if not list_of_files:
        return None
    return max(list_of_files, key=lambda p: Path(p).stat().st_ctime)


def deploy_rules(rule_file_path=None, waf_base_url=None, waf_port=None):
    waf_test_dir = _waf_test_dir()
    waf_base_url = waf_base_url or config.WAF_BASE_URL
    waf_port = waf_port if waf_port is not None else config.WAF_PORT

    if not rule_file_path:
        print("[!] 未指定规则文件，尝试查找最新生成的规则...")
        rule_file_path = find_latest_rule_file()
        if not rule_file_path:
            print("[-] 错误：未找到任何规则文件！请先运行规则生成。")
            return False

    rule_file_path = Path(rule_file_path)
    if not rule_file_path.exists():
        print(f"[-] 错误：指定的规则文件不存在：{rule_file_path}")
        return False

    print(f"[*] 准备部署规则: {rule_file_path}")
    active_rules_path = waf_test_dir / "active_rules.conf"
    try:
        content = rule_file_path.read_text(encoding="utf-8")
        active_rules_path.write_text(content, encoding="utf-8")
        print("  [+] 规则文件已替换")
    except Exception as e:
        print(f"[-] 复制规则文件失败: {e}")
        return False

    print("[*] 正在构建并启动 WAF 靶机容器 (首次编译可能需要1-3分钟，请耐心等待)...")
    try:
        subprocess.run(
            ["docker-compose", "down"],
            cwd=waf_test_dir,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        subprocess.run(
            ["docker-compose", "up", "-d", "--build"],
            cwd=waf_test_dir,
            check=True,
        )
        print("  [+] 容器构建及启动成功")

        time.sleep(2)
        import requests

        try:
            res = requests.get(waf_base_url, timeout=3)
            if res.status_code == 200:
                print(f"\n[SUCCESS] WAF 靶机已上线！当前运行端口: {waf_port}")
            else:
                print(f"\n[WARNING] WAF 靶机可能已上线，但返回了异常状态码: {res.status_code}")
        except Exception:
            print(f"\n[WARNING] 无法访问靶机端口 {waf_port}，请检查 Docker 状态。")
        return True
    except Exception as e:
        print(f"[-] 启动容器失败: {e}")
        return False


def stop_waf_test():
    waf_test_dir = _waf_test_dir()
    print("[*] 正在停止并移除容器...")
    subprocess.run(["docker-compose", "down"], cwd=waf_test_dir)
    print("[+] 靶机已清理")
