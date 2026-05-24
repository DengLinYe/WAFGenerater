from waf_test.deploy import deploy_rules, init_environment, stop_waf_test


def display_menu():
    print("\n" + "=" * 40)
    print("      WAF 测试靶机控制台")
    print("=" * 40)
    print("1. 初始化测试环境 (生成 Dockerfile/YML/配置)")
    print("2. 部署最新生成的 WAF 规则并重启靶机")
    print("3. 手动输入规则路径并部署")
    print("4. 停止并清理 WAF 靶机")
    print("0. 退出")
    print("=" * 40)


def main():
    while True:
        display_menu()
        choice = input("请选择操作 [0-4]: ").strip()

        if choice == "1":
            init_environment()
        elif choice == "2":
            deploy_rules()
        elif choice == "3":
            custom_path = input("请输入 .conf 规则文件的绝对或相对路径: ").strip()
            deploy_rules(custom_path)
        elif choice == "4":
            stop_waf_test()
        elif choice == "0":
            print("退出控制台。")
            break
        else:
            print("无效输入，请重新选择。")


if __name__ == "__main__":
    main()
