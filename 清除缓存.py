#本脚本为ECMcamera项目的配套工具，具体介绍见"食用指南.txt"
import subprocess
import os
import re

def delete_firewall_rules():
    # 获取所有防火墙规则
    process = subprocess.Popen('netsh advfirewall firewall show rule name=all', stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    output, error = process.communicate()

    if not error:
        rules = output.decode('latin-1').splitlines()
        for rule in rules:
            # 使用正则表达式匹配包含特定模式的规则名称
            match = re.search(r"Block.*(?:Inbound|Outbound|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", rule)
            if match:
                rule_name = match.group(0)
                subprocess.run(f'netsh advfirewall firewall delete rule name="{rule_name}"', shell=True)

def delete_files():
    files_to_delete = ["ip.txt", "ip2.txt", "target.txt"]
    for file in files_to_delete:
        try:
            os.remove(file)
        except FileNotFoundError:
            pass  # 如果文件不存在则忽略

def delete_task(task_name):
    try:
        # 删除计划任务
        subprocess.run(f'schtasks /Delete /TN "{task_name}" /F', shell=True, check=True)
        print(f"Task '{task_name}' deleted successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Error deleting task '{task_name}': {e}")

if __name__ == "__main__":
    print("Deleting firewall rules...")
    delete_firewall_rules()
    print("Firewall rules deleted.")

    print("\nDeleting files...")
    delete_files()
    print("Files deleted.")

    task_name = "ECMcameraStartup"
    print(f"\nDeleting task '{task_name}'...")
    delete_task(task_name)
