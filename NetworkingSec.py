import socket
import struct
import textwrap
from scapy.all import sniff, IP, TCP, UDP, ICMP
from scapy.layers.inet import Ether
from collections import defaultdict, deque
import subprocess
from concurrent.futures import ThreadPoolExecutor
import time

local_ip = "192.168.0.106"
# ----------------------------------
# Функція для перехоплення мережевого трафіку
# ----------------------------------
def analyze_packet(packet):
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        # Ігноруємо пакети, які приходять або відправляються моїм IP
        if src_ip == local_ip or dst_ip == local_ip:
            return

        # Виявлення аномалій: надлишкова кількість пакетів
        packet_count[src_ip] += 1
        if packet_count[src_ip] > PACKET_THRESHOLD:
            time.sleep(1)
            print(f"[АЛЕРТ] Підозріла активність: багато пакетів від {src_ip}")

        # Аналіз на сканування портів
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            if tcp_layer.flags == 'S':  # SYN-пакет
                scanned_ports[src_ip].add(tcp_layer.dport)
                if len(scanned_ports[src_ip]) > PORT_SCAN_THRESHOLD:
                    time.sleep(2)
                    print(f"[АЛЕРТ] Виявлено сканування портів з IP {src_ip}")

        # Розширений аналіз: виявлення UDP або ICMP трафіку
        if packet.haslayer(UDP):
            udp_layer = packet[UDP]
            time.sleep(2)
            print(f"[INFO] Виявлено UDP пакет: {src_ip} -> {dst_ip}, порт {udp_layer.dport}")

        if packet.haslayer(ICMP):
            icmp_layer = packet[ICMP]
            time.sleep(0.5)
            print(f"[INFO] Виявлено ICMP пакет: {src_ip} -> {dst_ip}, тип {icmp_layer.type}")

    # Очищення записів для запобігання переповненню пам'яті з FIFO-стратегією
    if len(packet_count) > CACHE_LIMIT:
        oldest_key = packet_count_fifo.popleft()
        del packet_count[oldest_key]
        print(f"[INFO] Досягнуто ліміту кешу. Видалено найстаріший запис для IP {oldest_key}.")

    if len(scanned_ports) > CACHE_LIMIT:
        oldest_key = scanned_ports_fifo.popleft()
        del scanned_ports[oldest_key]
        print(f"[INFO] Досягнуто ліміту кешу. Видалено найстаріший запис для IP {oldest_key}.")

# ----------------------------------
# Перехоплення трафіку
# ----------------------------------
def start_sniffing(interface):
    print(f"Запуск перехоплення на інтерфейсі {interface}...")
    try:
        sniff(iface=interface, prn=analyze_packet, store=False)
    except Exception as e:
        print(f"[ПОМИЛКА] Не вдалося розпочати перехоплення: {e}")

# ----------------------------------
# Автоматичне налаштування брандмауера
# ----------------------------------
def configure_firewall(block_ips=[], allowed_ips=[], restricted_ports=[]):
    for ip in block_ips:
        try:
            subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
            print(f"[Брандмауер] Заблоковано IP {ip}")
        except subprocess.CalledProcessError as e:
            print(f"[ПОМИЛКА] Не вдалося заблокувати IP {ip}: {e}")

    for ip in allowed_ips:
        try:
            subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "ACCEPT"], check=True)
            print(f"[Брандмауер] Дозволено трафік з IP {ip}")
        except subprocess.CalledProcessError as e:
            print(f"[ПОМИЛКА] Не вдалося дозволити IP {ip}: {e}")

    for port in restricted_ports:
        try:
            subprocess.run(["iptables", "-A", "INPUT", "-p", "tcp", "--dport", str(port), "-j", "DROP"], check=True)
            print(f"[Брандмауер] Обмежено доступ до порту {port}")
        except subprocess.CalledProcessError as e:
            print(f"[ПОМИЛКА] Не вдалося обмежити порт {port}: {e}")

# ----------------------------------
# Сканування діапазону IP
# ----------------------------------
def scan_host(ip, ports):
    results = []
    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            result = s.connect_ex((ip, port))
            if result == 0:
                try:
                    banner = get_banner(ip, port)
                    results.append(f"[ВІДКРИТО] {ip}:{port} - {banner}")
                except Exception:
                    results.append(f"[ВІДКРИТО] {ip}:{port}")
            else:
                results.append(f"[НЕ ВІДКРИТО] {ip}:{port} - Підключення не вдалося")
    return results

def scan_network(ip_range, ports):
    print(f"Сканування мережі {ip_range} на порти {ports}...")
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(scan_host, ip, ports) for ip in ip_range]
        for future in futures:
            for result in future.result():
                print(result)

# ----------------------------------
# Отримання банера
# ----------------------------------
def get_banner(ip, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((ip, port))
        s.send(b'\n')
        return s.recv(1024).decode().strip()

# ----------------------------------
# Основна програма
# ----------------------------------
if __name__ == "__main__":
    PACKET_THRESHOLD = 100
    PORT_SCAN_THRESHOLD = 10
    CACHE_LIMIT = 1000

    packet_count = defaultdict(int)
    scanned_ports = defaultdict(set)
    packet_count_fifo = deque()
    scanned_ports_fifo = deque()

    while True:
        print("\nВиберіть дію:")
        print("1. Перехоплення мережевого трафіку")
        print("2. Налаштування брандмауера")
        print("3. Сканування мережі")
        print("4. Вихід")

        try:
            choice = input("Ваш вибір: ").strip()
            if choice not in {"1", "2", "3", "4"}:
                raise ValueError("Невірний ввід. Введіть число від 1 до 4.")
        except ValueError as e:
            print(e)
            continue

        if choice == "1":
            while True:
                interface = input("Введіть інтерфейс для перехоплення (наприклад, eth0) або 'exit' для виходу: ").strip()
                if interface.lower() == "exit":
                    break
                if not interface:
                    print("[ПОМИЛКА] Не вказано інтерфейс.")
                    continue
                try:
                    start_sniffing(interface)
                except KeyboardInterrupt:
                    print("Перехоплення завершено.")
                    break

        elif choice == "2":
            while True:
                block_ips = input("Введіть IP для блокування (через дефіс) або 'exit' для виходу: ").strip()
                if block_ips.lower() == "exit":
                    break
                restricted_ports = input("Введіть порти для обмеження (через дефіс) або 'exit' для виходу: ").strip()
                if restricted_ports.lower() == "exit":
                    break
                allowed_ips = input("Введіть IP для дозволу (через дефіс) або 'exit' для виходу: ").strip()
                if allowed_ips.lower() == "exit":
                    break

                try:
                    restricted_ports = list(map(int, restricted_ports.split("-")))
                    configure_firewall(block_ips=block_ips.split("-"), allowed_ips=allowed_ips.split("-"), restricted_ports=restricted_ports)
                except ValueError:
                    print("[ПОМИЛКА] Введено некоректний формат портів.")


        elif choice == "3":
            while True:
                ip_range = input("Введіть діапазон IP для сканування (через дефіс) або 'exit' для виходу: ").strip()
                if ip_range.lower() == "exit":
                    break
                ports = input("Введіть порти для сканування (через дефіс) або 'exit' для виходу: ").strip()

                if ports.lower() == "exit":
                    break
                try:
                    ports = list(map(int, ports.split("-")))
                    scan_network(ip_range.split("-"), ports)
                except ValueError:

                    print("[ПОМИЛКА] Введено некоректний формат портів.")
        elif choice == "4":
            print("Вихід з програми.")
            break
