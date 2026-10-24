from scapy.all import ARP, Ether, srp
import os
import sys

def scan(ip_range):
    print(f"\nEscaneando a rede: {ip_range}")
    print("Aguarde, identificando dispositivos...\n")

    # 1. Criação do pacote ARP (Pergunta: Quem tem este IP?)
    arp_request = ARP(pdst=ip_range)

    # 2. Criação do pacote Ethernet (Envia para o endereço de Broadcast)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")

    # Combina os dois pacotes
    packet = broadcast / arp_request

    # 3. Envio e Recebimento (srp = send and receive packets)
    # timeout=2: espera 2 segundos por resposta
    # verbose=False: esconde as mensagens internas do Scapy
    answered_list = srp(packet, timeout=2, verbose=False)[0]

    # 4. Processamento dos resultados
    devices = []
    for sent, received in answered_list:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    return devices

def print_result(results):
    print("IP" + " " * 18 + "Endereço MAC")
    print("-" * 40)
    for device in results:
        print(f"{device['ip']:16} {device['mac']}")
    print("-" * 40)
    print(f"Total de dispositivos encontrados: {len(results)}\n")

if __name__ == "__main__":
    # Verifica se o usuário passou o IP/Range como argumento no terminal
    if len(sys.argv) > 1:
        target_network = sys.argv[1]
    else:
        # Valor padrão caso você execute apenas 'sudo python3 network_scanner.py'
        target_network = "192.168.1.0/24" 
    
    try:
        scan_results = scan(target_network)
        print_result(scan_results)
    except PermissionError:
        print("Erro: Você precisa executar este script como ROOT (sudo).")
    except Exception as e:
        print(f"Ocorreu um erro: {e}")
