"""
Captura de paquetes con Scapy: handler general y captura específica de gateway.
"""
import socket
from collections import defaultdict
from datetime import datetime

from scapy.all import sniff, IP, TCP, UDP, ICMP
import sys
import os

ROOT_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..")
)

sys.path.append(ROOT_DIR)
from config.constants import COLORS
from config import COLORS, CAPTURE_DURATION

# ---------------------------------------------------------------------------
# Estado de la captura (inicializado vacío; se reinicia en start_capture)
# ---------------------------------------------------------------------------
capture_stats: dict = {
    "protocols":      defaultdict(int),
    "ports":          defaultdict(int),
    "traffic_by_ip":  defaultdict(lambda: {"sent_bytes": 0, "recv_bytes": 0, "total_bytes": 0}),
    "packet_sizes":   [],
    "start_time":     None,
    "end_time":       None,
    "total_packets":  0,
}

# IP local activa (se inyecta desde network.interfaces al iniciar la captura)
local_ip: str | None = None


def _reset_stats() -> None:
    capture_stats["protocols"].clear()
    capture_stats["ports"].clear()
    capture_stats["traffic_by_ip"].clear()
    capture_stats["packet_sizes"] = []
    capture_stats["total_packets"] = 0
    capture_stats["start_time"] = None
    capture_stats["end_time"] = None


def packet_handler(packet) -> None:
    """Callback de Scapy: actualiza capture_stats por cada paquete recibido."""
    global capture_stats, local_ip

    capture_stats["total_packets"] += 1

    if scapy.all.IP not in packet:
        return

    ip_layer = packet[scapy.all.IP]
    size = len(packet)
    proto_name = "OTHER_IP"
    src_port = dst_port = 0

    if scapy.all.TCP in packet:
        proto_name = "TCP"
        src_port = packet[scapy.all.TCP].sport
        dst_port = packet[scapy.all.TCP].dport
        capture_stats["ports"][dst_port] += 1
        capture_stats["ports"][src_port] += 1
    elif scapy.all.UDP in packet:
        proto_name = "UDP"
        src_port = packet[scapy.all.UDP].sport
        dst_port = packet[scapy.all.UDP].dport
        capture_stats["ports"][dst_port] += 1
        capture_stats["ports"][src_port] += 1
    elif scapy.all.ICMP in packet:
        proto_name = "ICMP"

    capture_stats["protocols"][proto_name] += 1
    capture_stats["packet_sizes"].append(size)

    # Determinar dirección del tráfico
    effective_local = local_ip
    if not effective_local:
        try:
            effective_local = socket.gethostbyname(socket.gethostname())
        except socket.gaierror:
            return

    if ip_layer.src == effective_local:
        capture_stats["traffic_by_ip"][ip_layer.dst]["sent_bytes"] += size
        capture_stats["traffic_by_ip"][ip_layer.dst]["total_bytes"] += size
    elif ip_layer.dst == effective_local:
        capture_stats["traffic_by_ip"][ip_layer.src]["recv_bytes"] += size
        capture_stats["traffic_by_ip"][ip_layer.src]["total_bytes"] += size


def start_capture(interface: str, duration: int = CAPTURE_DURATION, local_ip_addr: str | None = None) -> dict:
    """
    Inicia la captura de tráfico general en la interfaz indicada.
    Devuelve el diccionario capture_stats al finalizar.
    """
    global local_ip
    local_ip = local_ip_addr

    _reset_stats()
    capture_stats["start_time"] = datetime.now().isoformat()

    print(f"{COLORS['cyan']}[*] Iniciando captura en '{interface}' por {duration}s...{COLORS['reset']}")
    try:
        scapy.all.sniff(iface=interface, prn=packet_handler, store=0, timeout=duration)
    except Exception as e:
        print(f"{COLORS['red']}[-] Error durante la captura de paquetes: {e}{COLORS['reset']}")
        print(f"{COLORS['yellow']}[!] Verifique que '{interface}' es correcta y tiene permisos.{COLORS['reset']}")

    capture_stats["end_time"] = datetime.now().isoformat()
    print(
        f"{COLORS['green']}[+] Captura completada. Total de paquetes: {capture_stats['total_packets']}{COLORS['reset']}"
    )
    return dict(capture_stats)


def capture_gateway_packets(gateway_ip: str, interface: str, duration: int = 30) -> list:
    """
    Captura paquetes con filtro BPF hacia/desde el gateway.
    Devuelve lista de paquetes Scapy.
    """
    if not gateway_ip:
        print(f"{COLORS['yellow']}[!] Gateway no disponible. Omitiendo captura.{COLORS['reset']}")
        return []

    print(
        f"{COLORS['cyan']}[*] Capturando paquetes de gateway ({gateway_ip}) "
        f"en '{interface}' por {duration}s...{COLORS['reset']}"
    )
    try:
        packets = scapy.all.sniff(
            iface=interface,
            filter=f"host {gateway_ip}",
            timeout=duration,
            store=1,
        )
        print(
            f"{COLORS['green']}[+] Captura de gateway completada. "
            f"Total: {len(packets)} paquetes.{COLORS['reset']}"
        )
        return list(packets)
    except Exception as e:
        print(f"{COLORS['red']}[-] Error capturando paquetes de gateway: {e}{COLORS['reset']}")
    return []
