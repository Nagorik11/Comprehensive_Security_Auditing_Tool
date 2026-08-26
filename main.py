"""
Punto de entrada principal del analizador de red.
Orquesta todos los módulos para realizar el análisis completo.
"""
from datetime import datetime

from config.constants import CAPTURE_DURATION, COLORS, OUTPUT_DIR, TIMESTAMP
from utils.shell import check_command_exists, check_root
from utils.oui import ensure_oui_file, load_oui_data
from network.interfaces import get_full_interface_config, select_interface_and_get_network
from network.devices import discover_devices_with_arp, get_default_gateway, get_network_devices
from network.connections import get_active_connections_typed, scan_network_services
from capture.sniffer import capture_gateway_packets, start_capture
from reports.generator import generate_reports
from topology.graph import build_network_graph, save_topology_graph


def main() -> None:
    check_root()
    start_time_script = datetime.now()
    print(f"{COLORS['cyan']}{'='*20} INICIO DEL ANÁLISIS DE RED {'='*20}{COLORS['reset']}")

    # Resultados a recolectar
    interfaces_data              = {}
    network_devices_cache        = []
    arp_discovered_devices_active = []
    active_connections           = []
    discovered_network_services  = []
    gateway_packets_info         = "Captura de gateway no realizada o sin resultados."

    # 0. Verificar y cargar archivo OUI
    if ensure_oui_file():
        load_oui_data()

    # 1. Configuración de interfaces y selección de red
    interfaces_data = get_full_interface_config()
    if not interfaces_data:
        print(f"{COLORS['red']}[-] No se pudo obtener la configuración de interfaces. Saliendo.{COLORS['reset']}")
        exit(1)

    selected_interface_name, selected_ip, network_range_cidr, selected_mac = \
        select_interface_and_get_network(interfaces_data)

    if not selected_interface_name or not network_range_cidr:
        print(f"{COLORS['red']}[-] No se seleccionó una interfaz válida. Saliendo.{COLORS['reset']}")
        exit(1)

    # 2. Detección de dispositivos
    network_devices_cache         = get_network_devices(network_range_cidr, selected_interface_name)
    arp_discovered_devices_active = discover_devices_with_arp(network_range_cidr, selected_interface_name, timeout=10)

    # 3. Análisis de conexiones locales
    active_connections = get_active_connections_typed()

    # 4. Escaneo de servicios en la red (opcional)
    if check_command_exists("nmap"):
        answer = input(
            f"{COLORS['yellow']}[?] ¿Realizar escaneo de servicios en {network_range_cidr}? (s/N): {COLORS['reset']}"
        ).lower()
        if answer == "s":
            discovered_network_services = scan_network_services(network_range_cidr, selected_interface_name)
        else:
            print(f"{COLORS['yellow']}[-] Escaneo de servicios omitido.{COLORS['reset']}")
    else:
        print(f"{COLORS['yellow']}[!] nmap no instalado. Omitiendo escaneo de servicios.{COLORS['reset']}")

    # 5. Captura de tráfico general (opcional)
    answer = input(
        f"{COLORS['yellow']}[?] ¿Capturar tráfico general en '{selected_interface_name}' "
        f"por {CAPTURE_DURATION}s? (s/N): {COLORS['reset']}"
    ).lower()
    capture_result = {}
    if answer == "s":
        capture_result = start_capture(selected_interface_name, CAPTURE_DURATION, selected_ip)
    else:
        print(f"{COLORS['yellow']}[-] Captura de tráfico omitida.{COLORS['reset']}")

    # 6. Captura de paquetes del gateway (opcional)
    default_gw_ip = get_default_gateway()
    if default_gw_ip:
        answer = input(
            f"{COLORS['yellow']}[?] ¿Capturar tráfico del gateway ({default_gw_ip}) "
            f"en '{selected_interface_name}' por 30s? (s/N): {COLORS['reset']}"
        ).lower()
        if answer == "s":
            gw_packets = capture_gateway_packets(default_gw_ip, selected_interface_name, duration=30)
            gateway_packets_info = (
                f"Capturados {len(gw_packets)} paquetes del gateway {default_gw_ip}."
            )
        else:
            gateway_packets_info = f"Captura de gateway ({default_gw_ip}) omitida por el usuario."
    else:
        gateway_packets_info = "No se pudo determinar la gateway para la captura específica."

    # 7. Generar topología de red
    try:
        topo_graph = build_network_graph(
            selected_ip,
            network_devices_cache,
            arp_discovered_devices_active,
            active_connections,
            discovered_network_services,
            capture_result,
        )
        save_topology_graph(topo_graph, OUTPUT_DIR, TIMESTAMP)
    except Exception as e:
        print(f"{COLORS['yellow']}[!] No se pudo generar la topología: {e}{COLORS['reset']}")

    # 8. Generar reportes (TXT, CSV, JSON)
    generate_reports(
        interfaces_data,
        network_devices_cache,
        arp_discovered_devices_active,
        active_connections,
        discovered_network_services,
        capture_result,
        gateway_packets_info,
    )

    # Finalizar
    duration = datetime.now() - start_time_script
    print(f"\n{COLORS['green']}[+] Análisis completo en {duration.total_seconds():.2f}s.{COLORS['reset']}")
    print(f"{COLORS['cyan']}{'='*20} FIN DEL ANÁLISIS DE RED {'='*20}{COLORS['reset']}")


if __name__ == "__main__":
    main()
