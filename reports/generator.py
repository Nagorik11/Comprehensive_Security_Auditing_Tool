"""
Generación de reportes: TXT, CSV (dispositivos, conexiones, servicios)
y JSON (interfaces, estadísticas de captura).
"""
import csv
import json
from datetime import datetime

from config.constants import COLORS, OUTPUT_FILES, SAFE_PORTS


def generate_reports(
    interface_details: dict,
    network_devices: list,
    arp_discovered_devices: list,
    active_conns: list,
    discovered_services: list,
    captured_pkts_stats: dict,
    gateway_pkts_summary: str,
) -> None:
    """Genera todos los archivos de reporte a partir de los datos recolectados."""
    print(f"\n{COLORS['cyan']}[*] Generando reportes...{COLORS['reset']}")

    _write_txt_report(
        interface_details, network_devices, arp_discovered_devices,
        active_conns, discovered_services, captured_pkts_stats, gateway_pkts_summary,
    )
    _write_csv_devices(network_devices)
    _write_csv_connections(active_conns)
    _write_csv_services(discovered_services)
    _write_json_interfaces(interface_details)
    _write_json_capture_stats(captured_pkts_stats)


# ---------------------------------------------------------------------------
# Helpers privados
# ---------------------------------------------------------------------------

def _write_txt_report(interface_details, network_devices, arp_discovered_devices,
                       active_conns, discovered_services, captured_pkts_stats, gateway_pkts_summary):
    path = OUTPUT_FILES["txt"]
    with open(path, "w", encoding="utf-8") as f:
        f.write("REPORTE COMPLETO DE ANÁLISIS DE RED\n")
        f.write(f"Generado el: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 80 + "\n\n")

        # Interfaces
        f.write("CONFIGURACIÓN DE INTERFACES DE RED:\n" + "=" * 80 + "\n")
        if interface_details:
            for name, config in interface_details.items():
                f.write(f"Interfaz: {name}\n")
                f.write(f"  Estado: {config.get('state', 'N/A')}\n")
                f.write(f"  Tipo: {config.get('type', 'N/A').title()}\n")
                f.write(f"  MAC: {config.get('mac', 'N/A')}\n")
                f.write(f"  MTU: {config.get('mtu', 'N/A')}\n")
                f.write(f"  IPv4: {[ip['address']+'/'+str(ip['prefix']) for ip in config.get('ipv4', [])]}\n")
                f.write(f"  IPv6: {[ip['address']+'/'+str(ip['prefix']) for ip in config.get('ipv6', [])]}\n")
                stats = config.get("stats", {})
                if stats:
                    f.write("  Estadísticas (RX/TX):\n")
                    f.write(f"    Paquetes: {stats.get('rx_packets',0)} / {stats.get('tx_packets',0)}\n")
                    f.write(f"    Bytes:    {stats.get('rx_bytes',0)} / {stats.get('tx_bytes',0)}\n")
                    f.write(f"    Errores:  {stats.get('rx_errors',0)} / {stats.get('tx_errors',0)}\n")
                f.write("-" * 40 + "\n")
        else:
            f.write("No se pudo obtener información de las interfaces.\n")

        # Dispositivos ARP cache
        f.write("\nDISPOSITIVOS EN LA RED (Cache ARP/Vecinos):\n" + "=" * 80 + "\n")
        if network_devices:
            for d in network_devices:
                f.write(
                    f"IP: {d['ip']:<15} MAC: {d['mac']:<17} "
                    f"Fabricante: {d.get('manufacturer','N/A'):<25} Estado: {d.get('state','N/A')}\n"
                )
        else:
            f.write("No se encontraron dispositivos en la caché ARP.\n")

        # Dispositivos ARP activo
        f.write("\nDISPOSITIVOS DESCUBIERTOS ACTIVAMENTE (Scapy ARP):\n" + "=" * 80 + "\n")
        if arp_discovered_devices:
            for d in arp_discovered_devices:
                f.write(f"IP: {d['ip']:<15} MAC: {d['mac']:<17} Fabricante: {d.get('manufacturer','N/A')}\n")
        else:
            f.write("No se descubrieron dispositivos activamente.\n")

        # Conexiones activas
        f.write("\nCONEXIONES DE RED ACTIVAS (LOCALES):\n" + "=" * 80 + "\n")
        if active_conns:
            f.write(f"{'Proto':<5} {'Estado':<10} {'IP Local':<20} {'PuertoL':<7} {'IP Remota':<20} {'PuertoR':<7} Proceso\n")
            f.write("-" * 80 + "\n")
            for c in active_conns:
                f.write(
                    f"{c['proto']:<5} {c['state']:<10} {c['local_ip']:<20} "
                    f"{str(c['local_port']):<7} {c['remote_ip']:<20} "
                    f"{str(c['remote_port']):<7} {c.get('process','N/A')}\n"
                )
        else:
            f.write("No se encontraron conexiones activas.\n")

        # Servicios
        f.write("\nSERVICIOS DETECTADOS EN LA RED (Nmap):\n" + "=" * 80 + "\n")
        if discovered_services:
            f.write(f"{'IP Host':<15} {'Puerto':<7} {'Proto':<5} {'Servicio':<20} Producto/Versión\n")
            f.write("-" * 80 + "\n")
            for svc in discovered_services:
                product_info = f"{svc.get('product','')} {svc.get('version','')}".strip()
                f.write(f"{svc['ip']:<15} {str(svc['port']):<7} {svc['protocol']:<5} {svc['service_name']:<20} {product_info}\n")
                if int(svc["port"]) not in SAFE_PORTS and svc["protocol"] == "tcp":
                    f.write(f"  [ALERTA] Puerto abierto no estándar: {svc['port']}/{svc['protocol']} en {svc['ip']}\n")
        else:
            f.write("No se detectaron servicios.\n")

        # Estadísticas de captura
        f.write("\nESTADÍSTICAS DE CAPTURA DE PAQUETES:\n" + "=" * 80 + "\n")
        if captured_pkts_stats and captured_pkts_stats.get("total_packets", 0) > 0:
            f.write(f"Duración: {captured_pkts_stats.get('start_time')} → {captured_pkts_stats.get('end_time')}\n")
            f.write(f"Total paquetes: {captured_pkts_stats['total_packets']}\n\n")
            f.write("Protocolos:\n")
            for proto, count in sorted(captured_pkts_stats["protocols"].items(), key=lambda x: x[1], reverse=True):
                f.write(f"  {proto}: {count}\n")
            f.write("\nPuertos más comunes (top 10):\n")
            for port, count in sorted(captured_pkts_stats["ports"].items(), key=lambda x: x[1], reverse=True)[:10]:
                f.write(f"  Puerto {port}: {count}\n")
            f.write("\nTráfico por IP (top 10 por bytes):\n")
            for ip, data in sorted(captured_pkts_stats["traffic_by_ip"].items(), key=lambda x: x[1]["total_bytes"], reverse=True)[:10]:
                f.write(f"  {ip:<15} | Enviado: {data['sent_bytes']} | Recibido: {data['recv_bytes']} | Total: {data['total_bytes']} bytes\n")
            sizes = captured_pkts_stats.get("packet_sizes", [])
            if sizes:
                f.write(f"\nTamaño promedio: {sum(sizes)/len(sizes):.2f} bytes\n")
                f.write(f"Tamaño mínimo:   {min(sizes)} bytes\n")
                f.write(f"Tamaño máximo:   {max(sizes)} bytes\n")
        else:
            f.write("No se realizó captura de paquetes.\n")

        # Gateway
        f.write("\nPAQUETES DE GATEWAY:\n" + "=" * 80 + "\n")
        f.write(gateway_pkts_summary + "\n")

    print(f"{COLORS['green']}[+] Reporte TXT guardado en: {path}{COLORS['reset']}")


def _write_csv_devices(network_devices):
    if not network_devices:
        return
    path = OUTPUT_FILES["devices_csv"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=network_devices[0].keys())
        writer.writeheader()
        writer.writerows(network_devices)
    print(f"{COLORS['green']}[+] Dispositivos CSV: {path}{COLORS['reset']}")


def _write_csv_connections(active_conns):
    if not active_conns:
        return
    path = OUTPUT_FILES["connections_csv"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=active_conns[0].keys())
        writer.writeheader()
        writer.writerows(active_conns)
    print(f"{COLORS['green']}[+] Conexiones CSV: {path}{COLORS['reset']}")


def _write_csv_services(discovered_services):
    if not discovered_services:
        return
    path = OUTPUT_FILES["services_csv"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=discovered_services[0].keys())
        writer.writeheader()
        writer.writerows(discovered_services)
    print(f"{COLORS['green']}[+] Servicios CSV: {path}{COLORS['reset']}")


def _write_json_interfaces(interface_details):
    if not interface_details:
        return
    path = OUTPUT_FILES["interfaces_json"]
    with open(path, "w", encoding="utf-8") as f:
        json.dump(interface_details, f, indent=2)
    print(f"{COLORS['green']}[+] Interfaces JSON: {path}{COLORS['reset']}")


def _write_json_capture_stats(captured_pkts_stats):
    if not captured_pkts_stats or captured_pkts_stats.get("total_packets", 0) == 0:
        return
    path = OUTPUT_FILES["capture_stats_json"]
    with open(path, "w", encoding="utf-8") as f:
        json.dump(captured_pkts_stats, f, indent=2)
    print(f"{COLORS['green']}[+] Estadísticas captura JSON: {path}{COLORS['reset']}")
