"""
Gestión de interfaces de red: obtención de configuración y selección interactiva.
"""
import ipaddress
import json
import os

from config.constants import COLORS
from utils.shell import run_cmd

# IP local seleccionada (usada por el módulo de captura)
local_ip_address_for_capture: str | None = None


def get_full_interface_config() -> dict:
    """
    Devuelve un diccionario con la configuración completa de todas las interfaces,
    incluyendo IPs, MAC, estado, MTU y estadísticas de /sys.
    """
    interfaces = {}
    output = run_cmd("ip -j -details address show")

    if output.startswith("Error"):
        print(f"{COLORS['red']}[-] Error obteniendo la configuración de interfaces: {output}{COLORS['reset']}")
        return interfaces

    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        print(f"{COLORS['red']}[-] Error decodificando la salida JSON de 'ip address show'.{COLORS['reset']}")
        return interfaces

    for iface_data in data:
        name = iface_data["ifname"]
        flags = iface_data.get("flags", [])
        iface_type = "loopback" if "LOOPBACK" in flags else iface_data.get("link_type", "unknown")

        interfaces[name] = {
            "mac":   iface_data.get("address", "00:00:00:00:00:00").upper(),
            "state": iface_data.get("operstate", "UNKNOWN").upper(),
            "mtu":   iface_data.get("mtu", 1500),
            "type":  iface_type,
            "ipv4":  [],
            "ipv6":  [],
            "stats": {},
            "flags": flags,
        }

        for addr_info in iface_data.get("addr_info", []):
            ip_data = {
                "address": addr_info["local"],
                "prefix":  addr_info["prefixlen"],
                "scope":   addr_info.get("scope", "global"),
            }
            if addr_info["family"] == "inet":
                interfaces[name]["ipv4"].append(ip_data)
            elif addr_info["family"] == "inet6":
                interfaces[name]["ipv6"].append(ip_data)

        stats_path = f"/sys/class/net/{name}/statistics/"
        if os.path.exists(stats_path):
            for stat_name in ["rx_packets", "tx_packets", "rx_bytes", "tx_bytes", "rx_errors", "tx_errors"]:
                try:
                    with open(os.path.join(stats_path, stat_name)) as f_stat:
                        interfaces[name]["stats"][stat_name] = int(f_stat.read().strip())
                except IOError:
                    interfaces[name]["stats"][stat_name] = 0

    return interfaces


def select_interface_and_get_network(interfaces_config: dict):
    """
    Muestra las interfaces activas y permite al usuario seleccionar una.

    Devuelve: (interface_name, local_ip, network_cidr, mac) o (None, None, None, None).
    """
    global local_ip_address_for_capture

    print(f"\n{COLORS['cyan']}[*] Interfaces de red disponibles:{COLORS['reset']}")
    active_interfaces_list = []

    for name, config in interfaces_config.items():
        if config["type"] == "loopback" or config["state"] != "UP" or not config["ipv4"]:
            continue
        global_ipv4 = [ip for ip in config["ipv4"] if ip["scope"] == "global"]
        if not global_ipv4:
            continue

        idx = len(active_interfaces_list) + 1
        first = global_ipv4[0]
        print(
            f"  {idx}. {name} ({first['address']}/{first['prefix']}) "
            f"- MAC: {config['mac']} - Estado: {config['state']}"
        )
        active_interfaces_list.append((name, config, first))

    if not active_interfaces_list:
        print(f"{COLORS['red']}[-] No se encontraron interfaces activas adecuadas.{COLORS['reset']}")
        return None, None, None, None

    while True:
        try:
            default = "1"
            raw = input(
                f"{COLORS['yellow']}[?] Seleccione la interfaz por número (Enter para default {default}): {COLORS['reset']}"
            )
            choice = int(raw or default)
            if 1 <= choice <= len(active_interfaces_list):
                if_name, _, ip_config = active_interfaces_list[choice - 1]
                iface_obj  = ipaddress.ip_interface(f"{ip_config['address']}/{ip_config['prefix']}")
                network_obj = iface_obj.network
                local_ip_address_for_capture = str(iface_obj.ip)

                print(f"{COLORS['green']}[+] Interfaz seleccionada: {if_name} ({local_ip_address_for_capture}){COLORS['reset']}")
                print(f"{COLORS['green']}[+] Rango de red derivado: {network_obj}{COLORS['reset']}")
                return if_name, local_ip_address_for_capture, str(network_obj), interfaces_config[if_name]["mac"]
            else:
                print(f"{COLORS['red']}[-] Selección inválida.{COLORS['reset']}")
        except ValueError:
            print(f"{COLORS['red']}[-] Entrada inválida. Por favor ingrese un número.{COLORS['reset']}")
