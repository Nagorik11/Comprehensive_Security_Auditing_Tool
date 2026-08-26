"""
Descubrimiento de dispositivos en la red:
  - Lectura de la tabla ARP/vecinos del kernel (con pre-poblado via nmap)
  - Escaneo activo con Scapy ARP
"""
import json

from scapy.all import ARP, Ether, srp

from config.constants import COLORS
from utils.oui import get_manufacturer
from utils.shell import check_command_exists, run_cmd


def get_network_devices(network_range: str, interface_name: str) -> list[dict]:
    """
    Pobla la caché ARP con un ping-scan de nmap y luego lee
    la tabla de vecinos del kernel.
    """
    devices: list[dict] = []

    if not check_command_exists("nmap"):
        print(f"{COLORS['yellow']}[!] nmap no está instalado. La caché ARP será menos efectiva.{COLORS['reset']}")
    else:
        print(
            f"{COLORS['cyan']}[*] Poblando caché ARP para {network_range} vía {interface_name} con nmap...{COLORS['reset']}"
        )
        run_cmd(f"nmap -sn -PR -e {interface_name} {network_range}", timeout=120)
        print(f"{COLORS['green']}[+] Escaneo nmap para poblar ARP completado.{COLORS['reset']}")

    print(f"{COLORS['cyan']}[*] Leyendo la tabla de vecinos (ARP cache)...{COLORS['reset']}")
    output = run_cmd("ip -j neigh show")
    if output.startswith("Error"):
        print(f"{COLORS['red']}[-] Error obteniendo la tabla de vecinos: {output}{COLORS['reset']}")
        return devices

    try:
        entries = json.loads(output)
        for entry in entries:
            if (
                entry.get("lladdr")
                and entry.get("dev") == interface_name
                and entry["state"] in {"REACHABLE", "STALE", "DELAY", "PROBE"}
            ):
                devices.append({
                    "ip":           entry.get("dst", "N/A"),
                    "mac":          entry["lladdr"].upper(),
                    "interface":    entry.get("dev", "N/A"),
                    "state":        entry["state"],
                    "manufacturer": get_manufacturer(entry["lladdr"]),
                })
        print(f"{COLORS['green']}[+] Dispositivos en tabla de vecinos: {len(devices)}{COLORS['reset']}")
    except json.JSONDecodeError:
        print(f"{COLORS['red']}[-] Error decodificando la salida JSON de 'ip neigh show'.{COLORS['reset']}")
    except Exception as e:
        print(f"{COLORS['red']}[-] Error obteniendo dispositivos: {e}{COLORS['reset']}")

    return devices


def discover_devices_with_arp(network_range: str, interface_name: str, timeout: int = 5) -> list[dict]:
    """Descubre dispositivos en la LAN mediante un ARP broadcast con Scapy."""
    arp_devices: list[dict] = []
    print(
        f"{COLORS['cyan']}[*] Descubriendo dispositivos con Scapy ARP en {network_range} "
        f"sobre {interface_name} (timeout: {timeout}s)...{COLORS['reset']}"
    )
    try:
        answered, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network_range),
            timeout=timeout,
            iface=interface_name,
            verbose=0,
        )
        for _, received in answered:
            arp_devices.append({
                "ip":           received.psrc,
                "mac":          received.hwsrc.upper(),
                "manufacturer": get_manufacturer(received.hwsrc),
            })
        print(f"{COLORS['green']}[+] Dispositivos descubiertos vía Scapy ARP: {len(arp_devices)}{COLORS['reset']}")
    except Exception as e:
        print(f"{COLORS['red']}[-] Error durante el descubrimiento ARP: {e}{COLORS['reset']}")
    return arp_devices


def get_default_gateway() -> str | None:
    """Devuelve la IP del gateway por defecto, o None si no se encuentra."""
    import re
    output = run_cmd("ip route show default")
    if output.startswith("Error"):
        print(f"{COLORS['red']}[-] Error obteniendo la default gateway: {output}{COLORS['reset']}")
        return None
    match = re.search(r"default via (\S+)", output)
    if match:
        gw_ip = match.group(1)
        print(f"{COLORS['green']}[+] Default Gateway: {gw_ip}{COLORS['reset']}")
        return gw_ip
    print(f"{COLORS['yellow']}[!] No se encontró default gateway.{COLORS['reset']}")
    return None
