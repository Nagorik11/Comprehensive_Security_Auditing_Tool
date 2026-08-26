"""
Análisis de conexiones locales activas (ss) y escaneo de servicios en red (nmap).
"""
import re
import xml.etree.ElementTree as ET

from config.constants import COLORS
from utils.shell import check_command_exists, run_cmd


# ---------------------------------------------------------------------------
# Conexiones locales (ss)
# ---------------------------------------------------------------------------

def get_active_connections_typed() -> list[dict]:
    """
    Obtiene conexiones TCP/UDP establecidas y en escucha usando 'ss'.
    Devuelve una lista de dicts con claves: proto, state, local_ip, local_port,
    remote_ip, remote_port, process.
    """
    connections: list[dict] = []

    if not check_command_exists("ss"):
        print(f"{COLORS['red']}[-] 'ss' no encontrado. No se pueden obtener conexiones activas.{COLORS['reset']}")
        return connections

    commands = {
        ("tcp", False): "ss -tnp",
        ("udp", False): "ss -unp",
        ("tcp", True):  "ss -tlnp",
        ("udp", True):  "ss -ulnp",
    }

    for (proto, is_listening), cmd in commands.items():
        label = f"{proto.upper()} {'en escucha' if is_listening else 'activas'}"
        print(f"{COLORS['cyan']}[*] Obteniendo conexiones {label}...{COLORS['reset']}")
        output = run_cmd(cmd)
        if not output.startswith("Error"):
            connections.extend(parse_ss_typed_output(output, proto, is_listening))
        else:
            print(f"{COLORS['yellow']}[!] No se pudieron obtener conexiones {label}: {output}{COLORS['reset']}")

    return connections


def parse_ss_typed_output(output: str, protocol: str, is_listening: bool = False) -> list[dict]:
    """Parsea la salida de 'ss' y devuelve lista de conexiones."""
    parsed: list[dict] = []
    lines = output.split("\n")

    if not lines or not lines[0].strip().lower().startswith("state"):
        return parsed

    addr_port_re = re.compile(r"(.+):([_a-zA-Z0-9*.-]+)$")
    proc_re      = re.compile(r'users:\(\("([^"]+)"')

    for line in lines[1:]:
        parts = line.strip().split()
        if not parts:
            continue

        # Determinar índices según protocolo/estado
        if protocol == "udp" and parts[0] == "UNCONN" and (
            len(parts) < 3 or not parts[1].replace(".", "", 1).isdigit()
        ):
            if len(parts) < 3:
                continue
            state_idx, local_idx, peer_idx, proc_start = 0, 1, 2, 3
        elif protocol == "tcp" or (protocol == "udp" and parts[0] != "UNCONN"):
            if len(parts) < 5:
                continue
            state_idx, local_idx, peer_idx, proc_start = 0, 3, 4, 5
        else:
            continue

        state          = parts[state_idx]
        local_addr_str = parts[local_idx]

        if len(parts) > peer_idx and not parts[peer_idx].startswith("users:"):
            peer_addr_str = parts[peer_idx]
            process_info  = " ".join(parts[proc_start:]) if len(parts) > proc_start else ""
        else:
            peer_addr_str = "*"
            process_info  = " ".join(parts[peer_idx:]) if len(parts) > peer_idx else ""

        try:
            def _split_addr_port(s):
                m = addr_port_re.match(s)
                return (m.group(1).strip("[]"), m.group(2)) if m else (s.strip("[]"), "*")

            local_ip, local_port   = _split_addr_port(local_addr_str)
            remote_ip, remote_port = _split_addr_port(peer_addr_str)

            if local_ip in ("0.0.0.0", "::"):
                local_ip = "*"

            proc_match = proc_re.search(process_info)
            process    = proc_match.group(1) if proc_match else "N/A"

            parsed.append({
                "proto":       protocol,
                "state":       state,
                "local_ip":    local_ip,
                "local_port":  local_port,
                "remote_ip":   remote_ip,
                "remote_port": remote_port,
                "process":     process,
            })
        except Exception:
            pass  # Suprimir líneas mal formateadas

    return parsed


# ---------------------------------------------------------------------------
# Escaneo de servicios en red (nmap)
# ---------------------------------------------------------------------------

def scan_network_services(ip_range: str, interface_name: str) -> list[dict]:
    """
    Escanea servicios comunes en el rango de red con nmap (-sV).
    Devuelve lista de dicts con ip, port, protocol, service_name, product, version.
    """
    services: list[dict] = []

    if not check_command_exists("nmap"):
        print(f"{COLORS['red']}[-] nmap no está instalado. Omitiendo escaneo de servicios.{COLORS['reset']}")
        return services

    print(
        f"{COLORS['cyan']}[*] Escaneando servicios en {ip_range} vía {interface_name}... "
        f"(puede tardar){COLORS['reset']}"
    )
    nmap_cmd = f"nmap -sV --open -T4 -e {interface_name} {ip_range} -oX -"
    xml_output = run_cmd(nmap_cmd, timeout=600)

    if xml_output.startswith("Error") or not xml_output:
        print(f"{COLORS['red']}[-] Error en escaneo nmap: {xml_output}{COLORS['reset']}")
        return services

    print(f"{COLORS['green']}[+] Escaneo de servicios completado.{COLORS['reset']}")

    try:
        root = ET.fromstring(xml_output)
        for host_node in root.findall("host"):
            addr_node = host_node.find("address[@addrtype='ipv4']")
            if addr_node is None:
                continue
            ip_addr = addr_node.get("addr")
            ports_node = host_node.find("ports")
            if ports_node is None:
                continue

            for port_node in ports_node.findall("port"):
                state_node = port_node.find("state")
                if state_node is None or state_node.get("state") != "open":
                    continue
                svc = port_node.find("service")
                services.append({
                    "ip":           ip_addr,
                    "port":         port_node.get("portid"),
                    "protocol":     port_node.get("protocol"),
                    "service_name": svc.get("name", "unknown")    if svc is not None else "unknown",
                    "product":      svc.get("product", "")        if svc is not None else "",
                    "version":      svc.get("version", "")        if svc is not None else "",
                    "extrainfo":    svc.get("extrainfo", "")      if svc is not None else "",
                })
    except ET.ParseError:
        print(f"{COLORS['red']}[-] Error parseando la salida XML de nmap.{COLORS['reset']}")
    except Exception as e:
        print(f"{COLORS['red']}[-] Error procesando resultados nmap: {e}{COLORS['reset']}")

    return services
