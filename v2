  import subprocess
import os
import re
import socket
from datetime import datetime
import concurrent.futures # Kept for future use, not actively used now
import csv
import json
import time
from collections import defaultdict
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, Ether, srp
import ipaddress # For network calculations

# Colores ANSI
COLORS = {
    "green": "\033[92m",
    "red": "\033[91m",
    "yellow": "\033[93m",
    "cyan": "\033[96m",
    "alert": "\033[97;41m",
    "reset": "\033[0m"
}

# Configuración
TIMESTAMP = datetime.now().strftime("%Y%m%d_%H%M%S")
OUTPUT_DIR = "network_analysis_reports" # Store reports in a subdirectory
os.makedirs(OUTPUT_DIR, exist_ok=True)

OUTPUT_FILES = {
    "txt": os.path.join(OUTPUT_DIR, f"network_analysis_report_{TIMESTAMP}.txt"),
    "connections_csv": os.path.join(OUTPUT_DIR, f"active_connections_{TIMESTAMP}.csv"),
    "capture_stats_json": os.path.join(OUTPUT_DIR, f"capture_stats_{TIMESTAMP}.json"),
    "interfaces_json": os.path.join(OUTPUT_DIR, f"network_interfaces_{TIMESTAMP}.json"),
    "devices_csv": os.path.join(OUTPUT_DIR, f"network_devices_{TIMESTAMP}.csv"),
    "services_csv": os.path.join(OUTPUT_DIR, f"discovered_services_{TIMESTAMP}.csv")
}
SAFE_PORTS = {22, 80, 443, 8080, 53, 123, 993, 995} # Example safe ports
MAX_WORKERS = 10 # For potential future concurrent tasks
CAPTURE_DURATION = 30 # Reduced default for quicker testing, can be increased
OUI_FILE_PATH = os.path.expanduser('~/.local/share/ieee-oui.txt')

# Estadísticas de captura de paquetes
capture_stats = {
    'protocols': defaultdict(int),
    'ports': defaultdict(int),
    'traffic_by_ip': defaultdict(lambda: {'sent_bytes': 0, 'recv_bytes': 0, 'total_bytes': 0}),
    'packet_sizes': [],
    'start_time': None,
    'end_time': None,
    'total_packets': 0
}

# OUI Data Cache
oui_data_cache = {}
local_ip_address_for_capture = None # Will be set after interface selection

# --- Funciones base ---
def check_root():
    if os.geteuid() != 0:
        print(f"{COLORS['red']}[-] Este script requiere privilegios de root (sudo) para funcionar correctamente.{COLORS['reset']}")
        exit(1)

def check_command_exists(command):
    try:
        subprocess.run([command, "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        # For commands like 'which' itself or general check
        return subprocess.call(['which', command], stdout=subprocess.PIPE, stderr=subprocess.PIPE) == 0


def run_cmd(cmd, timeout=20): # Increased default timeout for commands like nmap
    try:
        result = subprocess.run(
            cmd, shell=True, check=True,
            capture_output=True, text=True, timeout=timeout
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        # Log stderr for debugging but return a clear error message
        # print(f"{COLORS['yellow']}[DEBUG] CMD Error for '{cmd}': {e.stderr}{COLORS['reset']}")
        return f"Error ({e.returncode})" # Simpler error for checks
    except subprocess.TimeoutExpired:
        return f"Error: Command '{cmd}' timed out after {timeout} seconds."
    except Exception as e:
        return f"Error: {str(e)}"

# --- Gestión de OUI ---
def load_oui_data(oui_file_path):
    global oui_data_cache
    if not oui_data_cache and os.path.exists(oui_file_path):
        print(f"{COLORS['cyan']}[*] Cargando datos OUI desde {oui_file_path}...{COLORS['reset']}")
        try:
            with open(oui_file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    if '(hex)' in line: # Standard OUI file format
                        parts = line.split('(hex)')
                        mac_prefix = parts[0].strip().replace('-', '') # OUI part
                        manufacturer = parts[1].strip()
                        if len(mac_prefix) == 6: # Ensure it's a standard 3-byte OUI
                             oui_data_cache[mac_prefix] = manufacturer
            print(f"{COLORS['green']}[+] Datos OUI cargados: {len(oui_data_cache)} entradas.{COLORS['reset']}")
        except Exception as e:
            print(f"{COLORS['yellow']}[!] Advertencia: No se pudo parsear el archivo OUI {oui_file_path}: {e}{COLORS['reset']}")
    elif not os.path.exists(oui_file_path):
        print(f"{COLORS['yellow']}[!] Archivo OUI no encontrado en {oui_file_path}.{COLORS['reset']}")


def get_manufacturer(mac_address):
    if not oui_data_cache: # Should have been loaded in main
        print(f"{COLORS['yellow']}[!] Datos OUI no cargados. Fabricante desconocido.{COLORS['reset']}")
        return "Desconocido (Datos OUI no cargados)"
    mac_prefix = mac_address.replace(':', '').upper()[:6]
    return oui_data_cache.get(mac_prefix, "Desconocido")

def ensure_oui_file():
    if not os.path.exists(OUI_FILE_PATH):
        print(f"{COLORS['yellow']}[!] Archivo OUI no encontrado en {OUI_FILE_PATH}.{COLORS['reset']}")
        if not check_command_exists("wget"):
            print(f"{COLORS['red']}[-] 'wget' no está instalado. No se puede descargar el archivo OUI automáticamente.{COLORS['reset']}")
            print(f"{COLORS['yellow']}[-] Por favor, descárguelo manualmente de https://standards-oui.ieee.org/oui/oui.txt y guárdelo como {OUI_FILE_PATH}{COLORS['reset']}")
            return False
        
        choice = input(f"{COLORS['yellow']}[?] ¿Desea intentar descargarlo ahora? (s/N): {COLORS['reset']}").lower()
        if choice == 's':
            print(f"{COLORS['cyan']}[*] Descargando archivo OUI...{COLORS['reset']}")
            os.makedirs(os.path.dirname(OUI_FILE_PATH), exist_ok=True)
            cmd = f"wget -q -O {OUI_FILE_PATH} https://standards-oui.ieee.org/oui/oui.txt"
            result = run_cmd(cmd, timeout=60) # Longer timeout for download
            if "Error" in result or not os.path.exists(OUI_FILE_PATH): # Check if wget succeeded
                print(f"{COLORS['red']}[-] Error descargando el archivo OUI: {result}{COLORS['reset']}")
                print(f"{COLORS['yellow']}[-] Intente descargarlo manualmente y guardarlo como {OUI_FILE_PATH}{COLORS['reset']}")
                return False
            else:
                print(f"{COLORS['green']}[+] Archivo OUI descargado exitosamente.{COLORS['reset']}")
                return True
        else:
            print(f"{COLORS['yellow']}[-] Fabricantes de dispositivos no estarán disponibles.{COLORS['reset']}")
            return False
    return True

# --- Gestión de interfaces mejorada ---
def get_full_interface_config():
    interfaces = {}
    try:
        output = run_cmd("ip -j -details address show") # -details for more info
        if output.startswith("Error"):
            print(f"{COLORS['red']}[-] Error obteniendo la configuración de interfaces: {output}{COLORS['reset']}")
            return interfaces
        data = json.loads(output)
        
        for iface_data in data:
            name = iface_data['ifname']
            interfaces[name] = {
                'mac': iface_data.get('address', '00:00:00:00:00:00').upper(),
                'state': iface_data.get('operstate', 'UNKNOWN').upper(),
                'mtu': iface_data.get('mtu', 1500),
                'type': iface_data.get('link_type', 'unknown'), # ethernet, loopback, wlan etc.
                'ipv4': [],
                'ipv6': [],
                'stats': {},
                'flags': iface_data.get('flags', [])
            }

            if 'LOOPBACK' in interfaces[name]['flags']:
                interfaces[name]['type'] = 'loopback'
            # Further type detection could use iface_data['linkinfo']['info_kind'] for more specific types like 'vlan', 'bridge' if present

            for addr_info in iface_data.get('addr_info', []):
                ip_data = {
                    'address': addr_info['local'],
                    'prefix': addr_info['prefixlen'],
                    'scope': addr_info.get('scope', 'global')
                }
                if addr_info['family'] == 'inet':
                    interfaces[name]['ipv4'].append(ip_data)
                elif addr_info['family'] == 'inet6':
                    interfaces[name]['ipv6'].append(ip_data)

            stats_path = f"/sys/class/net/{name}/statistics/"
            if os.path.exists(stats_path):
                for stat_name in ['rx_packets', 'tx_packets', 'rx_bytes', 'tx_bytes', 'rx_errors', 'tx_errors']:
                    try:
                        with open(os.path.join(stats_path, stat_name)) as f_stat:
                            interfaces[name]['stats'][stat_name] = int(f_stat.read().strip())
                    except IOError:
                        interfaces[name]['stats'][stat_name] = 0
    except json.JSONDecodeError:
        print(f"{COLORS['red']}[-] Error decodificando la salida JSON de 'ip address show'.{COLORS['reset']}")
    except Exception as e:
        print(f"{COLORS['red']}[-] Excepción obteniendo interfaces: {e}{COLORS['reset']}")
    return interfaces

def select_interface_and_get_network(interfaces_config):
    global local_ip_address_for_capture
    print(f"\n{COLORS['cyan']}[*] Interfaces de red disponibles:{COLORS['reset']}")
    active_interfaces_list = []
    idx = 0
    for name, config in interfaces_config.items():
        if config['type'] == 'loopback' or config['state'] != 'UP' or not config['ipv4']:
            continue
        # Display only global scope IPv4 addresses for selection
        global_ipv4 = [ip_info for ip_info in config['ipv4'] if ip_info['scope'] == 'global']
        if not global_ipv4:
            continue
        
        print(f"  {idx + 1}. {name} ({global_ipv4[0]['address']}/{global_ipv4[0]['prefix']}) - MAC: {config['mac']} - Estado: {config['state']}")
        active_interfaces_list.append((name, config, global_ipv4[0]))
        idx += 1

    if not active_interfaces_list:
        print(f"{COLORS['red']}[-] No se encontraron interfaces activas adecuadas (UP, con IPv4 global).{COLORS['reset']}")
        return None, None, None, None

    while True:
        try:
            default_choice = "1" if len(active_interfaces_list) >= 1 else ""
            choice_input = input(f"{COLORS['yellow']}[?] Seleccione la interfaz por número (Enter para default {default_choice}): {COLORS['reset']}")
            choice = int(choice_input or default_choice)
            if 1 <= choice <= len(active_interfaces_list):
                if_name, _, ip_config = active_interfaces_list[choice - 1]
                
                # Use ipaddress module for robust network calculation
                ip_interface_obj = ipaddress.ip_interface(f"{ip_config['address']}/{ip_config['prefix']}")
                network_obj = ip_interface_obj.network
                
                local_ip_address_for_capture = str(ip_interface_obj.ip) # Store for packet handler
                
                print(f"{COLORS['green']}[+] Interfaz seleccionada: {if_name} ({local_ip_address_for_capture}){COLORS['reset']}")
                print(f"{COLORS['green']}[+] Rango de red derivado: {str(network_obj)}{COLORS['reset']}")
                return if_name, local_ip_address_for_capture, str(network_obj), interfaces_config[if_name]['mac']
            else:
                print(f"{COLORS['red']}[-] Selección inválida.{COLORS['reset']}")
        except ValueError:
            print(f"{COLORS['red']}[-] Entrada inválida. Por favor ingrese un número.{COLORS['reset']}")
        except IndexError:
             print(f"{COLORS['red']}[-] Selección inválida.{COLORS['reset']}")


# --- Detección de dispositivos ---
def get_network_devices(network_range_to_scan, interface_name):
    devices = []
    if not check_command_exists("nmap"):
        print(f"{COLORS['yellow']}[!] nmap no está instalado. La población de la caché ARP será menos efectiva.{COLORS['reset']}")
    else:
        print(f"{COLORS['cyan']}[*] Intentando poblar la caché ARP para {network_range_to_scan} vía {interface_name} usando nmap...{COLORS['reset']}")
        # -n: no DNS resolution, -PR: ARP ping
        # Forcing nmap to use the specified interface: -e <interface>
        # Adjust nmap command for better ARP cache population. -sn is ping scan.
        nmap_cmd = f"nmap -sn -PR -e {interface_name} {network_range_to_scan}"
        run_cmd(nmap_cmd, timeout=120) # Longer timeout for potentially large networks
        print(f"{COLORS['green']}[+] Escaneo nmap para poblar ARP completado.{COLORS['reset']}")

    print(f"{COLORS['cyan']}[*] Leyendo la tabla de vecinos (ARP cache)...{COLORS['reset']}")
    try:
        output = run_cmd("ip -j neigh show")
        if output.startswith("Error"):
            print(f"{COLORS['red']}[-] Error obteniendo dispositivos de la tabla de vecinos: {output}{COLORS['reset']}")
            return devices
        
        entries = json.loads(output)
        
        for entry in entries:
            # We are interested in entries with MAC addresses (lladdr) and that are REACHABLE or STALE (recently reachable)
            if entry.get('lladdr') and entry.get('dev') == interface_name and \
               entry['state'] in ['REACHABLE', 'STALE', 'DELAY', 'PROBE']:
                
                manufacturer = get_manufacturer(entry['lladdr'])
                
                devices.append({
                    'ip': entry.get('dst', 'N/A'),
                    'mac': entry['lladdr'].upper(),
                    'interface': entry.get('dev', 'N/A'),
                    'state': entry['state'],
                    'manufacturer': manufacturer
                })
        print(f"{COLORS['green']}[+] Dispositivos encontrados en la tabla de vecinos: {len(devices)}{COLORS['reset']}")
    except json.JSONDecodeError:
        print(f"{COLORS['red']}[-] Error decodificando la salida JSON de 'ip neigh show'.{COLORS['reset']}")
    except Exception as e:
        print(f"{COLORS['red']}[-] Error obteniendo dispositivos de la tabla de vecinos: {e}{COLORS['reset']}")
    
    return devices

def discover_devices_with_arp(network_range, interface_name, timeout=5):
    """Descubre dispositivos en la red local mediante ARP con Scapy"""
    arp_devices = []
    print(f"{COLORS['cyan']}[*] Descubriendo dispositivos con Scapy ARP en {network_range} sobre {interface_name} (timeout: {timeout}s)...{COLORS['reset']}")
    try:
        ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=network_range),
                         timeout=timeout, iface=interface_name, verbose=0)
        
        for sent, received in ans:
            manufacturer = get_manufacturer(received.hwsrc)
            arp_devices.append({
                'ip': received.psrc,
                'mac': received.hwsrc.upper(),
                'manufacturer': manufacturer
            })
        print(f"{COLORS['green']}[+] Dispositivos descubiertos vía Scapy ARP: {len(arp_devices)}{COLORS['reset']}")
    except Exception as e:
        print(f"{COLORS['red']}[-] Error durante el descubrimiento ARP con Scapy: {e}{COLORS['reset']}")
    return arp_devices

# --- Captura de paquetes ---
def packet_handler(packet):
    global capture_stats, local_ip_address_for_capture
    capture_stats['total_packets'] += 1
    
    if IP in packet:
        ip_layer = packet[IP]
        size = len(packet)
        proto_name = 'OTHER_IP'
        src_port, dst_port = 0, 0 # Default for non-TCP/UDP

        if TCP in packet:
            proto_name = 'TCP'
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            capture_stats['ports'][dst_port] += 1
            capture_stats['ports'][src_port] += 1
        elif UDP in packet:
            proto_name = 'UDP'
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            capture_stats['ports'][dst_port] += 1
            capture_stats['ports'][src_port] += 1
        elif ICMP in packet:
            proto_name = 'ICMP'
        
        capture_stats['protocols'][proto_name] += 1
        capture_stats['packet_sizes'].append(size)
        
        # Determine traffic direction based on local IP
        # local_ip_address_for_capture should be set by select_interface_and_get_network
        if local_ip_address_for_capture:
            if ip_layer.src == local_ip_address_for_capture: # Sent packet
                capture_stats['traffic_by_ip'][ip_layer.dst]['sent_bytes'] += size
                capture_stats['traffic_by_ip'][ip_layer.dst]['total_bytes'] += size
            elif ip_layer.dst == local_ip_address_for_capture: # Received packet
                capture_stats['traffic_by_ip'][ip_layer.src]['recv_bytes'] += size
                capture_stats['traffic_by_ip'][ip_layer.src]['total_bytes'] += size
            # Else, it's traffic not to/from our main IP (e.g. broadcast, multicast, or promiscuous mode capture)
        else: # Fallback if local IP not set (should not happen in normal flow)
            # This part might be less accurate if local_ip_address_for_capture is not set
            # For now, just log based on a generic local hostname, less reliable
            try:
                generic_local_ip = socket.gethostbyname(socket.gethostname())
                if ip_layer.src == generic_local_ip:
                    capture_stats['traffic_by_ip'][ip_layer.dst]['sent_bytes'] += size
                else:
                     capture_stats['traffic_by_ip'][ip_layer.src]['recv_bytes'] += size
                capture_stats['traffic_by_ip'][ip_layer.dst if ip_layer.src == generic_local_ip else ip_layer.src]['total_bytes'] += size
            except socket.gaierror: # Could happen if hostname not resolvable
                 pass


def start_capture(interface_to_sniff, duration=CAPTURE_DURATION):
    global capture_stats
    print(f"{COLORS['cyan']}[*] Iniciando captura de tráfico en '{interface_to_sniff}' por {duration}s...{COLORS['reset']}")
    capture_stats['start_time'] = datetime.now().isoformat()
    capture_stats['total_packets'] = 0 # Reset for current capture
    capture_stats['protocols'].clear()
    capture_stats['ports'].clear()
    capture_stats['traffic_by_ip'].clear()
    capture_stats['packet_sizes'] = []

    try:
        sniff(iface=interface_to_sniff, prn=packet_handler, store=0, timeout=duration)
    except Exception as e:
        print(f"{COLORS['red']}[-] Error durante la captura de paquetes: {e}{COLORS['reset']}")
        print(f"{COLORS['yellow']}[!] Asegúrese de que la interfaz '{interface_to_sniff}' es correcta y tiene permisos.{COLORS['reset']}")
    
    capture_stats['end_time'] = datetime.now().isoformat()
    print(f"{COLORS['green']}[+] Captura completada. Total de paquetes: {capture_stats['total_packets']}{COLORS['reset']}")

def capture_gateway_packets(gateway_ip, interface_to_sniff, duration=30):
    """Captura paquetes hacia/desde la default gateway"""
    if not gateway_ip:
        print(f"{COLORS['yellow']}[!] No se pudo determinar la default gateway. Omitiendo captura de gateway.{COLORS['reset']}")
        return []
    print(f"{COLORS['cyan']}[*] Capturando paquetes de la default gateway ({gateway_ip}) en '{interface_to_sniff}' por {duration}s...{COLORS['reset']}")
    try:
        packets = sniff(iface=interface_to_sniff, filter=f"host {gateway_ip}", timeout=duration, store=1)
        print(f"{COLORS['green']}[+] Captura de gateway completada. Total de paquetes: {len(packets)}{COLORS['reset']}")
        return packets # Returns list of Scapy packets
    except Exception as e:
        print(f"{COLORS['red']}[-] Error capturando paquetes de gateway: {e}{COLORS['reset']}")
    return []

# --- Escaneo de servicios ---
def scan_network_services(ip_range_to_scan, interface_name):
    services = []
    if not check_command_exists("nmap"):
        print(f"{COLORS['red']}[-] nmap no está instalado. Omitiendo escaneo de servicios.{COLORS['reset']}")
        return services
        
    print(f"{COLORS['cyan']}[*] Escaneando servicios comunes en la red ({ip_range_to_scan}) vía {interface_name}... (Esto puede tardar){COLORS['reset']}")
    # -sV: Version detection, --open: Only show open ports, -T4: Faster execution
    # Using common ports for speed. For full scan: -p 1-65535
    # Add -e <interface> to ensure nmap uses the correct one.
    nmap_cmd = f"nmap -sV --open -T4 -e {interface_name} {ip_range_to_scan} -oX -" # Output XML to stdout
    
    xml_output = run_cmd(nmap_cmd, timeout=600) # Long timeout for nmap

    if xml_output.startswith("Error") or not xml_output:
        print(f"{COLORS['red']}[-] Error durante el escaneo de servicios con nmap o no se recibió salida: {xml_output}{COLORS['reset']}")
        return services
    
    print(f"{COLORS['green']}[+] Escaneo de servicios completado.{COLORS['reset']}")
    
    try:
        import xml.etree.ElementTree as ET
        root = ET.fromstring(xml_output)
        for host_node in root.findall("host"):
            ip_addr = host_node.find("address[@addrtype='ipv4']").get("addr")
            ports_node = host_node.find("ports")
            if ports_node is not None:
                for port_node in ports_node.findall("port"):
                    state_node = port_node.find("state")
                    if state_node is not None and state_node.get("state") == "open":
                        service_node = port_node.find("service")
                        services.append({
                            "ip": ip_addr,
                            "port": port_node.get("portid"),
                            "protocol": port_node.get("protocol"),
                            "service_name": service_node.get("name", "unknown") if service_node is not None else "unknown",
                            "product": service_node.get("product", "") if service_node is not None else "",
                            "version": service_node.get("version", "") if service_node is not None else "",
                            "extrainfo": service_node.get("extrainfo", "") if service_node is not None else ""
                        })
    except ET.ParseError:
        print(f"{COLORS['red']}[-] Error parseando la salida XML de nmap.{COLORS['reset']}")
        # print(f"{COLORS['yellow']}[DEBUG NMAP XML]:\n{xml_output[:1000]}...{COLORS['reset']}") # For debugging
    except Exception as e:
        print(f"{COLORS['red']}[-] Error procesando resultados del escaneo de servicios: {e}{COLORS['reset']}")
    return services

# --- Análisis de conexiones locales ---
def get_active_connections_typed():
    connections = []
    # Check if 'ss' command is available
    if not check_command_exists("ss"):
        print(f"{COLORS['red']}[-] 'ss' command not found. Cannot retrieve active connections.{COLORS['reset']}")
        return connections

    proto_map = {'tcp': 'ss -tnp', 'udp': 'ss -unp'} # Established/Connected
    listen_proto_map = {'tcp': 'ss -tlnp', 'udp': 'ss -ulnp'} # Listening

    for proto, cmd in proto_map.items():
        print(f"{COLORS['cyan']}[*] Obteniendo conexiones {proto.upper()} activas...{COLORS['reset']}")
        output = run_cmd(cmd)
        if not output.startswith("Error"):
            connections.extend(parse_ss_typed_output(output, proto, is_listening=False))
        else:
            print(f"{COLORS['yellow']}[!] No se pudieron obtener conexiones {proto.upper()}: {output}{COLORS['reset']}")
            
    for proto, cmd in listen_proto_map.items():
        print(f"{COLORS['cyan']}[*] Obteniendo sockets {proto.upper()} en escucha...{COLORS['reset']}")
        output = run_cmd(cmd)
        if not output.startswith("Error"):
            connections.extend(parse_ss_typed_output(output, proto, is_listening=True))
        else:
            print(f"{COLORS['yellow']}[!] No se pudieron obtener sockets {proto.upper()} en escucha: {output}{COLORS['reset']}")
            
    return connections


def parse_ss_typed_output(output, protocol, is_listening=False):
    parsed_connections = []
    lines = output.split('\n')
    if not lines or not lines[0].strip().lower().startswith("state"): # Header check
        return parsed_connections

    for line_num, line_content in enumerate(lines[1:]): # Skip header
        parts = line_content.strip().split()
        
        # Expected structure:
        # State  Recv-Q Send-Q  Local Address:Port  Peer Address:Port Process (for TCP LISTEN/ESTAB)
        # State  Recv-Q Send-Q  Local Address:Port  Peer Address:Port         (for UDP LISTEN, no Process column sometimes)
        # State  Local Address:Port  Peer Address:Port Process (for UDP UNCONN, no Recv-Q/Send-Q)

        # Determine indices based on protocol and state
        state_idx, local_addr_idx, peer_addr_idx, process_info_start_idx = 0, 0, 0, 0

        if protocol == 'udp' and parts[0] == 'UNCONN' and (len(parts) < 3 or not parts[1].replace('.','',1).isdigit()):
            # UDP UNCONN: State Local Peer (Process)
            if len(parts) < 3: continue
            state_idx = 0
            local_addr_idx = 1
            peer_addr_idx = 2
            process_info_start_idx = 3
        elif (protocol == 'tcp' or (protocol == 'udp' and parts[0] != 'UNCONN')):
            # TCP or UDP (not UNCONN): State Recv-Q Send-Q Local Peer (Process)
            if len(parts) < 5 : continue # Need at least up to Peer address
            state_idx = 0
            # Recv-Q is parts[1], Send-Q is parts[2]
            local_addr_idx = 3
            peer_addr_idx = 4
            process_info_start_idx = 5
        else:
            continue # Unknown format

        state = parts[state_idx]
        local_addr_port = parts[local_addr_idx]
        
        peer_addr_port = "*" # Default
        if len(parts) > peer_addr_idx and not parts[peer_addr_idx].startswith("users:"):
            peer_addr_port = parts[peer_addr_idx]
            process_info = " ".join(parts[process_info_start_idx:]) if len(parts) > process_info_start_idx else ""
        else: # Peer address might be missing or process info starts earlier
            process_info = " ".join(parts[peer_addr_idx:]) if len(parts) > peer_addr_idx else ""


        try:
            addr_port_re = re.compile(r'(.+):([_a-zA-Z0-9*.-]+)$') # Supports hostnames, IPs, IPv6 brackets

            local_match = addr_port_re.match(local_addr_port)
            local_ip = local_match.group(1) if local_match else local_addr_port
            local_port = local_match.group(2) if local_match else "*"
            
            remote_match = addr_port_re.match(peer_addr_port)
            remote_ip = remote_match.group(1) if remote_match else peer_addr_port
            remote_port = remote_match.group(2) if remote_match else "*"
            
            proc_name_match = re.search(r'users:\(\("([^"]+)"', process_info)
            process = proc_name_match.group(1) if proc_name_match else "N/A"
            
            # Clean IPs (remove brackets from IPv6)
            local_ip = local_ip.strip("[]")
            remote_ip = remote_ip.strip("[]")
            if local_ip == "0.0.0.0" or local_ip == "::": local_ip = "*" # Common representation for listening on all interfaces

            parsed_connections.append({
                'proto': protocol,
                'state': state,
                'local_ip': local_ip,
                'local_port': local_port,
                'remote_ip': remote_ip,
                'remote_port': remote_port,
                'process': process
            })
        except Exception as e:
            # print(f"{COLORS['yellow']}[!] Advertencia: No se pudo parsear la línea de conexión {protocol}: '{line_content.strip()}' - {e}{COLORS['reset']}")
            # print(f"    Parts: {parts}, local_idx: {local_addr_idx}, peer_idx: {peer_addr_idx}, proc_idx: {process_info_start_idx}")
            pass # Suppress for now to avoid too much noise
    return parsed_connections

# --- Generación de reportes mejorada ---
def generate_reports(interface_details, network_devices, arp_discovered_devices, active_conns, discovered_services, captured_pkts_stats, gateway_pkts_summary):
    print(f"\n{COLORS['cyan']}[*] Generando reportes...{COLORS['reset']}")
    
    # Reporte TXT
    with open(OUTPUT_FILES['txt'], 'w', encoding='utf-8') as f:
        f.write("REPORTE COMPLETO DE ANÁLISIS DE RED\n")
        f.write(f"Generado el: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("="*80 + "\n\n")
        
        f.write("CONFIGURACIÓN DE INTERFACES DE RED:\n")
        f.write("="*80 + "\n")
        if interface_details:
            for name, config in interface_details.items():
                f.write(f"Interfaz: {name}\n")
                f.write(f"  Estado: {config.get('state', 'N/A')}\n")
                f.write(f"  Tipo: {config.get('type', 'N/A').title()}\n")
                f.write(f"  MAC: {config.get('mac', 'N/A')}\n")
                f.write(f"  MTU: {config.get('mtu', 'N/A')}\n")
                f.write(f"  IPv4: {[ip['address']+'/'+str(ip['prefix']) for ip in config.get('ipv4', [])]}\n")
                f.write(f"  IPv6: {[ip['address']+'/'+str(ip['prefix']) for ip in config.get('ipv6', [])]}\n")
                if config.get('stats'):
                    f.write(f"  Estadísticas (RX/TX):\n")
                    f.write(f"    Paquetes: {config['stats'].get('rx_packets', 0)} / {config['stats'].get('tx_packets', 0)}\n")
                    f.write(f"    Bytes: {config['stats'].get('rx_bytes', 0)} / {config['stats'].get('tx_bytes', 0)}\n")
                    f.write(f"    Errores: {config['stats'].get('rx_errors', 0)} / {config['stats'].get('tx_errors', 0)}\n")
                f.write("-"*40 + "\n")
        else:
            f.write("No se pudo obtener información de las interfaces.\n")
        
        f.write("\nDISPOSITIVOS EN LA RED (Desde Cache ARP/Vecinos):\n")
        f.write("="*80 + "\n")
        if network_devices:
            for device in network_devices:
                f.write(f"IP: {device['ip']:<15} MAC: {device['mac']:<17} Fabricante: {device.get('manufacturer', 'N/A'):<25} Estado: {device.get('state', 'N/A')}\n")
        else:
            f.write("No se encontraron dispositivos en la caché ARP para la interfaz seleccionada o error al obtenerlos.\n")

        f.write("\nDISPOSITIVOS EN LA RED (Descubiertos Activamente con Scapy ARP):\n")
        f.write("="*80 + "\n")
        if arp_discovered_devices:
            for device in arp_discovered_devices:
                f.write(f"IP: {device['ip']:<15} MAC: {device['mac']:<17} Fabricante: {device.get('manufacturer', 'N/A')}\n")
        else:
            f.write("No se descubrieron dispositivos activamente con Scapy ARP o el escaneo fue omitido.\n")

        f.write("\nCONEXIONES DE RED ACTIVAS (LOCALES):\n")
        f.write("="*80 + "\n")
        if active_conns:
            f.write(f"{'Proto':<5} {'Estado':<10} {'IP Local':<20} {'PuertoL':<7} {'IP Remota':<20} {'PuertoR':<7} {'Proceso'}\n")
            f.write("-"*80 + "\n")
            for conn in active_conns:
                f.write(f"{conn['proto']:<5} {conn['state']:<10} {conn['local_ip']:<20} {str(conn['local_port']):<7} {conn['remote_ip']:<20} {str(conn['remote_port']):<7} {conn.get('process', 'N/A')}\n")
        else:
            f.write("No se encontraron conexiones activas o error al obtenerlas.\n")
        
        f.write("\nSERVICIOS DETECTADOS EN LA RED (Nmap Scan):\n")
        f.write("="*80 + "\n")
        if discovered_services:
            f.write(f"{'IP Host':<15} {'Puerto':<7} {'Proto':<5} {'Servicio':<20} {'Producto/Versión'}\n")
            f.write("-"*80 + "\n")
            for service in discovered_services:
                product_info = f"{service.get('product','')} {service.get('version','')}".strip()
                f.write(f"{service['ip']:<15} {str(service['port']):<7} {service['protocol']:<5} {service['service_name']:<20} {product_info}\n")
                if int(service['port']) not in SAFE_PORTS and service['protocol'] == 'tcp': # Basic alert for non-standard open TCP ports
                    f.write(f"  {COLORS['alert']}[ALERTA] Puerto abierto no estándar: {service['port']}/{service['protocol']} en {service['ip']}{COLORS['reset']}\n") # Color won't show in .txt
        else:
            f.write("No se detectaron servicios (escaneo nmap omitido o sin resultados).\n")

        f.write("\nESTADÍSTICAS DE CAPTURA DE PAQUETES (Scapy Sniff):\n")
        f.write("="*80 + "\n")
        if captured_pkts_stats and captured_pkts_stats.get('total_packets', 0) > 0:
            f.write(f"Duración de captura: {captured_pkts_stats.get('start_time')} a {captured_pkts_stats.get('end_time')}\n")
            f.write(f"Total de paquetes capturados: {captured_pkts_stats['total_packets']}\n\n")
            f.write("Distribución de Protocolos:\n")
            for proto, count in sorted(captured_pkts_stats['protocols'].items(), key=lambda item: item[1], reverse=True):
                f.write(f"  {proto}: {count}\n")
            f.write("\nPuertos Más Comunes (Origen/Destino):\n")
            for port, count in sorted(captured_pkts_stats['ports'].items(), key=lambda item: item[1], reverse=True)[:10]:
                f.write(f"  Puerto {port}: {count}\n")
            f.write("\nTráfico por IP (Top 10 por bytes totales):\n")
            sorted_traffic = sorted(captured_pkts_stats['traffic_by_ip'].items(), key=lambda item: item[1]['total_bytes'], reverse=True)
            for ip, data in sorted_traffic[:10]:
                f.write(f"  IP: {ip:<15} | Enviado: {data['sent_bytes']} bytes | Recibido: {data['recv_bytes']} bytes | Total: {data['total_bytes']} bytes\n")
            if captured_pkts_stats['packet_sizes']:
                 avg_pkt_size = sum(captured_pkts_stats['packet_sizes']) / len(captured_pkts_stats['packet_sizes'])
                 f.write(f"\nTamaño promedio de paquete: {avg_pkt_size:.2f} bytes\n")
                 f.write(f"Tamaño mínimo de paquete: {min(captured_pkts_stats['packet_sizes'])} bytes\n")
                 f.write(f"Tamaño máximo de paquete: {max(captured_pkts_stats['packet_sizes'])} bytes\n")
        else:
            f.write("No se realizó captura de paquetes o no se capturaron paquetes.\n")

        f.write("\nPAQUETES DE GATEWAY:\n")
        f.write("="*80 + "\n")
        f.write(gateway_pkts_summary + "\n")

        f.write(f"\n\n{COLORS['green']}[+] Reporte guardado en: {OUTPUT_FILES['txt']}{COLORS['reset']}\n") # This color will be for console output

    # Reporte CSV de dispositivos de red (Cache ARP)
    if network_devices:
        with open(OUTPUT_FILES['devices_csv'], 'w', newline='', encoding='utf-8') as f_csv:
            writer = csv.DictWriter(f_csv, fieldnames=network_devices[0].keys())
            writer.writeheader()
            writer.writerows(network_devices)
        print(f"{COLORS['green']}[+] Reporte de dispositivos (cache) guardado en: {OUTPUT_FILES['devices_csv']}{COLORS['reset']}")

    # Reporte CSV de conexiones activas
    if active_conns:
        with open(OUTPUT_FILES['connections_csv'], 'w', newline='', encoding='utf-8') as f_csv:
            writer = csv.DictWriter(f_csv, fieldnames=active_conns[0].keys())
            writer.writeheader()
            writer.writerows(active_conns)
        print(f"{COLORS['green']}[+] Reporte de conexiones guardado en: {OUTPUT_FILES['connections_csv']}{COLORS['reset']}")

    # Reporte CSV de servicios descubiertos
    if discovered_services:
        with open(OUTPUT_FILES['services_csv'], 'w', newline='', encoding='utf-8') as f_csv:
            writer = csv.DictWriter(f_csv, fieldnames=discovered_services[0].keys())
            writer.writeheader()
            writer.writerows(discovered_services)
        print(f"{COLORS['green']}[+] Reporte de servicios guardado en: {OUTPUT_FILES['services_csv']}{COLORS['reset']}")

    # JSON de interfaces
    if interface_details:
        with open(OUTPUT_FILES['interfaces_json'], 'w', encoding='utf-8') as f_json:
            json.dump(interface_details, f_json, indent=2)
        print(f"{COLORS['green']}[+] Reporte de interfaces (JSON) guardado en: {OUTPUT_FILES['interfaces_json']}{COLORS['reset']}")

    # Estadísticas de captura de paquetes (JSON)
    if captured_pkts_stats and captured_pkts_stats.get('total_packets', 0) > 0 :
        with open(OUTPUT_FILES['capture_stats_json'], 'w', encoding='utf-8') as f_json:
            json.dump(captured_pkts_stats, f_json, indent=2)
        print(f"{COLORS['green']}[+] Estadísticas de captura (JSON) guardadas en: {OUTPUT_FILES['capture_stats_json']}{COLORS['reset']}")


# --- Función principal mejorada ---
def get_default_gateway():
    try:
        output = run_cmd("ip route show default")
        if output.startswith("Error"):
            print(f"{COLORS['red']}[-] Error obteniendo la default gateway: {output}{COLORS['reset']}")
            return None
        match = re.search(r"default via (\S+)", output)
        if match:
            gw_ip = match.group(1)
            print(f"{COLORS['green']}[+] Default Gateway encontrada: {gw_ip}{COLORS['reset']}")
            return gw_ip
        else:
            print(f"{COLORS['yellow']}[!] No se encontró default gateway en la tabla de rutas.{COLORS['reset']}")
    except Exception as e:
        print(f"{COLORS['red']}[-] Excepción obteniendo la default gateway: {e}{COLORS['reset']}")
    return None

def main():
    check_root()
    start_time_script = datetime.now()
    print(f"{COLORS['cyan']}{'='*20} INICIO DEL ANÁLISIS DE RED {'='*20}{COLORS['reset']}")

    # Variables para almacenar resultados
    interfaces_data = {}
    network_devices_cache = []
    arp_discovered_devices_active = []
    active_connections = []
    discovered_network_services = []
    # capture_stats is global
    gateway_packets_info = "Captura de gateway no realizada o sin resultados."

    # 0. Comprobaciones iniciales (OUI File)
    if ensure_oui_file():
        load_oui_data(OUI_FILE_PATH) # Load OUI data if file exists or was downloaded

    # 1. Configuración de Interfaces y Selección de Red
    interfaces_data = get_full_interface_config()
    if not interfaces_data:
        print(f"{COLORS['red']}[-] No se pudo obtener la configuración de las interfaces. Saliendo.{COLORS['reset']}")
        exit(1)
    
    selected_interface_name, selected_ip, network_range_cidr, selected_mac = select_interface_and_get_network(interfaces_data)
    if not selected_interface_name or not network_range_cidr:
        print(f"{COLORS['red']}[-] No se seleccionó una interfaz válida o no se pudo determinar el rango de red. Saliendo.{COLORS['reset']}")
        exit(1)

    # 2. Detección de Dispositivos
    #    a. Desde la caché ARP/vecinos (después de Nmap ping scan para poblar)
    network_devices_cache = get_network_devices(network_range_cidr, selected_interface_name)
    #    b. Descubrimiento activo con Scapy ARP
    arp_discovered_devices_active = discover_devices_with_arp(network_range_cidr, selected_interface_name, timeout=10)

    # 3. Análisis de Conexiones Locales
    active_connections = get_active_connections_typed()

    # 4. Escaneo de Servicios en la Red (Nmap)
    #    (Puede ser largo, considerar hacerlo opcional o con confirmación)
    if check_command_exists("nmap"):
        scan_services_q = input(f"{COLORS['yellow']}[?] ¿Realizar escaneo de servicios en la red {network_range_cidr}? (s/N): {COLORS['reset']}").lower()
        if scan_services_q == 's':
            discovered_network_services = scan_network_services(network_range_cidr, selected_interface_name)
        else:
            print(f"{COLORS['yellow']}[-] Escaneo de servicios omitido por el usuario.{COLORS['reset']}")
    else:
        print(f"{COLORS['yellow']}[!] nmap no está instalado, omitiendo escaneo de servicios.{COLORS['reset']}")


    # 5. Captura de Paquetes (General)
    capture_q = input(f"{COLORS['yellow']}[?] ¿Realizar captura de tráfico general en '{selected_interface_name}' por {CAPTURE_DURATION}s? (s/N): {COLORS['reset']}").lower()
    if capture_q == 's':
        start_capture(selected_interface_name, CAPTURE_DURATION)
    else:
        print(f"{COLORS['yellow']}[-] Captura de tráfico general omitida.{COLORS['reset']}")


    # 6. Captura de Paquetes de Gateway
    default_gw_ip = get_default_gateway()
    if default_gw_ip:
        capture_gw_q = input(f"{COLORS['yellow']}[?] ¿Realizar captura de tráfico de la gateway ({default_gw_ip}) en '{selected_interface_name}' por 30s? (s/N): {COLORS['reset']}").lower()
        if capture_gw_q == 's':
            gw_packets = capture_gateway_packets(default_gw_ip, selected_interface_name, duration=30)
            gateway_packets_info = f"Capturados {len(gw_packets)} paquetes relacionados con la gateway {default_gw_ip}."
            # Aquí podrías añadir un análisis más profundo de gw_packets si es necesario
        else:
            gateway_packets_info = f"Captura de gateway ({default_gw_ip}) omitida por el usuario."
    else:
        gateway_packets_info = "No se pudo determinar la gateway para la captura específica."


    # 7. Generación de Reportes
    generate_reports(
        interfaces_data,
        network_devices_cache,
        arp_discovered_devices_active,
        active_connections,
        discovered_network_services,
        capture_stats, # global variable
        gateway_packets_info
    )
    
    # Finalizar
    script_duration = datetime.now() - start_time_script
    print(f"\n{COLORS['green']}[+] Análisis completo realizado en {script_duration.total_seconds():.2f} segundos.{COLORS['reset']}")
    print(f"{COLORS['cyan']}{'='*20} FIN DEL ANÁLISIS DE RED {'='*20}{COLORS['reset']}")

if __name__ == "__main__":
    main()
