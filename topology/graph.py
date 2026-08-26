"""
Construcción y guardado del grafo de topología de red con NetworkX / Matplotlib.
"""
import os
import sys
import os

ROOT_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..")
)

sys.path.append(ROOT_DIR)
import matplotlib.pyplot as plt
import networkx as nx

from config.constants import COLORS


def build_network_graph(
    local_ip: str,
    network_devices: list,
    arp_devices: list,
    active_conns: list,
    services: list,
    captured_stats: dict,
) -> nx.Graph:
    """
    Construye un grafo no dirigido con los datos recolectados:
      - Dispositivos de caché ARP
      - Dispositivos descubiertos activamente
      - Conexiones activas (ss)
      - Servicios detectados (nmap)
      - Tráfico observado (capture_stats)
    """
    G = nx.Graph()

    if local_ip:
        G.add_node(local_ip, role="local", label=local_ip)

    # Caché ARP
    for d in network_devices or []:
        ip = d.get("ip")
        if ip and ip != "N/A":
            G.add_node(ip, mac=d.get("mac"), manufacturer=d.get("manufacturer"), role="device")
            if local_ip:
                G.add_edge(local_ip, ip, relation="arp_cache")

    # ARP activo
    for d in arp_devices or []:
        ip = d.get("ip")
        if ip:
            if not G.has_node(ip):
                G.add_node(ip, mac=d.get("mac"), manufacturer=d.get("manufacturer"), role="device")
            if local_ip:
                G.add_edge(local_ip, ip, relation="arp_scan")

    # Conexiones activas
    for c in active_conns or []:
        local  = c.get("local_ip")
        remote = c.get("remote_ip")
        if not local or not remote or remote in ("*", "N/A"):
            continue
        for endpoint in (local, remote):
            if not G.has_node(endpoint):
                G.add_node(endpoint, role="endpoint")
        attrs = {
            "proto":       c.get("proto"),
            "local_port":  c.get("local_port"),
            "remote_port": c.get("remote_port"),
            "process":     c.get("process"),
        }
        if G.has_edge(local, remote):
            G[local][remote].setdefault("conns", []).append(attrs)
        else:
            G.add_edge(local, remote, conns=[attrs], relation="active_conn")

    # Servicios (nmap)
    for s in services or []:
        ip   = s.get("ip")
        port = s.get("port")
        if not ip:
            continue
        if not G.has_node(ip):
            G.add_node(ip, role="host")
        if local_ip:
            meta = {"service_port": port, "service": s.get("service_name")}
            if G.has_edge(local_ip, ip):
                G[local_ip][ip].setdefault("services", []).append(meta)
            else:
                G.add_edge(local_ip, ip, services=[meta], relation="service")

    # Tráfico observado
    for ip, data in (captured_stats or {}).get("traffic_by_ip", {}).items():
        if not ip:
            continue
        if not G.has_node(ip):
            G.add_node(ip, role="observed")
        if local_ip:
            weight = data.get("total_bytes", 0)
            if G.has_edge(local_ip, ip):
                G[local_ip][ip]["traffic_bytes"] = G[local_ip][ip].get("traffic_bytes", 0) + weight
            else:
                G.add_edge(local_ip, ip, traffic_bytes=weight, relation="traffic")

    return G


def save_topology_graph(G: nx.Graph, output_dir: str, timestamp: str) -> tuple[str | None, str | None]:
    """
    Guarda el grafo como imagen PNG y como archivo GraphML.
    Devuelve (png_path, graphml_path) o (None, None) ante error.
    """
    os.makedirs(output_dir, exist_ok=True)
    png_path     = os.path.join(output_dir, f"network_topology_{timestamp}.png")
    graphml_path = os.path.join(output_dir, f"network_topology_{timestamp}.graphml")

    try:
        plt.figure(figsize=(12, 9))

        try:
            pos = nx.spring_layout(G, k=0.5, iterations=50)
        except Exception:
            pos = nx.spring_layout(G)

        roles       = nx.get_node_attributes(G, "role")
        color_map   = {
            "local":    "#1f78b4",
            "device":   "#33a02c",
            "host":     "#ff7f00",
            "endpoint": "#6a3d9a",
            "observed": "#b15928",
        }
        node_colors = [color_map.get(roles.get(n, ""), "#bbbbbb") for n in G.nodes()]
        node_sizes  = [300 + G.degree(n) * 150 for n in G.nodes()]

        nx.draw_networkx_nodes(G, pos, node_color=node_colors, node_size=node_sizes, alpha=0.9)
        nx.draw_networkx_edges(G, pos, alpha=0.6)
        nx.draw_networkx_labels(G, pos, {n: n for n in G.nodes()}, font_size=8)

        plt.axis("off")
        plt.tight_layout()
        plt.savefig(png_path, dpi=200)
        plt.close()

        nx.write_graphml(G, graphml_path)

        print(f"{COLORS['green']}[+] Topología PNG guardada: {png_path}{COLORS['reset']}")
        print(f"{COLORS['green']}[+] GraphML guardado:       {graphml_path}{COLORS['reset']}")
        return png_path, graphml_path

    except Exception as e:
        print(f"{COLORS['red']}[-] Error guardando topología: {e}{COLORS['reset']}")
        return None, None
