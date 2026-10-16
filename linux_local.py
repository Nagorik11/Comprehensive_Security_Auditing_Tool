"""Consulta configuración local de Linux sin root ni sondas de red."""
import ipaddress
import json
import os
from pathlib import Path
import shutil
import subprocess


def command_output(args, timeout=8):
    command = shutil.which(args[0])
    if not command:
        return None, f"No está instalado {args[0]}."
    try:
        result = subprocess.run([command, *args[1:]], capture_output=True,
                                text=True, timeout=timeout, check=False,
                                env={**os.environ, "LC_ALL": "C"})
    except subprocess.TimeoutExpired:
        return None, f"{args[0]} excedió el tiempo de espera."
    except OSError:
        return None, f"No se pudo ejecutar {args[0]}."
    if result.returncode:
        return None, f"{args[0]} devolvió un error; puede faltar acceso a la configuración local."
    return result.stdout, None


def json_list(args):
    output, error = command_output(args)
    if error:
        return [], error
    try:
        value = json.loads(output)
    except (ValueError, TypeError):
        return [], f"{args[0]} no devolvió JSON válido."
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        return [], f"{args[0]} devolvió un formato inesperado."
    return value, None


def split_nmcli(line):
    """Separa campos de nmcli -t --escape yes, preservando : y \\ en SSID."""
    fields, current, escaped = [], [], False
    for char in line:
        if escaped:
            current.append(char)
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == ":":
            fields.append("".join(current))
            current = []
        else:
            current.append(char)
    if escaped:
        current.append("\\")
    return fields + ["".join(current)]


def valid_ip(value):
    try:
        return str(ipaddress.ip_address(value))
    except (ValueError, TypeError):
        return None


def system_dns():
    """Lee resolv.conf: es configuración del sistema, no de una interfaz."""
    try:
        lines = Path("/etc/resolv.conf").read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    result = []
    for line in lines:
        fields = line.split()
        if len(fields) >= 2 and fields[0] == "nameserver":
            address = valid_ip(fields[1])
            if address and address not in result:
                result.append(address)
    return result


def read_linux(interface=None):
    addresses, error = json_list(["ip", "-j", "address", "show"])
    if error:
        return {}, "unavailable", error
    # Explicit interface selection works even without a default route.
    candidates = [item for item in addresses
                  if item.get("ifname") != "lo" and
                  item.get("operstate", "UNKNOWN") in ("UP", "UNKNOWN") and
                  item.get("addr_info")]
    if interface:
        candidates = [item for item in candidates if item.get("ifname") == interface]
    if not candidates:
        return {}, "unavailable", "No se encontró una interfaz activa con direcciones para la selección indicada."
    routes, route_error = json_list(["ip", "-j", "route", "show", "default"])
    warnings = [route_error] if route_error else []
    routes = sorted(routes, key=lambda item: item.get("metric", 0))
    choices = {item.get("ifname"): item for item in candidates}
    selected = next((choices[route["dev"]] for route in routes
                     if route.get("dev") in choices), candidates[0])
    name = selected["ifname"]
    if len(candidates) > 1 and not interface:
        warnings.append("Hay varias interfaces; se priorizó una ruta IPv4 predeterminada. Usa --interface para elegir explícitamente; una VPN puede cambiar la ruta efectiva.")
    entries = [item for item in selected["addr_info"]
               if isinstance(item, dict) and item.get("scope") == "global"]
    entries.sort(key=lambda item: item.get("family") != "inet")
    data, sources = {"interface": name}, {"interface": "ip"}
    for entry in entries:
        try:
            parsed = ipaddress.ip_interface(f"{entry['local']}/{entry['prefixlen']}")
        except (KeyError, ValueError):
            continue
        data.update(ip=str(parsed.ip), cidr=str(parsed))
        sources.update(ip="ip", cidr="ip")
        break
    gateway = next((valid_ip(route.get("gateway")) for route in routes
                    if route.get("dev") == name and valid_ip(route.get("gateway"))), None)
    if gateway:
        data["gateway"], sources["gateway"] = gateway, "ip"

    if shutil.which("nmcli"):
        output, nm_error = command_output([
            "nmcli", "-t", "--escape", "yes", "-f",
            "GENERAL.TYPE,IP4.GATEWAY,IP4.DNS", "device", "show", name])
        if nm_error:
            warnings.append(nm_error)
        else:
            dns, device_type = [], None
            for line in output.splitlines():
                fields = split_nmcli(line)
                if len(fields) != 2:
                    continue
                key, value = fields
                if key == "GENERAL.TYPE":
                    device_type = value
                elif key == "IP4.GATEWAY" and not data.get("gateway") and valid_ip(value):
                    data["gateway"], sources["gateway"] = valid_ip(value), "nmcli"
                elif key.startswith("IP4.DNS[") and valid_ip(value):
                    dns.append(valid_ip(value))
            if dns:
                data["dns"], sources["dns"] = list(dict.fromkeys(dns)), "nmcli"
            if device_type == "wifi":
                cached, cache_error = command_output([
                    "nmcli", "-t", "--escape", "yes", "-f",
                    "IN-USE,SSID,SIGNAL,SECURITY,FREQ", "device", "wifi", "list",
                    "ifname", name, "--rescan", "no"])
                if cache_error:
                    warnings.append(cache_error)
                else:
                    active = [split_nmcli(line) for line in cached.splitlines()]
                    active = [fields for fields in active if len(fields) == 5 and fields[0] == "*"]
                    if active:
                        _, ssid, signal, security, frequency = active[0]
                        if ssid:
                            data["ssid"], sources["ssid"] = ssid, "nmcli-cache"
                        if security and security != "--":
                            data["security"], sources["security"] = security, "nmcli-cache"
                        try:
                            percent = int(signal)
                            if 0 <= percent <= 100:
                                data["signal_percent"], sources["signal_percent"] = percent, "nmcli-cache"
                        except ValueError:
                            pass
                        try:
                            data["frequency_mhz"] = int(frequency.split()[0])
                            sources["frequency_mhz"] = "nmcli-cache"
                        except (ValueError, IndexError):
                            pass
                        warnings.append("SSID, señal y seguridad proceden de la caché de NetworkManager; no se verifica el cifrado negociado.")
                    else:
                        warnings.append("La caché de NetworkManager no identifica el punto de acceso activo.")
    else:
        warnings.append("nmcli no está disponible; faltan datos Wi-Fi y DNS por interfaz.")
    resolver = system_dns()
    if resolver:
        data["system_dns"], sources["system_dns"] = resolver, "resolv.conf"
    if not data.get("ip"):
        warnings.append("No se encontró una dirección global utilizable en la interfaz seleccionada.")
    data["_sources"], data["_warnings"] = sources, warnings
    return data, "partial" if warnings else "ok", None
