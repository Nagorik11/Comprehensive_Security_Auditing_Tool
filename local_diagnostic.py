#!/usr/bin/env python3
"""Diagnóstico local sin root, escaneo, captura ni dependencias Python externas."""
import argparse
import ipaddress
import json
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path


def read_wifi(timeout=15):
    """Consulta solo la conexión actual mediante la API oficial de Android."""
    command = shutil.which("termux-wifi-connectioninfo")
    if not command:
        return {}, "unavailable", "Falta termux-wifi-connectioninfo; instala termux-api y la app compatible Termux:API."
    try:
        result = subprocess.run([command], capture_output=True, text=True,
                                timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return {}, "timeout", "Termux:API no respondió; revisa la app complementaria y sus permisos."
    except OSError:
        return {}, "error", "No se pudo ejecutar Termux:API."
    if result.returncode:
        return {}, "error", "Termux:API devolvió un error; revisa sus permisos."
    try:
        data = json.loads(result.stdout)
    except (ValueError, TypeError):
        return {}, "error", "Termux:API no devolvió JSON válido."
    if not isinstance(data, dict) or "error" in data:
        return {}, "error", "Termux:API no entregó datos de conexión utilizables."
    return data, "ok", None


def build_report(data, status, message, manual=None):
    manual = manual or {}
    values, sources = {}, {}
    for key in ("ssid", "ip", "frequency_mhz", "rssi", "link_speed_mbps"):
        value = data.get(key)
        if value is None or value in ("", "<unknown ssid>", "0.0.0.0"):
            continue
        if key == "ip":
            try:
                value = str(ipaddress.ip_address(value))
            except ValueError:
                continue
        values[key], sources[key] = value, "termux-api"
    for key in ("ssid", "cidr", "gateway", "dns", "security"):
        if manual.get(key) is not None:
            values[key], sources[key] = manual[key], "manual"
    warnings = [message] if message else []
    if "cidr" in values:
        interface = ipaddress.ip_interface(values["cidr"])
        values["network"] = str(interface.network)
        sources["network"] = "derived_from_manual_cidr"
        if values.get("ip") and values["ip"] != str(interface.ip):
            warnings.append("La IP de Termux:API difiere del CIDR manual; verifica que correspondan a la misma conexión.")
        if "ip" not in values:
            values["ip"], sources["ip"] = str(interface.ip), "manual"
    for key in ("ssid", "ip", "cidr", "network", "gateway", "dns", "security",
                "frequency_mhz", "rssi", "link_speed_mbps"):
        values.setdefault(key, None)
    findings = []
    if values["security"] and "TKIP" in values["security"].upper():
        findings.append({"finding": "TKIP declarado: revisar configuración WPA2-AES/WPA3 con el administrador.",
                         "source": "manual", "verified_by_radio": False})
    return {"schema_version": 1, "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "scope": "local_device_only", "api_status": status,
            "connection": values, "sources": sources, "warnings": warnings,
            "findings": findings,
            "limitations": ["No se prueba aislamiento, intrusión, servicios ni configuración del router.",
                            "Los datos manuales no son mediciones; null indica dato no disponible.",
                            "SSID y BSSID no prueban la identidad del propietario de una red."]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--local-only", action="store_true", help="Modo único; se usa siempre.")
    parser.add_argument("--manual-only", action="store_true", help="No consultar Termux:API.")
    parser.add_argument("--ssid")
    parser.add_argument("--cidr", help="IP/máscara de TU teléfono, por ejemplo 192.0.2.5/24")
    parser.add_argument("--gateway")
    parser.add_argument("--dns", action="append", help="Repetible para varios DNS")
    parser.add_argument("--security", help="Texto observado en Ajustes; no se verifica por radio")
    parser.add_argument("--output", type=Path, help="Archivo JSON nuevo; no sobrescribe archivos")
    args = parser.parse_args()
    manual = {key: getattr(args, key) for key in ("ssid", "cidr", "gateway", "dns", "security")}
    try:
        if args.cidr:
            manual["cidr"] = str(ipaddress.ip_interface(args.cidr))
        if args.gateway:
            manual["gateway"] = str(ipaddress.ip_address(args.gateway))
        if args.dns:
            manual["dns"] = [str(ipaddress.ip_address(item)) for item in args.dns]
    except ValueError as exc:
        parser.error(str(exc))
    data, status, message = ({}, "not_requested", None) if args.manual_only else read_wifi()
    report = build_report(data, status, message, manual)
    output = json.dumps(report, ensure_ascii=False, indent=2)
    if args.output:
        try:
            with args.output.open("x", encoding="utf-8") as handle:
                handle.write(output + "\n")
        except OSError as exc:
            parser.error(str(exc))
    print(output)


if __name__ == "__main__":
    main()
