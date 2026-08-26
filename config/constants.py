"""
Constantes y configuración global del analizador de red.
"""
import os
from datetime import datetime

# Colores ANSI para salida en consola
COLORS = {
    "green":  "\033[92m",
    "red":    "\033[91m",
    "yellow": "\033[93m",
    "cyan":   "\033[96m",
    "alert":  "\033[97;41m",
    "reset":  "\033[0m",
}

# Directorio de salida y timestamp
TIMESTAMP  = datetime.now().strftime("%Y%m%d_%H%M%S")
OUTPUT_DIR = "network_analysis_reports"
os.makedirs(OUTPUT_DIR, exist_ok=True)

OUTPUT_FILES = {
    "txt":               os.path.join(OUTPUT_DIR, f"network_analysis_report_{TIMESTAMP}.txt"),
    "connections_csv":   os.path.join(OUTPUT_DIR, f"active_connections_{TIMESTAMP}.csv"),
    "capture_stats_json":os.path.join(OUTPUT_DIR, f"capture_stats_{TIMESTAMP}.json"),
    "interfaces_json":   os.path.join(OUTPUT_DIR, f"network_interfaces_{TIMESTAMP}.json"),
    "devices_csv":       os.path.join(OUTPUT_DIR, f"network_devices_{TIMESTAMP}.csv"),
    "services_csv":      os.path.join(OUTPUT_DIR, f"discovered_services_{TIMESTAMP}.csv"),
}

# Puertos considerados seguros
SAFE_PORTS = {22, 80, 443, 8080, 53, 123, 993, 995}

# Concurrencia
MAX_WORKERS = 10

# Duración por defecto de la captura de paquetes (segundos)
CAPTURE_DURATION = 30

# Ruta del archivo OUI (fabricantes MAC)
OUI_FILE_PATH = os.path.expanduser("~/.local/share/ieee-oui.txt")
