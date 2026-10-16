# Diagnóstico local en Termux y Linux sin root

`local_diagnostic.py` es un punto de entrada independiente que funciona con la biblioteca estándar de Python. Detecta Termux o Linux automáticamente y permite elegir con `--backend termux` o `--backend linux`. Evita las dependencias ausentes de `main.py` y no importa Scapy, Nmap ni los módulos de captura. El modo único es local: no enumera equipos ni envía sondas de red.

## Computadora Linux

Descomprime el ZIP o utiliza el repositorio completo: `local_diagnostic.py` y `linux_local.py` deben estar en la misma carpeta. Se requiere Python 3 e `ip` (paquete `iproute2` en Debian/Ubuntu/Kali). `nmcli`, incluido en NetworkManager, es opcional y aporta datos adicionales de la conexión.

```sh
python3 local_diagnostic.py --local-only --output diagnostico-linux.json
```

Si hay varias interfaces (Wi-Fi, cable o VPN), comprueba el campo `interface` o elige la interfaz de tu conexión explícitamente:

```sh
python3 local_diagnostic.py --backend linux --interface wlan0 --output diagnostico-wifi.json
```

Sustituye `wlan0` por el nombre real; algunos equipos utilizan nombres como `wlp2s0`. Sin selección explícita, se prioriza la interfaz de una ruta IPv4 predeterminada según su métrica. La selección no evalúa reglas avanzadas de enrutamiento o rutas VPN divididas. El diagnóstico de puerta de enlace y DNS por interfaz está orientado a IPv4; no es una auditoría completa de IPv6.

El programa consulta `ip -j address show` e `ip -j route show default`. Con NetworkManager, lee los DNS IPv4 de la interfaz y los datos del punto de acceso marcado como activo en su caché mediante `nmcli device wifi list --rescan no`. No solicita un escaneo nuevo. Los datos de otras redes no se exportan, ni se leen claves guardadas.

La fuente de cada campo queda registrada en `sources`. `signal_percent` es la señal de NetworkManager en porcentaje y no se convierte a RSSI. El campo `security` de la caché no demuestra qué cifrado se negoció. `system_dns` es la configuración de `/etc/resolv.conf`, separada de los DNS de la interfaz; una dirección como `127.0.0.53` es un resolver local y no permite identificar los servidores upstream.

Una interfaz inexistente, la falta de herramientas o un permiso denegado generan un informe parcial o no disponible; no se pide sudo para ejecutar el diagnóstico. Los contenedores pueden bloquear Netlink aunque tengan el comando `ip`. `api_status` identifica la disponibilidad de la recolección, no la salud ni la seguridad de la red. El formato JSON es versión 2.

Referencia de comandos NetworkManager: https://networkmanager.dev/docs/api/latest/nmcli.html

## Preparación en Termux

Instala Termux:API desde una fuente compatible con tu Termux (firmas compatibles). Concede los permisos que Android solicite para acceder a información Wi-Fi; algunos campos requieren permiso de ubicación y ubicación habilitada. Consulta https://github.com/termux/termux-api para instalación. En Termux:

```sh
pkg install python termux-api
python local_diagnostic.py --local-only --output diagnostico-local.json
```

El comando consulta `termux-wifi-connectioninfo` con un límite de 15 segundos. Una API ausente, un error de permisos o un timeout se registran en JSON. No se requiere sudo. No se exportan MAC ni BSSID. SSID e IP pueden ser datos privados: revisa el informe antes de compartirlo.

## Datos manuales

Si el sistema impide consultar la configuración, introduce los datos observados en los ajustes de tu dispositivo. Ejemplo ilustrativo (sustituye estos valores):

```sh
python local_diagnostic.py --manual-only --ssid 'Mi red de laboratorio' --cidr 192.0.2.5/24 --gateway 192.0.2.1 --output diagnostico-manual.json
```

Se admiten `--dns DIRECCION` (repetible) y `--security TEXTO`. No se deduce la puerta de enlace de la IP. Cada campo manual se identifica como tal y los datos desconocidos quedan en null. La API no se utiliza para certificar cifrado, identidad de la red ni ausencia de intrusiones. Un SSID repetido no prueba que dos conexiones sean del mismo punto de acceso.

Los archivos de salida se crean sin sobrescribir archivos existentes. `--output` es opcional: sin él, se imprime JSON en la terminal. Un resultado parcial sigue siendo JSON válido; comprueba `api_status`, `warnings` y los campos null.

## Validación

```sh
python3 -m unittest -v test_local_diagnostic.py test_linux_local.py
```

Las pruebas usan respuestas simuladas de la API y de los comandos Linux para validar errores, selección de interfaz, escape de caracteres de SSID y procedencia; no constituyen mediciones de una red real. La validación local en el contenedor Linux confirma que el error de Netlink se registra sin abortar la generación de JSON. Sigue siendo necesaria validación en un teléfono Android y una computadora con Wi-Fi para confirmar compatibilidad con sus permisos y herramientas.

## Alcance del cambio

El flujo Linux original permanece separado. Sigue teniendo imports de `utils` ausentes en el repositorio y dependencia de privilegios. Este nuevo punto de entrada permite el diagnóstico local sin ejecutar ese flujo.
