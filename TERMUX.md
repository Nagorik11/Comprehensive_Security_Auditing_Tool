# Diagnóstico local en Termux sin root

`local_diagnostic.py` es un punto de entrada independiente que funciona con la biblioteca estándar de Python. Evita las dependencias ausentes de `main.py` y no importa Scapy, Nmap ni los módulos de captura. El modo único es local: no enumera equipos ni envía sondas de red.

## Preparación

Instala Termux:API desde una fuente compatible con tu Termux (firmas compatibles). Concede los permisos que Android solicite para acceder a información Wi-Fi; algunos campos requieren permiso de ubicación y ubicación habilitada. Consulta https://github.com/termux/termux-api para instalación. En Termux:

```sh
pkg install python termux-api
python local_diagnostic.py --local-only --output diagnostico-local.json
```

El comando consulta `termux-wifi-connectioninfo` con un límite de 15 segundos. Una API ausente, un error de permisos o un timeout se registran en JSON. No se requiere sudo. No se exportan MAC ni BSSID. SSID e IP pueden ser datos privados: revisa el informe antes de compartirlo.

## Datos manuales

Si no puedes instalar la API, consulta los detalles Wi-Fi de Android e introduce los datos observados. Ejemplo ilustrativo (sustituye estos valores):

```sh
python local_diagnostic.py --manual-only --ssid 'Mi red de laboratorio' --cidr 192.0.2.5/24 --gateway 192.0.2.1 --output diagnostico-manual.json
```

Se admiten `--dns DIRECCION` (repetible) y `--security TEXTO`. No se deduce la puerta de enlace de la IP. Cada campo manual se identifica como tal y los datos desconocidos quedan en null. La API no se utiliza para certificar cifrado, identidad de la red ni ausencia de intrusiones. Un SSID repetido no prueba que dos conexiones sean del mismo punto de acceso.

Los archivos de salida se crean sin sobrescribir archivos existentes. `--output` es opcional: sin él, se imprime JSON en la terminal. Un resultado parcial sigue siendo JSON válido; comprueba `api_status`, `warnings` y los campos null.

## Validación

```sh
python -m unittest -v test_local_diagnostic.py
```

Las pruebas usan respuestas simuladas de la API para validar errores y procedencia; no constituyen mediciones de una red real. Es necesaria validación en un teléfono Android para confirmar compatibilidad con su versión y permisos.

## Alcance del cambio

El flujo Linux original permanece separado. Sigue teniendo imports de `utils` ausentes en el repositorio y dependencia de privilegios. Este nuevo punto de entrada permite el diagnóstico local sin ejecutar ese flujo.
