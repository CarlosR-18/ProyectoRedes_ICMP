# Grupo 4 - ICMP y descubrimiento de rutas

Proyecto final del curso IF5000 - Redes y Comunicación de Datos.

## Tema asignado

Grupo 4: Capa de Red - ICMP y descubrimiento de rutas.

El sistema demuestra el funcionamiento de ICMP como protocolo de diagnóstico y soporte de la capa de red. Además, incluye utilidades propias para realizar pruebas de conectividad y descubrimiento de rutas, sin depender directamente de los comandos `ping` o `tracert` del sistema operativo.

## Objetivo del sistema

Implementar una herramienta que permita:

* Construir y enviar mensajes ICMP Echo Request.
* Recibir y analizar respuestas ICMP Echo Reply.
* Descubrir rutas mediante modificación del TTL.
* Analizar capturas `.pcap` con tráfico ICMP.
* Detectar una posible anomalía de tipo ICMP Flood.
* Comparar los resultados con Wireshark.

## Estructura del proyecto

```text
icmp_proyecto/
├── captures/
│   └── demo.pcap
├── docs/
│   ├── pruebas_reproducibles.md
│   └── validacion_wireshark.md
├── reports/
│   ├── demo_icmp_report.json
│   └── demo_icmp_detection_report.json
├── src/
│   ├── __init__.py
│   ├── icmp_analyzer.py
│   ├── icmp_detector.py
│   ├── icmp_utils.py
│   ├── ping.py
│   └── traceroute.py
├── tests/
│   ├── __init__.py
│   └── test_icmp_utils.py
├── .gitignore
├── README.md
└── requirements.txt
```

## Componentes principales

### 1. Utilidades ICMP

Archivo:

```text
src/icmp_utils.py
```

Incluye funciones para:

* Calcular el checksum ICMP.
* Construir paquetes ICMP Echo Request.
* Interpretar campos básicos de paquetes ICMP.
* Extraer datos ICMP desde paquetes IPv4.
* Identificar tipos ICMP comunes.

### 2. Ping propio

Archivo:

```text
src/ping.py
```

Permite enviar paquetes ICMP Echo Request construidos manualmente y medir el tiempo de respuesta.

Comando de uso:

```cmd
python -m src.ping 8.8.8.8 -c 4
```

Ejemplo de resultado:

```text
4 paquetes transmitidos, 4 recibidos
pérdida de paquetes: 0.00%
rtt min/prom/max = 70.31/71.87/73.21 ms
```

### 3. Traceroute propio

Archivo:

```text
src/traceroute.py
```

Permite descubrir los saltos de red hacia un destino mediante paquetes ICMP Echo Request y modificación manual del TTL.

Comando de uso:

```cmd
python -m src.traceroute 8.8.8.8 -m 15 -t 3
```

Ejemplo de resultado:

```text
1   192.168.0.1      Time Exceeded
3   172.16.18.25     Time Exceeded
4   172.16.10.89     Time Exceeded
...
15  8.8.8.8          Echo Reply

Destino alcanzado.
```

### 4. Analizador de capturas ICMP

Archivo:

```text
src/icmp_analyzer.py
```

Permite leer archivos `.pcap` o `.pcapng` y generar un resumen del tráfico ICMP.

Comando de uso:

```cmd
python -m src.icmp_analyzer captures/demo.pcap -o reports/demo_icmp_report.json
```

Resultado obtenido con la captura de ejemplo:

```text
Paquetes totales: 40
Paquetes ICMP: 40
Echo Request: 20
Echo Reply: 20
```

### 5. Detector de ICMP Flood

Archivo:

```text
src/icmp_detector.py
```

Detecta posibles eventos de ICMP Flood contando la cantidad de Echo Request enviados por una misma IP dentro de una ventana de tiempo.

Comando de uso:

```cmd
python -m src.icmp_detector captures/demo.pcap -w 1 -t 10 -o reports/demo_icmp_detection_report.json
```

Resultado obtenido con la captura de ejemplo:

```text
Anomalía evaluada: ICMP Flood
Paquetes totales: 40
Paquetes ICMP: 40
Echo Request: 20
Alertas generadas: 1
Fuente detectada: 192.168.0.6
```

## Instalación

Clonar el repositorio:

```cmd
git clone URL_DEL_REPOSITORIO
cd icmp_proyecto
```

Instalar dependencias:

```cmd
python -m pip install -r requirements.txt
```

Dependencias principales:

```text
scapy
pytest
```

## Ejecución de pruebas

Ejecutar pruebas unitarias:

```cmd
python -m pytest
```

Verificar sintaxis de los módulos principales:

```cmd
python -m py_compile src/icmp_utils.py
python -m py_compile src/ping.py
python -m py_compile src/traceroute.py
python -m py_compile src/icmp_analyzer.py
python -m py_compile src/icmp_detector.py
```

## Captura de ejemplo

El repositorio incluye una captura de prueba:

```text
captures/demo.pcap
```

Esta captura contiene tráfico ICMP entre el equipo local y `8.8.8.8`.

Resumen:

```text
40 paquetes ICMP
20 Echo Request
20 Echo Reply
```

## Reportes generados

El sistema genera reportes en formato JSON dentro de la carpeta `reports`.

Reportes incluidos:

```text
reports/demo_icmp_report.json
reports/demo_icmp_detection_report.json
```

## Validación con Wireshark

Los resultados del sistema se validan usando Wireshark.

Filtros utilizados:

```text
icmp
```

```text
icmp.type == 8
```

```text
icmp.type == 0
```

Comparación esperada:

| Métrica               | Sistema propio | Wireshark |
| --------------------- | -------------: | --------: |
| Paquetes ICMP totales |             40 |        40 |
| Echo Request          |             20 |        20 |
| Echo Reply            |             20 |        20 |

La validación completa se encuentra en:

```text
docs/validacion_wireshark.md
```

## Pruebas reproducibles

La documentación de pruebas reproducibles se encuentra en:

```text
docs/pruebas_reproducibles.md
```

Incluye comandos para:

* Ejecutar ping propio.
* Ejecutar traceroute propio.
* Analizar capturas ICMP.
* Detectar posible ICMP Flood.
* Validar resultados con Wireshark o tshark.

## Consideraciones en Windows

Para ejecutar herramientas que usan ICMP, raw sockets o Scapy, se recomienda abrir la terminal como administrador.

Si `tshark` no se reconoce como comando, se puede validar la captura usando Wireshark en modo gráfico.

## Anomalía analizada

La anomalía seleccionada es ICMP Flood.

Un ICMP Flood consiste en el envío excesivo de paquetes ICMP Echo Request hacia un destino o desde una misma fuente, lo que puede provocar saturación o comportamiento anómalo en la red.

El sistema usa una detección basada en umbral:

```text
Cantidad de Echo Request por IP origen dentro de una ventana temporal.
```

Configuración usada en la prueba:

```text
Ventana: 1 segundo
Umbral: 10 Echo Request
```

## Asistencia de IA

Se utilizó asistencia de IA como apoyo para:

* Redactar documentación técnica.
* Revisar posibles mejoras del sistema.
* Apoyar la construcción inicial de módulos en Python.

El grupo revisó, ejecutó, probó y ajustó el sistema durante el desarrollo.
