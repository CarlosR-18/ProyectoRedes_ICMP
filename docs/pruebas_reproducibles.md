# Pruebas reproducibles

Este documento describe los comandos utilizados para reproducir las pruebas principales del sistema del Grupo 4: ICMP y descubrimiento de rutas.

## Requisitos previos

Instalar las dependencias del proyecto:

```cmd
python -m pip install -r requirements.txt
```

En Windows, las utilidades que usan paquetes ICMP mediante raw sockets o Scapy deben ejecutarse desde una terminal con permisos de administrador.

## 1. Prueba de ping propio

Comando:

```cmd
python -m src.ping 8.8.8.8 -c 4
```

Resultado esperado:

* Envío de paquetes ICMP Echo Request.
* Recepción de paquetes ICMP Echo Reply.
* Cálculo de RTT mínimo, promedio y máximo.
* Cálculo de pérdida de paquetes.

Ejemplo de resultado obtenido:

```text
4 paquetes transmitidos, 4 recibidos
pérdida de paquetes: 0.00%
rtt min/prom/max = 70.31/71.87/73.21 ms
```

## 2. Prueba de traceroute propio

Comando:

```cmd
python -m src.traceroute 8.8.8.8 -m 15 -t 3
```

Resultado esperado:

* Visualización de saltos intermedios.
* Respuestas ICMP Time Exceeded en saltos intermedios.
* Echo Reply al llegar al destino final.
* Tiempos de respuesta por salto.

Ejemplo de resultado obtenido:

```text
1   192.168.0.1      Time Exceeded
3   172.16.18.25     Time Exceeded
4   172.16.10.89     Time Exceeded
...
15  8.8.8.8          Echo Reply

Destino alcanzado.
```

## 3. Análisis de captura ICMP

Archivo usado:

```text
captures/demo.pcap
```

Comando:

```cmd
python -m src.icmp_analyzer captures/demo.pcap -o reports/demo_icmp_report.json
```

Resultado obtenido:

```text
Paquetes totales: 40
Paquetes ICMP: 40
Porcentaje ICMP: 100.0%
Duración: 1.526633 segundos
ICMP por segundo: 26.2015
Echo Request: 20
Echo Reply: 20
```

El reporte completo se guarda en:

```text
reports/demo_icmp_report.json
```

## 4. Detección de posible ICMP Flood

Comando:

```cmd
python -m src.icmp_detector captures/demo.pcap -w 1 -t 10 -o reports/demo_icmp_detection_report.json
```

Parámetros utilizados:

* `-w 1`: ventana de análisis de 1 segundo.
* `-t 10`: umbral de 10 Echo Request por ventana.

Resultado obtenido:

```text
Anomalía evaluada: ICMP Flood
Paquetes totales: 40
Paquetes ICMP: 40
Echo Request: 20
Alertas generadas: 1
Fuente detectada: 192.168.0.6
```

El reporte completo se guarda en:

```text
reports/demo_icmp_detection_report.json
```

## 5. Validación con Wireshark/tshark

Para comparar los resultados del sistema con una herramienta estándar, se pueden usar los siguientes comandos con tshark:

```cmd
tshark -r captures/demo.pcap -Y icmp
```

```cmd
tshark -r captures/demo.pcap -Y "icmp.type == 8"
```

```cmd
tshark -r captures/demo.pcap -Y "icmp.type == 0"
```

Estos comandos permiten validar manualmente la cantidad de paquetes ICMP, Echo Request y Echo Reply detectados por el sistema.

## Nota sobre tshark en Windows

Si el comando `tshark` no se reconoce en Windows, se puede validar la captura usando Wireshark en modo gráfico.

Filtros equivalentes en Wireshark:

```text
icmp
```

```text
icmp.type == 8
```

```text
icmp.type == 0
```

Para la captura `captures/demo.pcap`, el sistema reportó:

* 40 paquetes ICMP en total.
* 20 paquetes Echo Request.
* 20 paquetes Echo Reply.

Estos valores deben coincidir con los resultados observados en Wireshark usando los filtros anteriores.
