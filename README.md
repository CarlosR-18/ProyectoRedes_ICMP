Grupo 4 - ICMP y descubrimiento de rutas

Proyecto final del curso IF5000 - Redes y Comunicación de Datos.

## Tema asignado

Grupo 4: Capa de Red - ICMP y descubrimiento de rutas.

El sistema tiene como objetivo demostrar el funcionamiento de ICMP como protocolo de diagnóstico y soporte de la capa de red. Además, incluirá una implementación propia de utilidades como ping y traceroute, sin depender directamente de los comandos del sistema operativo.

## Componentes principales

- Implementación propia de ping usando mensajes ICMP Echo Request y Echo Reply.
- Implementación propia de traceroute mediante control del TTL.
- Captura y análisis de tráfico ICMP.
- Detección de una condición anómala relacionada con ICMP.
- Validación de resultados mediante Wireshark o tshark.

## Estructura del proyecto

```text
grupo4-icmp/
├── src/
│   └── Código fuente del sistema
├── tests/
│   └── Pruebas unitarias
├── captures/
│   └── Capturas pcap de ejemplo
├── reports/
│   └── Reportes generados por el sistema
├── docs/
│   └── Documentación adicional
├── README.md
├── requirements.txt
└── .gitignore