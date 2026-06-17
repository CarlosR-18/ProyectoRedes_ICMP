# Validación con Wireshark

Este documento describe la validación realizada entre los resultados generados por el sistema propio del Grupo 4 y la observación de la captura mediante Wireshark.

## Archivo analizado

```text
captures/demo.pcap
```

## Objetivo de la validación

Comprobar que el analizador propio identifica correctamente los paquetes ICMP presentes en la captura, especialmente:

* Cantidad total de paquetes ICMP.
* Cantidad de paquetes ICMP Echo Request.
* Cantidad de paquetes ICMP Echo Reply.
* Direcciones IP origen y destino principales.

## Resultados del sistema propio

Comando utilizado:

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

Principales IP origen:

```text
192.168.0.6: 20
8.8.8.8: 20
```

Principales IP destino:

```text
8.8.8.8: 20
192.168.0.6: 20
```

## Validación usando Wireshark

En Wireshark se debe abrir el archivo:

```text
captures/demo.pcap
```

Luego se aplican los siguientes filtros:

### Total de paquetes ICMP

Filtro:

```text
icmp
```

Resultado esperado:

```text
40 paquetes ICMP
```

### Paquetes Echo Request

Filtro:

```text
icmp.type == 8
```

Resultado esperado:

```text
20 paquetes Echo Request
```

### Paquetes Echo Reply

Filtro:

```text
icmp.type == 0
```

Resultado esperado:

```text
20 paquetes Echo Reply
```

## Comparación de resultados

| Métrica               | Sistema propio |   Wireshark | Coincide |
| --------------------- | -------------: | ----------: | -------- |
| Paquetes ICMP totales |             40 |          40 | Sí       |
| Echo Request          |             20 |          20 | Sí       |
| Echo Reply            |             20 |          20 | Sí       |
| IP origen principal   |    192.168.0.6 | 192.168.0.6 | Sí       |
| IP destino principal  |        8.8.8.8 |     8.8.8.8 | Sí       |

## Validación alternativa con tshark

Si tshark está instalado, se pueden usar estos comandos:

```cmd
tshark -r captures/demo.pcap -Y icmp
```

```cmd
tshark -r captures/demo.pcap -Y "icmp.type == 8"
```

```cmd
tshark -r captures/demo.pcap -Y "icmp.type == 0"
```

En Windows, si `tshark` no se reconoce como comando, se puede usar Wireshark en modo gráfico con los filtros indicados anteriormente.

## Conclusión

Los resultados obtenidos por el sistema propio coinciden con la validación realizada en Wireshark. Esto indica que el analizador identifica correctamente los paquetes ICMP, sus tipos principales y las direcciones IP involucradas en la captura.
