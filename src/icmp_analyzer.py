"""
Analizador de capturas ICMP en archivos pcap.

Este módulo lee capturas de red en formato .pcap o .pcapng,
filtra paquetes ICMP y genera un resumen con métricas básicas.
"""

import argparse
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from scapy.all import ICMP, IP, rdpcap

from .icmp_utils import get_icmp_type_name


def timestamp_to_iso(timestamp: float) -> str:
    """
    Convierte un timestamp Unix a formato ISO 8601.

    Args:
        timestamp: Tiempo en formato Unix.

    Returns:
        Fecha y hora en formato ISO 8601.
    """
    return datetime.fromtimestamp(float(timestamp), tz=timezone.utc).isoformat()


def analyze_icmp_capture(pcap_path: str) -> dict[str, Any]:
    """
    Analiza una captura pcap y extrae métricas de tráfico ICMP.

    Args:
        pcap_path: Ruta del archivo .pcap o .pcapng.

    Returns:
        Diccionario con el resumen del análisis.
    """
    packets = rdpcap(pcap_path)

    total_packets = len(packets)
    icmp_packets = []

    icmp_type_counter = Counter()
    source_counter = Counter()
    destination_counter = Counter()
    conversations = Counter()

    first_timestamp = None
    last_timestamp = None

    packet_details = []

    for index, packet in enumerate(packets, start=1):
        if IP not in packet or ICMP not in packet:
            continue

        ip_layer = packet[IP]
        icmp_layer = packet[ICMP]

        timestamp = float(packet.time)

        if first_timestamp is None or timestamp < first_timestamp:
            first_timestamp = timestamp

        if last_timestamp is None or timestamp > last_timestamp:
            last_timestamp = timestamp

        icmp_type = int(icmp_layer.type)
        icmp_code = int(icmp_layer.code)
        type_name = get_icmp_type_name(icmp_type)

        source_ip = ip_layer.src
        destination_ip = ip_layer.dst

        icmp_packets.append(packet)

        icmp_type_counter[type_name] += 1
        source_counter[source_ip] += 1
        destination_counter[destination_ip] += 1
        conversations[f"{source_ip} -> {destination_ip}"] += 1

        packet_details.append(
            {
                "packet_number": index,
                "timestamp": timestamp_to_iso(timestamp),
                "source_ip": source_ip,
                "destination_ip": destination_ip,
                "icmp_type": icmp_type,
                "icmp_code": icmp_code,
                "icmp_type_name": type_name,
                "ip_ttl": int(ip_layer.ttl),
                "ip_length": int(ip_layer.len) if ip_layer.len is not None else None,
            }
        )

    icmp_count = len(icmp_packets)

    duration_seconds = 0.0
    if first_timestamp is not None and last_timestamp is not None:
        duration_seconds = max(0.0, last_timestamp - first_timestamp)

    packets_per_second = 0.0
    if duration_seconds > 0:
        packets_per_second = icmp_count / duration_seconds

    report = {
        "capture_file": str(pcap_path),
        "total_packets": total_packets,
        "icmp_packets": icmp_count,
        "icmp_percentage": round((icmp_count / total_packets) * 100, 2)
        if total_packets > 0
        else 0,
        "first_packet_time": timestamp_to_iso(first_timestamp)
        if first_timestamp is not None
        else None,
        "last_packet_time": timestamp_to_iso(last_timestamp)
        if last_timestamp is not None
        else None,
        "duration_seconds": round(duration_seconds, 6),
        "icmp_packets_per_second": round(packets_per_second, 4),
        "icmp_types": dict(icmp_type_counter),
        "top_sources": dict(source_counter.most_common(10)),
        "top_destinations": dict(destination_counter.most_common(10)),
        "conversations": dict(conversations.most_common(20)),
        "packet_details": packet_details,
    }

    return report


def save_json_report(report: dict[str, Any], output_path: str) -> None:
    """
    Guarda el reporte en formato JSON.

    Args:
        report: Diccionario con los resultados del análisis.
        output_path: Ruta donde se guardará el archivo JSON.
    """
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)

    with output_file.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=4, ensure_ascii=False)


def print_summary(report: dict[str, Any]) -> None:
    """
    Imprime un resumen del análisis en consola.

    Args:
        report: Diccionario con los resultados del análisis.
    """
    print("\n--- Resumen de análisis ICMP ---")
    print(f"Archivo analizado: {report['capture_file']}")
    print(f"Paquetes totales: {report['total_packets']}")
    print(f"Paquetes ICMP: {report['icmp_packets']}")
    print(f"Porcentaje ICMP: {report['icmp_percentage']}%")
    print(f"Duración: {report['duration_seconds']} segundos")
    print(f"ICMP por segundo: {report['icmp_packets_per_second']}")

    print("\nTipos ICMP encontrados:")
    if report["icmp_types"]:
        for icmp_type, amount in report["icmp_types"].items():
            print(f"- {icmp_type}: {amount}")
    else:
        print("- No se encontraron paquetes ICMP.")

    print("\nPrincipales IP origen:")
    for source_ip, amount in report["top_sources"].items():
        print(f"- {source_ip}: {amount}")

    print("\nPrincipales IP destino:")
    for destination_ip, amount in report["top_destinations"].items():
        print(f"- {destination_ip}: {amount}")


def main() -> None:
    """
    Punto de entrada principal del analizador.
    """
    parser = argparse.ArgumentParser(
        description="Analizador de tráfico ICMP en archivos pcap o pcapng."
    )

    parser.add_argument(
        "pcap_file",
        help="Ruta del archivo .pcap o .pcapng a analizar."
    )

    parser.add_argument(
        "-o",
        "--output",
        default=None,
        help="Ruta del archivo JSON de salida."
    )

    args = parser.parse_args()

    pcap_path = Path(args.pcap_file)

    if not pcap_path.exists():
        print(f"Error: no existe el archivo {pcap_path}")
        return

    output_path = args.output

    if output_path is None:
        output_path = f"reports/{pcap_path.stem}_icmp_report.json"

    report = analyze_icmp_capture(str(pcap_path))
    save_json_report(report, output_path)
    print_summary(report)

    print(f"\nReporte guardado en: {output_path}")


if __name__ == "__main__":
    main()