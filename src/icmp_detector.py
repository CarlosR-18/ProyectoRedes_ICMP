"""
Detector de anomalías ICMP.

Este módulo analiza capturas .pcap o .pcapng y detecta posibles
comportamientos anómalos relacionados con ICMP, especialmente
posibles eventos de ICMP Flood basados en la cantidad de Echo Request
por dirección IP origen dentro de una ventana de tiempo.
"""

import argparse
import json
from collections import Counter, defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from scapy.all import ICMP, IP, rdpcap

from .icmp_utils import get_icmp_type_name


def timestamp_to_iso(timestamp: float) -> str:
    """
    Convierte un timestamp Unix a formato ISO 8601.

    Args:
        timestamp: Tiempo Unix.

    Returns:
        Fecha y hora en formato ISO 8601.
    """
    return datetime.fromtimestamp(float(timestamp), tz=timezone.utc).isoformat()


def detect_icmp_flood(
    pcap_path: str,
    window_seconds: float,
    threshold: int,
    expected_attacker: str | None = None
) -> dict[str, Any]:
    """
    Detecta posibles eventos de ICMP Flood en una captura.

    La detección se basa en contar cuántos paquetes ICMP Echo Request
    envía una misma IP origen dentro de una ventana temporal.

    Args:
        pcap_path: Ruta del archivo .pcap o .pcapng.
        window_seconds: Tamaño de la ventana temporal en segundos.
        threshold: Cantidad máxima permitida de Echo Request por ventana.
        expected_attacker: IP esperada como atacante para calcular métricas simples.

    Returns:
        Diccionario con resultados, alertas y métricas.
    """
    packets = rdpcap(pcap_path)

    total_packets = len(packets)
    total_icmp_packets = 0
    total_echo_requests = 0

    echo_requests_by_source = Counter()
    icmp_types = Counter()

    windows_by_source = defaultdict(deque)
    alert_active_by_source = defaultdict(bool)

    alerts = []

    first_timestamp = None
    last_timestamp = None
    first_detection_time = None

    for packet_number, packet in enumerate(packets, start=1):
        if IP not in packet or ICMP not in packet:
            continue

        total_icmp_packets += 1

        ip_layer = packet[IP]
        icmp_layer = packet[ICMP]

        timestamp = float(packet.time)
        source_ip = ip_layer.src
        destination_ip = ip_layer.dst
        icmp_type = int(icmp_layer.type)
        icmp_code = int(icmp_layer.code)
        type_name = get_icmp_type_name(icmp_type)

        icmp_types[type_name] += 1

        if first_timestamp is None or timestamp < first_timestamp:
            first_timestamp = timestamp

        if last_timestamp is None or timestamp > last_timestamp:
            last_timestamp = timestamp

        if icmp_type != 8:
            continue

        total_echo_requests += 1
        echo_requests_by_source[source_ip] += 1

        source_window = windows_by_source[source_ip]
        source_window.append(timestamp)

        while source_window and timestamp - source_window[0] > window_seconds:
            source_window.popleft()

        current_count = len(source_window)

        if current_count >= threshold and not alert_active_by_source[source_ip]:
            rate = current_count / window_seconds

            alert = {
                "packet_number": packet_number,
                "timestamp": timestamp_to_iso(timestamp),
                "source_ip": source_ip,
                "destination_ip": destination_ip,
                "icmp_type": icmp_type,
                "icmp_code": icmp_code,
                "icmp_type_name": type_name,
                "window_seconds": window_seconds,
                "echo_requests_in_window": current_count,
                "threshold": threshold,
                "estimated_rate_per_second": round(rate, 4),
                "description": (
                    f"Posible ICMP Flood: {source_ip} envió "
                    f"{current_count} Echo Request en {window_seconds} segundos."
                )
            }

            alerts.append(alert)
            alert_active_by_source[source_ip] = True

            if first_detection_time is None:
                first_detection_time = timestamp

        if current_count < threshold:
            alert_active_by_source[source_ip] = False

    duration_seconds = 0.0

    if first_timestamp is not None and last_timestamp is not None:
        duration_seconds = max(0.0, last_timestamp - first_timestamp)

    detected_sources = sorted({alert["source_ip"] for alert in alerts})

    true_positive = None
    false_positive = None
    false_negative = None

    if expected_attacker is not None:
        true_positive = expected_attacker in detected_sources
        false_positive = len(
            [source for source in detected_sources if source != expected_attacker]
        )
        false_negative = not true_positive

    report = {
        "capture_file": str(pcap_path),
        "detection_name": "ICMP Flood",
        "detection_method": (
            "Conteo de paquetes ICMP Echo Request por IP origen "
            "dentro de una ventana temporal."
        ),
        "configuration": {
            "window_seconds": window_seconds,
            "threshold_echo_requests": threshold,
            "expected_attacker": expected_attacker
        },
        "summary": {
            "total_packets": total_packets,
            "total_icmp_packets": total_icmp_packets,
            "total_echo_requests": total_echo_requests,
            "duration_seconds": round(duration_seconds, 6),
            "total_alerts": len(alerts),
            "detected_sources": detected_sources,
            "icmp_types": dict(icmp_types),
            "echo_requests_by_source": dict(echo_requests_by_source.most_common(20))
        },
        "metrics": {
            "true_positive": true_positive,
            "false_positive_count": false_positive,
            "false_negative": false_negative,
            "first_detection_time": timestamp_to_iso(first_detection_time)
            if first_detection_time is not None
            else None
        },
        "alerts": alerts
    }

    return report


def save_json_report(report: dict[str, Any], output_path: str) -> None:
    """
    Guarda el reporte de detección en formato JSON.

    Args:
        report: Resultados de detección.
        output_path: Ruta del archivo JSON.
    """
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)

    with output_file.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=4, ensure_ascii=False)


def print_detection_summary(report: dict[str, Any]) -> None:
    """
    Imprime un resumen del resultado de detección.

    Args:
        report: Reporte generado por el detector.
    """
    print("\n--- Detección de anomalía ICMP ---")
    print(f"Archivo analizado: {report['capture_file']}")
    print(f"Anomalía evaluada: {report['detection_name']}")
    print(f"Ventana: {report['configuration']['window_seconds']} segundos")
    print(f"Umbral: {report['configuration']['threshold_echo_requests']} Echo Request")

    summary = report["summary"]

    print(f"\nPaquetes totales: {summary['total_packets']}")
    print(f"Paquetes ICMP: {summary['total_icmp_packets']}")
    print(f"Echo Request: {summary['total_echo_requests']}")
    print(f"Alertas generadas: {summary['total_alerts']}")

    print("\nFuentes detectadas:")
    if summary["detected_sources"]:
        for source in summary["detected_sources"]:
            print(f"- {source}")
    else:
        print("- No se detectaron fuentes anómalas.")

    print("\nEcho Request por IP origen:")
    for source_ip, amount in summary["echo_requests_by_source"].items():
        print(f"- {source_ip}: {amount}")

    metrics = report["metrics"]

    if metrics["true_positive"] is not None:
        print("\nMétricas contra IP esperada:")
        print(f"Verdadero positivo: {metrics['true_positive']}")
        print(f"Falsos positivos: {metrics['false_positive_count']}")
        print(f"Falso negativo: {metrics['false_negative']}")


def main() -> None:
    """
    Punto de entrada principal del detector.
    """
    parser = argparse.ArgumentParser(
        description="Detector de posible ICMP Flood en capturas pcap o pcapng."
    )

    parser.add_argument(
        "pcap_file",
        help="Ruta del archivo .pcap o .pcapng a analizar."
    )

    parser.add_argument(
        "-w",
        "--window",
        type=float,
        default=1.0,
        help="Ventana de tiempo en segundos. Por defecto: 1."
    )

    parser.add_argument(
        "-t",
        "--threshold",
        type=int,
        default=10,
        help="Cantidad de Echo Request permitidos por ventana. Por defecto: 10."
    )

    parser.add_argument(
        "-a",
        "--expected-attacker",
        default=None,
        help="IP esperada como origen anómalo para calcular métricas simples."
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
        output_path = f"reports/{pcap_path.stem}_icmp_detection_report.json"

    report = detect_icmp_flood(
        pcap_path=str(pcap_path),
        window_seconds=args.window,
        threshold=args.threshold,
        expected_attacker=args.expected_attacker
    )

    save_json_report(report, output_path)
    print_detection_summary(report)

    print(f"\nReporte guardado en: {output_path}")


if __name__ == "__main__":
    main()