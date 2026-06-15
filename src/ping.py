"""
Implementación propia de ping usando ICMP Echo Request y Echo Reply.

Este módulo construye paquetes ICMP manualmente, los envía mediante
raw sockets y calcula tiempos de respuesta sin usar el comando ping
del sistema operativo.
"""

import argparse
import os
import select
import socket
import statistics
import struct
import time
from typing import Optional

from .icmp_utils import (
    ICMP_ECHO_REPLY,
    build_echo_request,
    extract_icmp_from_ipv4_packet,
    get_icmp_type_name,
    parse_icmp_packet,
)


def extract_ttl_from_ipv4_packet(packet: bytes) -> Optional[int]:
    """
    Extrae el valor TTL desde un paquete IPv4 completo.

    Args:
        packet: Paquete recibido desde el socket raw.

    Returns:
        TTL si el paquete contiene encabezado IPv4, en caso contrario None.
    """
    if len(packet) < 20:
        return None

    version = packet[0] >> 4

    if version != 4:
        return None

    return packet[8]


def receive_echo_reply(
    sock: socket.socket,
    identifier: int,
    sequence: int,
    timeout: float
) -> tuple[Optional[str], Optional[int], Optional[float], Optional[str]]:
    """
    Espera una respuesta ICMP para un paquete Echo Request enviado.

    Args:
        sock: Socket raw usado para recibir respuestas ICMP.
        identifier: Identificador esperado del paquete ICMP.
        sequence: Número de secuencia esperado.
        timeout: Tiempo máximo de espera en segundos.

    Returns:
        Tupla con IP origen, TTL, RTT en milisegundos y nombre del tipo ICMP.
    """
    start_time = time.perf_counter()
    remaining_time = timeout

    while remaining_time > 0:
        ready = select.select([sock], [], [], remaining_time)

        if not ready[0]:
            return None, None, None, None

        receive_time = time.perf_counter()
        packet, address = sock.recvfrom(65535)

        ttl = extract_ttl_from_ipv4_packet(packet)
        icmp_data = extract_icmp_from_ipv4_packet(packet)
        parsed = parse_icmp_packet(icmp_data)

        icmp_type = parsed["type"]
        type_name = get_icmp_type_name(icmp_type)

        if (
            icmp_type == ICMP_ECHO_REPLY
            and parsed["identifier"] == identifier
            and parsed["sequence"] == sequence
        ):
            rtt_ms = (receive_time - start_time) * 1000
            return address[0], ttl, rtt_ms, type_name

        elapsed = receive_time - start_time
        remaining_time = timeout - elapsed

    return None, None, None, None


def run_ping(destination: str, count: int, timeout: float, interval: float) -> None:
    """
    Ejecuta la utilidad ping propia.

    Args:
        destination: Dominio o dirección IP destino.
        count: Cantidad de paquetes ICMP a enviar.
        timeout: Tiempo máximo de espera por respuesta.
        interval: Pausa entre paquetes enviados.
    """
    try:
        destination_ip = socket.gethostbyname(destination)
    except socket.gaierror:
        print(f"No se pudo resolver el destino: {destination}")
        return

    identifier = os.getpid() & 0xFFFF
    rtts = []
    transmitted = 0
    received = 0

    print(f"PING propio a {destination} ({destination_ip})")
    print("Usando ICMP Echo Request construido manualmente.\n")

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as sock:
            for sequence in range(1, count + 1):
                payload = struct.pack("!d", time.time()) + b" Grupo4-ICMP-PING"
                packet = build_echo_request(identifier, sequence, payload)

                transmitted += 1
                sock.sendto(packet, (destination_ip, 0))

                source_ip, ttl, rtt_ms, type_name = receive_echo_reply(
                    sock,
                    identifier,
                    sequence,
                    timeout
                )

                if rtt_ms is None:
                    print(f"seq={sequence} tiempo agotado")
                else:
                    received += 1
                    rtts.append(rtt_ms)
                    ttl_text = ttl if ttl is not None else "N/D"
                    print(
                        f"respuesta desde {source_ip}: "
                        f"icmp_seq={sequence} ttl={ttl_text} "
                        f"tiempo={rtt_ms:.2f} ms tipo={type_name}"
                    )

                if sequence < count:
                    time.sleep(interval)

    except PermissionError:
        print("Error: se requieren permisos de administrador para usar raw sockets.")
        print("Ejecutá la terminal como administrador e intentá de nuevo.")
        return
    except KeyboardInterrupt:
        print("\nEjecución interrumpida por el usuario.")
    except OSError as error:
        print(f"Error de red o socket: {error}")
        return

    print("\n--- Estadísticas ping propio ---")

    packet_loss = ((transmitted - received) / transmitted) * 100 if transmitted > 0 else 0

    print(f"{transmitted} paquetes transmitidos, {received} recibidos")
    print(f"pérdida de paquetes: {packet_loss:.2f}%")

    if rtts:
        print(
            "rtt min/prom/max = "
            f"{min(rtts):.2f}/"
            f"{statistics.mean(rtts):.2f}/"
            f"{max(rtts):.2f} ms"
        )


def main() -> None:
  
    parser = argparse.ArgumentParser(
        description="Ping propio usando paquetes ICMP construidos manualmente."
    )

    parser.add_argument(
        "destination",
        help="Dirección IP o dominio destino."
    )

    parser.add_argument(
        "-c",
        "--count",
        type=int,
        default=4,
        help="Cantidad de paquetes a enviar. Por defecto: 4."
    )

    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=2.0,
        help="Tiempo máximo de espera por respuesta en segundos. Por defecto: 2."
    )

    parser.add_argument(
        "-i",
        "--interval",
        type=float,
        default=1.0,
        help="Intervalo entre paquetes en segundos. Por defecto: 1."
    )

    args = parser.parse_args()

    run_ping(
        destination=args.destination,
        count=args.count,
        timeout=args.timeout,
        interval=args.interval
    )


if __name__ == "__main__":
    main()