"""
Implementación propia de traceroute usando ICMP y control de TTL.

Este módulo construye paquetes ICMP Echo Request manualmente, usando
el cálculo de checksum, identificador y secuencia mediante funciones
propias del proyecto. Luego envía los paquetes mediante un raw socket,
modificando el campo TTL del encabezado IP en cada intento para descubrir
los saltos intermedios entre el equipo local y el destino.

No utiliza el comando traceroute/tracert del sistema operativo ni delega
la construcción del paquete ICMP en Scapy.
"""

import argparse
import os
import select
import socket
import time
from typing import Optional

from .icmp_utils import (
    ICMP_ECHO_REPLY,
    ICMP_ECHO_REQUEST,
    ICMP_TIME_EXCEEDED,
    ICMP_DESTINATION_UNREACHABLE,
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


def is_icmp_packet(packet: bytes) -> bool:
    """
    Verifica si un paquete IPv4 recibido corresponde al protocolo ICMP
    (protocolo número 1).

    Args:
        packet: Paquete IPv4 completo recibido desde el socket raw.

    Returns:
        True si el campo "protocolo" del encabezado IP es ICMP (1).
    """
    if len(packet) < 20:
        return False

    version = packet[0] >> 4

    if version != 4:
        return False

    protocol = packet[9]
    return protocol == 1


def probe_hop(
    sock: socket.socket,
    destination_ip: str,
    ttl: int,
    identifier: int,
    sequence: int,
    timeout: float,
    debug: bool = False,
) -> tuple[Optional[str], Optional[float], Optional[int], Optional[str]]:
    """
    Envía un único paquete ICMP Echo Request construido manualmente con
    un TTL específico y espera la respuesta (Time Exceeded, Echo Reply,
    Destination Unreachable o ninguna).

    Args:
        sock: Socket raw ya configurado con el TTL deseado.
        destination_ip: IP destino final del traceroute.
        ttl: Valor de TTL usado en este intento (solo para referencia).
        identifier: Identificador ICMP del proceso.
        sequence: Número de secuencia de este paquete.
        timeout: Tiempo máximo de espera en segundos.
        debug: Si es True, imprime cada paquete crudo recibido y por qué
            se acepta o se descarta. Solo para diagnóstico temporal.

    Returns:
        Tupla (ip_origen, rtt_ms, icmp_type, nombre_tipo). Todos los
        valores son None si no llegó ninguna respuesta a tiempo.
    """
    payload = f"Grupo4-ICMP-TRACE-ttl{ttl}".encode()
    packet = build_echo_request(identifier, sequence, payload)

    start_time = time.perf_counter()
    sock.sendto(packet, (destination_ip, 0))

    remaining_time = timeout

    while remaining_time > 0:
        ready = select.select([sock], [], [], remaining_time)

        if not ready[0]:
            if debug:
                print(f"    [debug] ttl={ttl} seq={sequence}: timeout, nada llegó")
            return None, None, None, None

        receive_time = time.perf_counter()
        raw_packet, address = sock.recvfrom(65535)

        if debug:
            print(
                f"    [debug] ttl={ttl} seq={sequence}: llegaron "
                f"{len(raw_packet)} bytes desde {address[0]}"
            )

        if not is_icmp_packet(raw_packet):
            if debug:
                print("    [debug]   -> descartado: no es protocolo ICMP")
            elapsed = receive_time - start_time
            remaining_time = timeout - elapsed
            continue

        icmp_data = extract_icmp_from_ipv4_packet(raw_packet)

        try:
            parsed = parse_icmp_packet(icmp_data)
        except ValueError as error:
            if debug:
                print(f"    [debug]   -> descartado: parseo ICMP falló ({error})")
            elapsed = receive_time - start_time
            remaining_time = timeout - elapsed
            continue

        icmp_type = parsed["type"]

        if debug:
            print(
                f"    [debug]   -> ICMP tipo={icmp_type} "
                f"id={parsed['identifier']} seq={parsed['sequence']} "
                f"(esperado id={identifier} seq={sequence})"
            )

        
        if icmp_type == ICMP_ECHO_REQUEST:
            if debug:
                print("    [debug]   -> descartado: es nuestro propio Echo Request saliente")
            elapsed = receive_time - start_time
            remaining_time = timeout - elapsed
            continue

       
        if icmp_type == ICMP_ECHO_REPLY:
            if parsed["identifier"] == identifier and parsed["sequence"] == sequence:
                rtt_ms = (receive_time - start_time) * 1000
                return address[0], rtt_ms, icmp_type, get_icmp_type_name(icmp_type)
            elapsed = receive_time - start_time
            remaining_time = timeout - elapsed
            continue

        if icmp_type in (ICMP_TIME_EXCEEDED, ICMP_DESTINATION_UNREACHABLE):
            inner_ip_packet = parsed["payload"]
            inner_icmp_data = extract_icmp_from_ipv4_packet(inner_ip_packet)

            try:
                inner_parsed = parse_icmp_packet(inner_icmp_data)
            except ValueError:
                elapsed = receive_time - start_time
                remaining_time = timeout - elapsed
                continue

            if (
                inner_parsed["identifier"] == identifier
                and inner_parsed["sequence"] == sequence
            ):
                rtt_ms = (receive_time - start_time) * 1000
                return address[0], rtt_ms, icmp_type, get_icmp_type_name(icmp_type)

        elapsed = receive_time - start_time
        remaining_time = timeout - elapsed

    return None, None, None, None


def run_traceroute(
    destination: str,
    max_hops: int,
    timeout: float,
    probes_per_hop: int,
    debug: bool = False,
) -> None:
    """
    Ejecuta traceroute propio hacia un destino usando paquetes ICMP
    construidos a mano y control manual del TTL.

    Args:
        destination: Dominio o dirección IP destino.
        max_hops: Cantidad máxima de saltos.
        timeout: Tiempo máximo de espera por respuesta.
        probes_per_hop: Cantidad de intentos por salto.
        debug: Si es True, imprime información detallada de cada
            paquete recibido. Solo para diagnóstico temporal.
    """
    try:
        destination_ip = socket.gethostbyname(destination)
    except socket.gaierror:
        print(f"No se pudo resolver el destino: {destination}")
        return

    identifier = os.getpid() & 0xFFFF
    sequence = 1

    print(f"TRACEROUTE propio hacia {destination} ({destination_ip})")
    print("Usando ICMP Echo Request construido manualmente y TTL incremental.\n")

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as sock:
            for ttl in range(1, max_hops + 1):
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)

                hop_ips = []
                hop_times = []
                last_type_name = None
                reached_destination = False

                for _ in range(probes_per_hop):
                    source_ip, rtt_ms, icmp_type, type_name = probe_hop(
                        sock,
                        destination_ip,
                        ttl,
                        identifier,
                        sequence,
                        timeout,
                        debug=debug,
                    )
                    sequence += 1

                    if source_ip is None:
                        hop_ips.append("*")
                        hop_times.append("*")
                    else:
                        hop_ips.append(source_ip)
                        hop_times.append(f"{rtt_ms:.2f} ms")
                        last_type_name = type_name

                        if icmp_type in (ICMP_ECHO_REPLY, ICMP_DESTINATION_UNREACHABLE):
                            reached_destination = True

                    time.sleep(0.1)

                unique_ips = []
                for ip in hop_ips:
                    if ip not in unique_ips:
                        unique_ips.append(ip)

                ip_text = " ".join(unique_ips)
                times_text = "  ".join(hop_times)

                if last_type_name:
                    print(f"{ttl:2d}  {ip_text:<40} {times_text}  ({last_type_name})")
                else:
                    print(f"{ttl:2d}  {ip_text:<40} {times_text}")

                if reached_destination:
                    print("\nDestino alcanzado.")
                    break

    except PermissionError:
        print("Error: se requieren permisos de administrador para usar raw sockets.")
        print("Ejecutá la terminal como administrador e intentá de nuevo.")
        return
    except KeyboardInterrupt:
        print("\nEjecución interrumpida por el usuario.")
    except OSError as error:
        print(f"Error de red o socket: {error}")
        return


def main() -> None:
    """
    Punto de entrada principal del programa.
    """
    parser = argparse.ArgumentParser(
        description="Traceroute propio usando ICMP y control manual del TTL."
    )

    parser.add_argument(
        "destination",
        help="Dirección IP o dominio destino."
    )

    parser.add_argument(
        "-m",
        "--max-hops",
        type=int,
        default=30,
        help="Cantidad máxima de saltos. Por defecto: 30."
    )

    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=2.0,
        help="Tiempo máximo de espera por salto en segundos. Por defecto: 2."
    )

    parser.add_argument(
        "-p",
        "--probes",
        type=int,
        default=3,
        help="Cantidad de intentos por salto. Por defecto: 3."
    )

    parser.add_argument(
    "--debug",
    action="store_true",
    help="Muestra información detallada de cada paquete recibido "
         "(opcional, útil para diagnóstico)."
)

    args = parser.parse_args()

    run_traceroute(
        destination=args.destination,
        max_hops=args.max_hops,
        timeout=args.timeout,
        probes_per_hop=args.probes,
        debug=args.debug,
    )


if __name__ == "__main__":
    main()