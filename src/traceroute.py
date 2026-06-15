"""
Implementación propia de traceroute usando ICMP y control de TTL.

Este módulo envía paquetes ICMP Echo Request con distintos valores de TTL
para descubrir los saltos intermedios entre el equipo local y el destino.
No utiliza el comando traceroute/tracert del sistema operativo.
"""

import argparse
import socket
import time

from scapy.all import IP, ICMP, sr1, conf


def get_icmp_type_name(icmp_type: int) -> str:
    """
    Devuelve un nombre legible para los tipos ICMP más comunes.
    """
    names = {
        0: "Echo Reply",
        3: "Destination Unreachable",
        8: "Echo Request",
        11: "Time Exceeded"
    }

    return names.get(icmp_type, f"Tipo desconocido ({icmp_type})")


def run_traceroute(
    destination: str,
    max_hops: int,
    timeout: float,
    probes_per_hop: int
) -> None:
    """
    Ejecuta traceroute propio hacia un destino usando paquetes ICMP.

    Args:
        destination: Dominio o dirección IP destino.
        max_hops: Cantidad máxima de saltos.
        timeout: Tiempo máximo de espera por respuesta.
        probes_per_hop: Cantidad de intentos por salto.
    """
    try:
        destination_ip = socket.gethostbyname(destination)
    except socket.gaierror:
        print(f"No se pudo resolver el destino: {destination}")
        return

    conf.verb = 0

    print(f"TRACEROUTE propio hacia {destination} ({destination_ip})")
    print("Usando ICMP Echo Request y modificación manual del TTL.\n")

    sequence = 1

    for ttl in range(1, max_hops + 1):
        hop_ips = []
        hop_times = []
        last_type_name = None
        reached_destination = False

        for _ in range(probes_per_hop):
            packet = IP(dst=destination_ip, ttl=ttl) / ICMP(
                type=8,
                code=0,
                id=1234,
                seq=sequence
            ) / b"Grupo4-ICMP-TRACE"

            start_time = time.perf_counter()

            reply = sr1(
                packet,
                timeout=timeout
            )

            end_time = time.perf_counter()
            sequence += 1

            if reply is None:
                hop_ips.append("*")
                hop_times.append("*")
                continue

            rtt_ms = (end_time - start_time) * 1000
            source_ip = reply.src

            if ICMP in reply:
                icmp_type = int(reply[ICMP].type)
                last_type_name = get_icmp_type_name(icmp_type)

                if icmp_type == 0:
                    reached_destination = True

                if icmp_type == 3:
                    reached_destination = True
            else:
                last_type_name = "Respuesta no ICMP"

            hop_ips.append(source_ip)
            hop_times.append(f"{rtt_ms:.2f} ms")

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

    args = parser.parse_args()

    run_traceroute(
        destination=args.destination,
        max_hops=args.max_hops,
        timeout=args.timeout,
        probes_per_hop=args.probes
    )


if __name__ == "__main__":
    main()