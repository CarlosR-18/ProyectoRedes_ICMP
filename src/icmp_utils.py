"""
Utilidades base para trabajar con paquetes ICMP.

Este módulo contiene funciones para calcular el checksum de ICMP,
construir paquetes Echo Request y extraer información básica de
mensajes ICMP recibidos.
"""

import struct
import time
from typing import Dict, Any


ICMP_ECHO_REPLY = 0
ICMP_DESTINATION_UNREACHABLE = 3
ICMP_ECHO_REQUEST = 8
ICMP_TIME_EXCEEDED = 11

ICMP_HEADER_FORMAT = "!BBHHH"
ICMP_HEADER_SIZE = 8


def calculate_checksum(data: bytes) -> int:
   
    if len(data) % 2 != 0:
        data += b"\x00"

    total = 0

    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i + 1]
        total += word
        total = (total & 0xFFFF) + (total >> 16)

    checksum = ~total & 0xFFFF
    return checksum


def build_echo_request(identifier: int, sequence: int, payload: bytes | None = None) -> bytes:
    
    if payload is None:
        timestamp = time.time()
        payload = struct.pack("!d", timestamp) + b" Grupo4-ICMP"

    header_without_checksum = struct.pack(
        ICMP_HEADER_FORMAT,
        ICMP_ECHO_REQUEST,
        0,
        0,
        identifier,
        sequence
    )

    checksum = calculate_checksum(header_without_checksum + payload)

    header = struct.pack(
        ICMP_HEADER_FORMAT,
        ICMP_ECHO_REQUEST,
        0,
        checksum,
        identifier,
        sequence
    )

    return header + payload


def parse_icmp_packet(packet: bytes) -> Dict[str, Any]:
  
    if len(packet) < ICMP_HEADER_SIZE:
        raise ValueError("El paquete ICMP es demasiado corto.")

    icmp_type, code, checksum, identifier, sequence = struct.unpack(
        ICMP_HEADER_FORMAT,
        packet[:ICMP_HEADER_SIZE]
    )

    return {
        "type": icmp_type,
        "code": code,
        "checksum": checksum,
        "identifier": identifier,
        "sequence": sequence,
        "payload": packet[ICMP_HEADER_SIZE:]
    }


def extract_icmp_from_ipv4_packet(packet: bytes) -> bytes:
   
    if len(packet) < 20:
        return packet

    version = packet[0] >> 4

    if version != 4:
        return packet

    ihl = packet[0] & 0x0F
    ip_header_length = ihl * 4

    if len(packet) < ip_header_length:
        return packet

    return packet[ip_header_length:]


def get_icmp_type_name(icmp_type: int) -> str:
   
    names = {
        ICMP_ECHO_REPLY: "Echo Reply",
        ICMP_DESTINATION_UNREACHABLE: "Destination Unreachable",
        ICMP_ECHO_REQUEST: "Echo Request",
        ICMP_TIME_EXCEEDED: "Time Exceeded"
    }

    return names.get(icmp_type, f"Tipo desconocido ({icmp_type})")