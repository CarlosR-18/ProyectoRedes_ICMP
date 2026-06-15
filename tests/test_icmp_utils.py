import struct

from src.icmp_utils import (
    ICMP_ECHO_REQUEST,
    ICMP_HEADER_FORMAT,
    calculate_checksum,
    build_echo_request,
    parse_icmp_packet,
    extract_icmp_from_ipv4_packet,
    get_icmp_type_name,
)


def test_calculate_checksum_known_echo_request_header():
    data = b"\x08\x00\x00\x00\x00\x01\x00\x01"

    result = calculate_checksum(data)

    assert result == 0xF7FD


def test_checksum_of_completed_packet_is_zero():
    payload = b"test"
    header_without_checksum = struct.pack(
        ICMP_HEADER_FORMAT,
        ICMP_ECHO_REQUEST,
        0,
        0,
        1,
        1
    )

    checksum = calculate_checksum(header_without_checksum + payload)

    header_with_checksum = struct.pack(
        ICMP_HEADER_FORMAT,
        ICMP_ECHO_REQUEST,
        0,
        checksum,
        1,
        1
    )

    completed_packet = header_with_checksum + payload

    assert calculate_checksum(completed_packet) == 0


def test_build_echo_request_creates_valid_packet():
    packet = build_echo_request(identifier=123, sequence=1, payload=b"hello")

    parsed = parse_icmp_packet(packet)

    assert parsed["type"] == 8
    assert parsed["code"] == 0
    assert parsed["identifier"] == 123
    assert parsed["sequence"] == 1
    assert parsed["payload"] == b"hello"


def test_parse_icmp_packet_rejects_short_packet():
    short_packet = b"\x08\x00"

    try:
        parse_icmp_packet(short_packet)
        assert False
    except ValueError:
        assert True


def test_extract_icmp_from_ipv4_packet():
    ip_header = b"\x45" + b"\x00" * 19
    icmp_packet = build_echo_request(identifier=1, sequence=1, payload=b"abc")
    full_packet = ip_header + icmp_packet

    extracted = extract_icmp_from_ipv4_packet(full_packet)

    assert extracted == icmp_packet


def test_get_icmp_type_name():
    assert get_icmp_type_name(0) == "Echo Reply"
    assert get_icmp_type_name(8) == "Echo Request"
    assert get_icmp_type_name(11) == "Time Exceeded"