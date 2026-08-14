#!/usr/bin/env python3

import json
import pathlib
import sys

from google.protobuf.internal import decoder
from google.protobuf.internal import wire_format
from google.protobuf.message import DecodeError


def read_length_delimited(buffer, position, end):
    size, position = decoder._DecodeVarint(buffer, position)
    next_position = position + size
    if next_position > end:
        raise DecodeError("truncated length-delimited field")
    return buffer[position:next_position].tobytes(), next_position


def decode_message_envelope(encoded):
    buffer = memoryview(encoded)
    position = 0
    end = len(buffer)
    fields = {}
    unknown = []
    while position < end:
        tag, position = decoder._DecodeVarint(buffer, position)
        field_number, wire_type = wire_format.UnpackTag(tag)
        if field_number in (1, 2, 7):
            if wire_type != wire_format.WIRETYPE_LENGTH_DELIMITED:
                raise DecodeError("wrong wire type")
            fields[field_number], position = read_length_delimited(buffer, position, end)
        elif field_number in (3, 4, 5, 8):
            if wire_type != wire_format.WIRETYPE_VARINT:
                raise DecodeError("wrong wire type")
            fields[field_number], position = decoder._DecodeVarint(buffer, position)
        elif field_number == 6:
            if wire_type != wire_format.WIRETYPE_LENGTH_DELIMITED:
                raise DecodeError("wrong wire type")
            value, position = read_length_delimited(buffer, position, end)
            fields.setdefault(field_number, []).append(value)
        else:
            value, position = decoder._DecodeUnknownField(
                buffer, position, end, field_number, wire_type
            )
            unknown.append((field_number, wire_type, value))
    return fields, unknown


def expect_decode_error(encoded):
    try:
        decode_message_envelope(encoded)
    except (DecodeError, IndexError):
        return
    raise AssertionError("malformed Protobuf input was accepted")


def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: protobuf_conformance_test.py <golden-vector-json>")

    vectors = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
    encoded = bytes.fromhex(vectors["protobuf_message_envelope"]["bytes_hex"])
    fields, unknown = decode_message_envelope(encoded)
    assert fields[1] == bytes.fromhex("00112233445566778899aabbccddeeff")
    assert fields[2] == b"test"
    assert fields[3] == 1
    assert fields[4] == 1000
    assert fields[5] == 1
    assert fields[7] == b"abc"
    assert not unknown

    fields, unknown = decode_message_envelope(encoded + bytes.fromhex("7a01ff"))
    assert fields[7] == b"abc"
    assert unknown == [(15, wire_format.WIRETYPE_LENGTH_DELIMITED, b"\xff")]

    expect_decode_error(encoded[:-1])
    expect_decode_error(bytes.fromhex("0affffffff0f"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
