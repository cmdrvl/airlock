"""Independent RFC 8785 (JCS) reference used by tests/jcs_crosscheck.rs.

Standard library only, and deliberately written without reference to the Rust code: keys are
ordered by UTF-16 code units through the `utf-16-be` encoding, and number digits come from
CPython's `repr(float)` (David Gay's shortest round-trip algorithm) rather than from Rust.

Usage (always run with `python3 -I`):
    jcs_reference.py numbers FILE   each line is 1-16 hex digits of an IEEE 754 double; prints
                                    the RFC 8785 number serialization, one per line
    jcs_reference.py canon FILE     each line is one JSON document; prints its canonical form,
                                    or "ERROR: ..." for a document RFC 8785 cannot represent
                                    interoperably (an integer beyond 2^53 in magnitude)
"""
import decimal
import json
import math
import struct
import sys

MAX_INTERCHANGE_INTEGER = 2**53


def es_number(value: float) -> str:
    """ECMAScript Number::toString for a finite double (RFC 8785 section 3.2.2.3)."""
    if math.isnan(value) or math.isinf(value):
        raise ValueError("NaN and Infinity are not permitted")
    if value == 0:
        return "0"
    sign = "-" if value < 0 else ""
    # normalize() strips trailing zeros; digits x 10^exponent is then the shortest form.
    parts = decimal.Decimal(repr(abs(value))).normalize().as_tuple()
    digits = "".join(str(d) for d in parts.digits)
    k = len(digits)
    n = k + parts.exponent  # value = 0.digits x 10^n
    if k <= n <= 21:
        return sign + digits + "0" * (n - k)
    if 0 < n <= 21:
        return sign + digits[:n] + "." + digits[n:]
    if -6 < n <= 0:
        return sign + "0." + "0" * (-n) + digits
    e = n - 1
    exponent = ("-" if e < 0 else "+") + str(abs(e))
    if k == 1:
        return sign + digits + "e" + exponent
    return sign + digits[0] + "." + digits[1:] + "e" + exponent


ESCAPES = {'"': '\\"', "\\": "\\\\", "\b": "\\b", "\t": "\\t", "\n": "\\n", "\f": "\\f", "\r": "\\r"}


def es_string(text: str) -> str:
    out = ['"']
    for ch in text:
        if ch in ESCAPES:
            out.append(ESCAPES[ch])
        elif ord(ch) < 0x20:
            out.append("\\u%04x" % ord(ch))
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def canonical(value) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        if abs(value) > MAX_INTERCHANGE_INTEGER:
            raise ValueError("integer %d is beyond 2^53 in magnitude" % value)
        return str(value)
    if isinstance(value, float):
        return es_number(value)
    if isinstance(value, str):
        return es_string(value)
    if isinstance(value, list):
        return "[" + ",".join(canonical(item) for item in value) + "]"
    if isinstance(value, dict):
        members = sorted(value.items(), key=lambda kv: kv[0].encode("utf-16-be"))
        return "{" + ",".join(es_string(k) + ":" + canonical(v) for k, v in members) + "}"
    raise TypeError("unsupported type %r" % type(value))


def main() -> int:
    mode, path = sys.argv[1], sys.argv[2]
    out = []
    with open(path, "r", encoding="utf-8", newline="\n") as handle:
        lines = handle.read().split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    for line in lines:
        if mode == "numbers":
            bits = int(line, 16)
            value = struct.unpack(">d", struct.pack(">Q", bits))[0]
            try:
                out.append(es_number(value))
            except ValueError as error:
                out.append("ERROR: %s" % error)
        elif mode == "canon":
            try:
                out.append(canonical(json.loads(line)))
            except ValueError as error:
                out.append("ERROR: %s" % error)
        else:
            raise SystemExit("unknown mode %r" % mode)
    sys.stdout.buffer.write(("\n".join(out) + "\n").encode("utf-8"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
