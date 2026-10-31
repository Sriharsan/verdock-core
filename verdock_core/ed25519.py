"""Ed25519 signatures (RFC 8032, section 5.1) in pure Python.

Written from the RFC's description of the curve, encoding, key generation,
signing and verification. Signing is deterministic.

This code is not constant time. It is fine for signing receipts on a host
you control and for verifying them anywhere, but do not use it where an
attacker can measure signing time precisely.

Verification uses the cofactorless equation [S]B = R + [k]A, rejects
S >= L, and rejects public keys and R values that do not decode to a curve
point (including non canonical y >= p).
"""

import hashlib

_P = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493


def _inv(x):
    return pow(x, _P - 2, _P)


_D = -121665 * _inv(121666) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _add(p1, p2):
    # Extended homogeneous coordinates (X, Y, Z, T), RFC 8032 section 5.1.4.
    x1, y1, z1, t1 = p1
    x2, y2, z2, t2 = p2
    a = (y1 - x1) * (y2 - x2) % _P
    b = (y1 + x1) * (y2 + x2) % _P
    c = 2 * t1 * t2 * _D % _P
    d = 2 * z1 * z2 % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


_IDENTITY = (0, 1, 1, 0)


def _mul(scalar, point):
    result = _IDENTITY
    while scalar > 0:
        if scalar & 1:
            result = _add(result, point)
        point = _add(point, point)
        scalar >>= 1
    return result


def _equal(p1, p2):
    return ((p1[0] * p2[2] - p2[0] * p1[2]) % _P == 0
            and (p1[1] * p2[2] - p2[1] * p1[2]) % _P == 0)


def _recover_x(y, sign):
    if y >= _P:
        return None
    x2 = (y * y - 1) * _inv(_D * y * y + 1) % _P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P != 0:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


_GY = 4 * _inv(5) % _P
_GX = _recover_x(_GY, 0)
_G = (_GX, _GY, 1, _GX * _GY % _P)


def _encode(point):
    zinv = _inv(point[2])
    x = point[0] * zinv % _P
    y = point[1] * zinv % _P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _decode(data):
    if len(data) != 32:
        return None
    y = int.from_bytes(data, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % _P)


def _hash_int(data):
    return int.from_bytes(hashlib.sha512(data).digest(), "little")


def _expand(seed):
    if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    digest = hashlib.sha512(bytes(seed)).digest()
    scalar = int.from_bytes(digest[:32], "little")
    scalar &= (1 << 254) - 8
    scalar |= 1 << 254
    return scalar, digest[32:]


def public_key(seed):
    """Return the 32 byte public key for a 32 byte seed (private key)."""
    scalar, _ = _expand(seed)
    return _encode(_mul(scalar, _G))


def sign(seed, message):
    """Return the 64 byte signature of message under seed."""
    scalar, prefix = _expand(seed)
    message = bytes(message)
    pub = _encode(_mul(scalar, _G))
    r = _hash_int(prefix + message) % _L
    r_bytes = _encode(_mul(r, _G))
    k = _hash_int(r_bytes + pub + message) % _L
    s = (r + k * scalar) % _L
    return r_bytes + s.to_bytes(32, "little")


def verify(pub, message, signature):
    """Return True if signature is valid for message under public key pub."""
    if len(pub) != 32 or len(signature) != 64:
        return False
    a_point = _decode(bytes(pub))
    if a_point is None:
        return False
    r_point = _decode(bytes(signature[:32]))
    if r_point is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _L:
        return False
    k = _hash_int(bytes(signature[:32]) + bytes(pub) + bytes(message)) % _L
    return _equal(_mul(s, _G), _add(r_point, _mul(k, a_point)))
