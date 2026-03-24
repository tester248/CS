import secrets
import math
import base64


def is_probable_prime(n, k=8):
    if n < 2:
        return False
    small_primes = [2,3,5,7,11,13,17,19,23,29]
    for p in small_primes:
        if n % p == 0:
            return n == p
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(k):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = (x * x) % n
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bits):
    while True:
        p = secrets.randbits(bits) | 1 | (1 << (bits - 1))
        if is_probable_prime(p):
            return p


def egcd(a, b):
    if b == 0:
        return (a, 1, 0)
    g, x1, y1 = egcd(b, a % b)
    return (g, y1, x1 - (a // b) * y1)


def modinv(a, m):
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError('modular inverse does not exist')
    return x % m


def generate_keys(bits=1024, e=65537):
    p = generate_prime(bits // 2)
    q = generate_prime(bits // 2)
    while q == p:
        q = generate_prime(bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    if math.gcd(e, phi) != 1:
        raise ValueError('e and phi not coprime')
    d = modinv(e, phi)
    return (n, e), (n, d)


def encrypt_bytes(data: bytes, pubkey):
    n, e = pubkey
    plen = (n.bit_length() - 1) // 8
    clen = (n.bit_length() + 7) // 8
    # prepend length
    data = len(data).to_bytes(4, 'big') + data
    out = bytearray()
    for i in range(0, len(data), plen):
        chunk = data[i:i+plen]
        if len(chunk) < plen:
            chunk = chunk + b"\x00" * (plen - len(chunk))
        m = int.from_bytes(chunk, 'big')
        c = pow(m, e, n)
        out.extend(c.to_bytes(clen, 'big'))
    return base64.b64encode(bytes(out)).decode()


def decrypt_bytes(ct_b64: str, privkey):
    n, d = privkey
    clen = (n.bit_length() + 7) // 8
    plen = (n.bit_length() - 1) // 8
    raw = base64.b64decode(ct_b64)
    if len(raw) % clen != 0:
        raise ValueError('invalid ciphertext')
    out = bytearray()
    for i in range(0, len(raw), clen):
        block = raw[i:i+clen]
        c = int.from_bytes(block, 'big')
        m = pow(c, d, n)
        out.extend(m.to_bytes(plen, 'big'))
    total_len = int.from_bytes(out[:4], 'big')
    return bytes(out[4:4+total_len])


if __name__ == '__main__':
    # simple demo
    pub, priv = generate_keys(1024)
    msg = 'Cyber Security RSA Implementation'.encode()
    ct = encrypt_bytes(msg, pub)
    pt = decrypt_bytes(ct, priv)
    print('pub_n bits:', pub[0].bit_length())
    print('CIPHERTEXT:', ct)
    print('DECRYPTED:', pt.decode())
