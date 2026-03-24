def power(base, expo, m):
    res = 1
    base %= m
    while expo > 0:
        if expo & 1:
            res = (res * base) % m
        base = (base * base) % m
        expo >>= 1
    return res


def mod_inverse_trial(e, phi):
    for d in range(2, phi):
        if (e * d) % phi == 1:
            return d
    return None


def generate_keys(p, q):
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 2
    from math import gcd
    while e < phi:
        if gcd(e, phi) == 1:
            break
        e += 1
    d = mod_inverse_trial(e, phi)
    return (e, d, n)


def encrypt(m, e, n):
    return power(m, e, n)


def decrypt(c, d, n):
    return power(c, d, n)


if __name__ == '__main__':
    p = 7919
    q = 1009
    e, d, n = generate_keys(p, q)
    print('Public Key (e,n):', (e, n))
    print('Private Key (d,n):', (d, n))
    M = 1234
    print('Original Message:', M)
    C = encrypt(M, e, n)
    print('Encrypted Message:', C)
    dec = decrypt(C, d, n)
    print('Decrypted Message:', dec)
