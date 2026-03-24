
SBOX = [0x9, 0x4, 0xA, 0xB,
        0xD, 0x1, 0x8, 0x5,
        0x6, 0x2, 0x0, 0x3,
        0xC, 0xE, 0xF, 0x7]

INV_SBOX = [SBOX.index(i) for i in range(16)]

RCON = [0x80, 0x30]  # round constants for S-AES (8-bit values)


def nibble_sub(byte):
    #Apply S-box to high and low nibble of an 8-bit value
    hi = (byte >> 4) & 0xF
    lo = byte & 0xF
    return (SBOX[hi] << 4) | SBOX[lo]


def rot_nib(byte):
    #Swap the two 4-bit nibbles of an 8-bit value.
    return ((byte & 0xF) << 4) | ((byte >> 4) & 0xF)


def gf4_mul(a, b):
    mod = 0b10011
    res = 0
    aa = a
    bb = b
    while bb:
        if bb & 1:
            res ^= aa
        bb >>= 1
        aa <<= 1
        if aa & 0x10:
            aa ^= mod
    return res & 0xF


def mix_column(col):
    """Mix a column of two nibbles [s0, s1] using matrix [[1,4],[4,1]]."""
    s0, s1 = col
    new0 = gf4_mul(1, s0) ^ gf4_mul(4, s1)
    new1 = gf4_mul(4, s0) ^ gf4_mul(1, s1)
    return new0, new1


def key_schedule(key16):
    # Generate round keys K0,K1,K2 from 16-bit key.
    # split into two bytes
    w0 = (key16 >> 8) & 0xFF
    w1 = key16 & 0xFF

    def g(byte, rcon):
        return nibble_sub(rot_nib(byte)) ^ rcon

    w2 = w0 ^ g(w1, RCON[0])
    w3 = w2 ^ w1
    w4 = w2 ^ g(w3, RCON[1])
    w5 = w4 ^ w3

    k0 = (w0 << 8) | w1
    k1 = (w2 << 8) | w3
    k2 = (w4 << 8) | w5
    return [k0, k1, k2]


def add_round_key(state16, round_key16):
    return state16 ^ round_key16


def sub_nibbles_state(state16):
    #Apply S-box to each 4-bit nibble in 16-bit state (4 nibbles)
    out = 0
    for i in range(4):
        nib = (state16 >> (12 - 4 * i)) & 0xF
        out = (out << 4) | SBOX[nib]
    return out


def shift_rows(state16):
    #State is 4 nibbles: [n0 n1 n2 n3] arranged as 2x2 matrix:
    n0 = (state16 >> 12) & 0xF
    n1 = (state16 >> 8) & 0xF
    n2 = (state16 >> 4) & 0xF
    n3 = state16 & 0xF
    # after shift
    r0, r1 = n0, n1
    r2, r3 = n3, n2
    return (r0 << 12) | (r1 << 8) | (r2 << 4) | r3


def mix_columns(state16):
    # split into columns: col0 = [n0, n2], col1 = [n1, n3]
    n0 = (state16 >> 12) & 0xF
    n1 = (state16 >> 8) & 0xF
    n2 = (state16 >> 4) & 0xF
    n3 = state16 & 0xF
    c0 = mix_column((n0, n2))
    c1 = mix_column((n1, n3))
    return (c0[0] << 12) | (c1[0] << 8) | (c0[1] << 4) | c1[1]


def encrypt(plaintext16, key16):
    # key schedule
    k0, k1, k2 = key_schedule(key16)

    state = add_round_key(plaintext16, k0)

    # Round 1
    state = sub_nibbles_state(state)
    state = shift_rows(state)
    state = mix_columns(state)
    state = add_round_key(state, k1)

    # Round 2 (no mixcolumns after final round)
    state = sub_nibbles_state(state)
    state = shift_rows(state)
    state = add_round_key(state, k2)

    return state


def to_bitstring(x, bits):
    return format(x, '0{}b'.format(bits))


if __name__ == '__main__':
    plaintext = int('1101011100101000'.replace(' ', ''), 2)
    key = int('0100101011110101'.replace(' ', ''), 2)

    ct = encrypt(plaintext, key)
    print('Plaintext :', to_bitstring(plaintext, 16))
    print('Key       :', to_bitstring(key, 16))
    print('Ciphertext:', to_bitstring(ct, 16))
