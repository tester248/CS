from collections import deque

def permute(bits, table):
    return [bits[i] for i in table]

def left_shift(bits, n):
    d = deque(bits)
    d.rotate(-n)
    return list(d)

def gen_keys(key=None):
    if key is None:
        key = [1,0,1,0,0,0,0,0,1,0]
    p10_table = [2,4,1,6,3,9,0,8,7,5]
    p8_table = [5,2,6,3,7,4,9,8]

    p10 = permute(key, p10_table)

    l = p10[:5]
    r = p10[5:]

    l = left_shift(l, 1)
    r = left_shift(r, 1)
    k1 = permute(l + r, p8_table)

    l = left_shift(l, 2)
    r = left_shift(r, 2)
    k2 = permute(l + r, p8_table)

    return k1, k2

S0 = [
    [1,0,3,2],
    [3,2,1,0],
    [0,2,1,3],
    [3,1,3,2],
]
S1 = [
    [0,1,2,3],
    [2,0,1,3],
    [3,0,1,0],
    [2,1,0,3],
]

def sbox_lookup(bits4, sbox):
    # bits4: list of 4 bits [b1,b2,b3,b4]
    row = (bits4[0] << 1) | bits4[3]
    col = (bits4[1] << 1) | bits4[2]
    val = sbox[row][col]
    return [(val >> 1) & 1, val & 1]

def fk(left4, right4, subkey):
    # EP: expand 4 bits to 8
    ep_table = [3,0,1,2,1,2,3,0]
    ep = permute(right4, ep_table)
    xor = [a ^ b for a, b in zip(ep, subkey)]
    left_xor = xor[:4]
    right_xor = xor[4:]

    s0_out = sbox_lookup(left_xor, S0)
    s1_out = sbox_lookup(right_xor, S1)

    p4_table = [1,3,2,0]
    p4_in = s0_out + s1_out
    p4 = permute(p4_in, p4_table)

    new_left = [a ^ b for a, b in zip(left4, p4)]
    return new_left, right4

def initial_permutation(bits8):
    ip_table = [1,5,2,0,3,7,4,6]
    return permute(bits8, ip_table)

def inverse_initial_permutation(bits8):
    ip_inv = [3,0,2,4,6,1,7,5]
    return permute(bits8, ip_inv)

def encrypt(plaintext8, key10=None):
    k1, k2 = gen_keys(key10)
    ip = initial_permutation(plaintext8)
    left = ip[:4]
    right = ip[4:]

    left, right = fk(left, right, k1)
    # swap
    left, right = right, left

    left, right = fk(left, right, k2)

    preoutput = left + right
    cipher = inverse_initial_permutation(preoutput)
    return cipher

def bits_from_string(s):
    s = s.strip()
    if len(s) != 8 or any(c not in "01" for c in s):
        raise ValueError("Plaintext must be 8 bits (string of 0/1)")
    return [int(c) for c in s]

def bits_to_string(bits):
    return "".join(str(b) for b in bits)

if __name__ == "__main__":
    # key=1010000010, plaintext=10010111 -> cipher 00111000
    default_key = [1,0,1,0,0,0,0,0,1,0]
    plaintext = bits_from_string("10010111")

    k1, k2 = gen_keys(default_key)
    print("Key1:", bits_to_string(k1))
    print("Key2:", bits_to_string(k2))

    cipher = encrypt(plaintext, default_key)
    print("Plaintext:", bits_to_string(plaintext))
    print("Ciphertext:", bits_to_string(cipher))
