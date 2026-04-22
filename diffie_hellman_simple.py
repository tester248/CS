import secrets, hashlib
# prime and generator 
P = 23
G = 5

def gen_priv(bits=8):
    # random private key
    return secrets.randbits(bits) | 1

def pub(priv):
    # public value g^priv mod p
    return pow(G, priv, P)

def shared(their_pub, priv):
    # compute shared secret and derive SHA-256 key
    s = pow(their_pub, priv, P)
    b = s.to_bytes((s.bit_length() + 7) // 8 or 1, 'big')
    return s, hashlib.sha256(b).hexdigest()

def main():
    # Person A and Person B generate private keys
    a = gen_priv()
    b = gen_priv()
    # exchange public values
    A = pub(a)
    B = pub(b)
    # each computes the shared secret
    sa, ka = shared(B, a)
    sb, kb = shared(A, b)

    print(f"p={P} g={G}")
    print(f"Person A: priv={a} pub={A}")
    print(f"Person B: priv={b} pub={B}")
    print(f"Person A shared={sa} key={ka}")
    print(f"Person B shared={sb} key={kb}")
    print("Success: keys match" if ka == kb else "Error: keys differ")

if __name__ == '__main__':
    main()
