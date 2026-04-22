"""Simple Diffie-Hellman helper functions for demo purposes.

This module uses a small default prime for readability in class/practical demos.
For real-world use, replace `P` and `G` with validated large primes (RFC 3526 groups)
and use appropriate key lengths.
"""
import secrets
import hashlib

# Default small prime and generator for demonstration only
# p = 23, g = 5 is a classical small example.
P = 23
G = 5

def generate_private_key(bits=16):
    """Generate a random private key with approximately `bits` bits.

    Default uses small size for demo; increase bits for stronger keys.
    """
    if bits < 8:
        bits = 8
    return secrets.randbits(bits) | 1

def compute_public(private_key, p=P, g=G):
    """Compute the public value g^a mod p."""
    return pow(g, private_key, p)

def compute_shared_secret(their_public, private_key, p=P):
    """Compute the shared secret and return raw integer and a SHA-256 digest (hex).

    Returns (shared_int, shared_key_hex)
    """
    shared = pow(their_public, private_key, p)
    # convert to bytes then derive a symmetric key via SHA-256
    b = shared.to_bytes((shared.bit_length() + 7) // 8 or 1, byteorder="big")
    key_hex = hashlib.sha256(b).hexdigest()
    return shared, key_hex

if __name__ == "__main__":
    # quick self-demo when run directly
    a = generate_private_key()
    b = generate_private_key()
    A = compute_public(a)
    B = compute_public(b)
    sa, ka = compute_shared_secret(B, a)
    sb, kb = compute_shared_secret(A, b)
    print("Demo parameters:")
    print(f"p={P}, g={G}")
    print()
    print("Alice private:", a)
    print("Alice public:", A)
    print("Bob private:", b)
    print("Bob public:", B)
    print()
    print("Shared (Alice):", sa)
    print("Shared (Bob):  ", sb)
    print("Derived key (hex):", ka)
