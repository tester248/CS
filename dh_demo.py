"""Demo runner for Diffie-Hellman key exchange (practical #4)

Run with: python3 dh_demo.py
"""
from diffie_hellman import generate_private_key, compute_public, compute_shared_secret, P, G


def main():
    print("Diffie-Hellman Demo")
    print(f"Using demo prime p={P} and generator g={G}\n")

    # Generate private keys (small size for demo clarity)
    alice_priv = generate_private_key(bits=8)
    bob_priv = generate_private_key(bits=8)

    alice_pub = compute_public(alice_priv)
    bob_pub = compute_public(bob_priv)

    print("Alice -> private:", alice_priv)
    print("Alice -> public:", alice_pub)
    print()
    print("Bob   -> private:", bob_priv)
    print("Bob   -> public:", bob_pub)
    print()

    a_shared_int, a_key_hex = compute_shared_secret(bob_pub, alice_priv)
    b_shared_int, b_key_hex = compute_shared_secret(alice_pub, bob_priv)

    print("Alice computed shared integer:", a_shared_int)
    print("Bob   computed shared integer:", b_shared_int)
    print()
    print("Alice derived key (SHA-256 hex):", a_key_hex)
    print("Bob   derived key (SHA-256 hex):", b_key_hex)

    if a_key_hex == b_key_hex:
        print('\nSuccess: both parties derived the same key.')
    else:
        print('\nFailure: derived keys differ!')


if __name__ == "__main__":
    main()
