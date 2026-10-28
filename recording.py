"""Interactive filming companion. Synthetic keys only. --auto runs without pauses."""
import sys
from demo import recover_small_scalar, lab
from cryptography.hazmat.primitives.asymmetric import ec

def pause(n, title):
    print(f"\nSTEP {n}: {title}")
    if "--auto" not in sys.argv:
        input("Press Enter to reveal this step: ")

pause(1, "The public point is the target")
public = ec.derive_private_key(4, ec.SECP384R1()).public_key()
print("Synthetic P-384 target constructed with scalar 4; search receives public key only.")
pause(2, "Try 1, 2 and 3")
for candidate in range(1,4):
    match = ec.derive_private_key(candidate, public.curve).public_key().public_numbers() == public.public_numbers()
    assert not match
    print(f"candidate {candidate}: match={match}")
pause(3, "Try 4")
found, key = recover_small_scalar(public, 4)
assert found == 4
print(f"candidate {found}: match=True; signing key reconstructed")
pause(4, "A failed small search is not a security certificate")
public256 = ec.derive_private_key(256, ec.SECP384R1()).public_key()
assert recover_small_scalar(public256,255) is None
assert recover_small_scalar(public256,256)[0] == 256
print("target 256, limit 255: NOT FOUND; limit 256: FOUND")
pause(5, "Forge a synthetic leaf and check two trust anchors")
scalar, accepted, rejected = lab()
assert scalar == 4 and accepted == 0 and rejected != 0
print(f"demo.invalid: lab root exit={accepted}; unrelated root exit={rejected}")
print("Same forged leaf, different explicitly supplied trusted root.")
pause(6, "Read the boundary of the result")
print("6 filming stages complete. No network, installed certificates, or system trust changes.")
print("Not a browser TLS handshake, hostname test, CT test, revocation test, or real CA attack.")
