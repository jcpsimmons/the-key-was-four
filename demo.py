"""Offline teaching lab. Synthetic certificates only; no network or trust-store edits."""
from datetime import datetime, timedelta, timezone
from pathlib import Path
import subprocess
import tempfile

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def recover_small_scalar(public, limit=255):
    """Search a deliberately tiny candidate set using only the public key."""
    target = public.public_numbers()
    for candidate in range(1, limit + 1):
        key = ec.derive_private_key(candidate, public.curve)
        if key.public_key().public_numbers() == target:
            return candidate, key
    return None


def name(label):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, label)])


def certificate(subject, issuer, public, signer, ca, path_length=None):
    now = datetime.now(timezone.utc)
    builder = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
               .public_key(public).serial_number(x509.random_serial_number())
               .not_valid_before(now - timedelta(minutes=5))
               .not_valid_after(now + timedelta(days=1))
               .add_extension(x509.BasicConstraints(ca=ca, path_length=path_length), True)
               .add_extension(x509.KeyUsage(digital_signature=True,
                   content_commitment=False, key_encipherment=False, data_encipherment=False,
                   key_agreement=False, key_cert_sign=ca, crl_sign=ca,
                   encipher_only=False, decipher_only=False), True))
    if not ca:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName("demo.invalid")]), False)
    return builder.sign(signer, hashes.SHA384())


def lab():
    curve = ec.SECP384R1()
    root_key = ec.generate_private_key(curve)
    weak_key = ec.derive_private_key(4, curve)  # Deliberately bad fixture.
    root_name, ca_name = name("Synthetic Lab Root"), name("Synthetic Weak Intermediate")
    root = certificate(root_name, root_name, root_key.public_key(), root_key, True, 1)
    intermediate = certificate(ca_name, root_name, weak_key.public_key(), root_key, True, 0)
    # This function receives the public certificate key, never the original private key.
    recovered, attacker_key = recover_small_scalar(intermediate.public_key())
    leaf_key = ec.generate_private_key(curve)
    forged = certificate(name("demo.invalid"), ca_name, leaf_key.public_key(), attacker_key, False)
    other_key = ec.generate_private_key(curve)
    other_name = name("Unrelated Lab Root")
    other_root = certificate(other_name, other_name, other_key.public_key(), other_key, True, 1)
    with tempfile.TemporaryDirectory(prefix="four-lab-") as directory:
        folder = Path(directory)
        for label, cert in [("root", root), ("intermediate", intermediate),
                            ("forged", forged), ("other", other_root)]:
            (folder / f"{label}.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        def verify(trust):
            return subprocess.run([
                "openssl", "verify", "-CAfile", str(folder / f"{trust}.pem"),
                "-untrusted", str(folder / "intermediate.pem"),
                str(folder / "forged.pem")], capture_output=True, text=True)
        accepted, rejected = verify("root"), verify("other")
    if accepted.returncode != 0 or rejected.returncode == 0:
        raise RuntimeError(f"Unexpected verifier result: {accepted.stderr}; {rejected.stderr}")
    return recovered, accepted.returncode, rejected.returncode


if __name__ == "__main__":
    scalar, accepted, rejected = lab()
    print("SYNTHETIC OFFLINE LAB | P-384 | no real CA keys")
    print(f"Public key search: private scalar recovered after {scalar} guesses")
    print("Recovered key signs a new certificate for demo.invalid")
    print(f"Verifier trusts our lab root: ACCEPTED (exit {accepted})")
    print(f"Verifier trusts an unrelated root: REJECTED (exit {rejected})")
    print("No certificates installed. Temporary public certificates removed.")
