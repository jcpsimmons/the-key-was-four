import unittest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from demo import lab, recover_small_scalar


class DemoTests(unittest.TestCase):
    def test_recovers_four_from_public_key(self):
        public = ec.derive_private_key(4, ec.SECP384R1()).public_key()
        scalar, recovered = recover_small_scalar(public)
        self.assertEqual(scalar, 4)
        self.assertEqual(recovered.public_key().public_numbers(), public.public_numbers())

    def test_search_boundary(self):
        public = ec.derive_private_key(255, ec.SECP384R1()).public_key()
        self.assertIsNone(recover_small_scalar(public, 254))
        self.assertEqual(recover_small_scalar(public, 255)[0], 255)

    def test_outside_search_is_not_recovered(self):
        public = ec.derive_private_key(256, ec.SECP384R1()).public_key()
        self.assertIsNone(recover_small_scalar(public))

    def test_recovered_key_can_sign(self):
        public = ec.derive_private_key(4, ec.SECP384R1()).public_key()
        _, key = recover_small_scalar(public)
        signature = key.sign(b"synthetic message", ec.ECDSA(hashes.SHA384()))
        public.verify(signature, b"synthetic message", ec.ECDSA(hashes.SHA384()))
        with self.assertRaises(InvalidSignature):
            public.verify(signature, b"changed message", ec.ECDSA(hashes.SHA384()))

    def test_chain_acceptance_and_distrust(self):
        scalar, accepted, rejected = lab()
        self.assertEqual((scalar, accepted), (4, 0))
        self.assertNotEqual(rejected, 0)


if __name__ == "__main__":
    unittest.main()
