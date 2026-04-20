"""
Test Skeleton for Hybrid Encryption Module

This file will be expanded in Week 2 once encryption
and decryption logic is fully implemented.
"""

import unittest
from hybrid_encrypt import hybrid_encrypt, hybrid_decrypt


class TestHybridEncryption(unittest.TestCase):

    def setUp(self):
        """
        Setup test inputs.
        Replace with actual ECC key generation later.
        """
        self.sample_plaintext = b"Test message"
        self.receiver_public_key = None
        self.receiver_private_key = None

    def test_hybrid_encrypt_stub(self):
        """
        Ensure hybrid_encrypt raises NotImplementedError.
        """
        with self.assertRaises(NotImplementedError):
            hybrid_encrypt(self.sample_plaintext, self.receiver_public_key)

    def test_hybrid_decrypt_stub(self):
        """
        Ensure hybrid_decrypt raises NotImplementedError.
        """
        with self.assertRaises(NotImplementedError):
            hybrid_decrypt({}, self.receiver_private_key)


if __name__ == "__main__":
    unittest.main()
