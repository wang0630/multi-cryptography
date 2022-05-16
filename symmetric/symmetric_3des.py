from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from Crypto.Cipher import DES3
from Crypto.Random import get_random_bytes
from .symmetric_base import *

#


class Symmetric3Des(SymmetricBase):
    def __init__(self, mode):
        """
         Use cryptography package for 3DES-CBC but use pycryptodome for 3DES-CTR
        :param mode: Either CBC or CTR
        """
        super().__init__(get_random_bytes(24), 64, 8)
        self.mode = mode

        if self.mode == 'CBC':
            mode_ins = modes.CBC(get_random_bytes(self.BLOCK_SIZE_BYTES))
            self.cipher = Cipher(algorithm=algorithms.TripleDES(self.key), mode=mode_ins)

            self.encryptor = self.cipher.encryptor()
            self.decryptor = self.cipher.decryptor()

        elif self.mode == 'CTR':
            # Avoid Option 3(degrade to single DES)
            # 3des key should be 24 bytes long in order to be separated to 3 different keys
            # Follow the document: https://www.pycryptodome.org/en/latest/src/cipher/des3.html
            while True:
                try:
                    self.key = DES3.adjust_key_parity(self.key)
                    break
                except ValueError as e:
                    # regenerate key
                    self.key = get_random_bytes(24)
        else:
            raise TypeError(f'Mode {mode} is not supported')

        # Need to create two cipher context for enc and dec
        self.encryptor = DES3.new(self.key, DES3.MODE_CTR, nonce=b'')
        # Decryptor must use the same nonce(or iv) as the encryptor
        self.decryptor = DES3.new(self.key, DES3.MODE_CTR, nonce=self.encryptor.nonce)

    def encrypt_ctr(self, file_path):
        ciphertext = []
        with open(file_path, 'rb') as fd:
            line = fd.read(self.BLOCK_SIZE_BYTES)
            while line:
                ciphertext.append(self.encryptor.encrypt(line))
                line = fd.read(self.BLOCK_SIZE_BYTES)

        return ciphertext

    def decrypt_ctr(self, ciphertext):
        plaintext = []

        for c in ciphertext:
            plaintext.append(self.decryptor.decrypt(c))

        return plaintext

    def run(self, file_path):
        if self.mode == 'CBC':
            return super().run(file_path)

        elif self.mode == 'CTR':
            ct = self.encrypt_ctr(file_path)
            return self.decrypt_ctr(ct)

