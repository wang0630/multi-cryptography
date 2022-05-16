from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
from Crypto.Util import Padding
from .symmetric_base import *


class SymmetricDes(SymmetricBase):
    def __init__(self, mode):
        """
        Use pycryptodome package for both DES-CBC and DES-CTR
        :param mode: Either CBC or CTR
        """
        super().__init__(get_random_bytes(8), 64, 8)
        self.mode = mode

        if self.mode == 'CBC':
            mode_ins = DES.MODE_CBC
            self.encryptor = DES.new(self.key, mode_ins, iv=get_random_bytes(self.BLOCK_SIZE_BYTES))
            self.decryptor = DES.new(self.key, mode_ins, iv=self.encryptor.iv)
        elif self.mode == 'CTR':
            mode_ins = DES.MODE_CTR
            # Need to create two cipher context for enc and dec
            self.encryptor = DES.new(self.key, mode_ins, nonce=b'')
            # Decryptor must use the same nonce(or iv) as the encryptor
            self.decryptor = DES.new(self.key, mode_ins, nonce=self.encryptor.nonce)
        else:
            raise TypeError(f'Mode {mode} is not supported')

    def encrypt(self, file_path):
        ciphertext = []

        with open(file_path, 'rb') as fd:
            line = fd.read(self.BLOCK_SIZE_BYTES)
            while line:
                if len(line) < self.BLOCK_SIZE_BYTES:
                    ct = self.encryptor.encrypt(Padding.pad(line, self.BLOCK_SIZE_BYTES))
                else:
                    ct = self.encryptor.encrypt(line)

                ciphertext.append(ct)
                line = fd.read(self.BLOCK_SIZE_BYTES)

        return ciphertext

    def decrypt(self, ciphertext):
        plaintext = []
        LEN = len(ciphertext)
        for i in range(LEN-1):
            pt = self.decryptor.decrypt(ciphertext[i])
            plaintext.append(pt)

        pt = Padding.unpad(self.decryptor.decrypt(ciphertext[LEN-1]), self.BLOCK_SIZE_BYTES)
        plaintext.append(pt)

        return plaintext
