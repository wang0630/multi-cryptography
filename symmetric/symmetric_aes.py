from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from Crypto.Random import get_random_bytes
from .symmetric_base import *


class SymmetricAes(SymmetricBase):
    def __init__(self, mode):
        """
         Use cryptography package for both AES-128-CBC and AES-128-CTR
        :param mode: Either CBC or CTR
        """
        super().__init__(get_random_bytes(16), 128, 16)
        self.mode = mode

        if self.mode == 'CBC':
            mode_ins = modes.CBC(get_random_bytes(self.BLOCK_SIZE_BYTES))
        elif self.mode == 'CTR':
            # it is called nonce, use name iv for simplicity
            mode_ins = modes.CTR(get_random_bytes(self.BLOCK_SIZE_BYTES))
        else:
            raise TypeError(f'Mode {mode} is not supported')

        self.cipher = Cipher(algorithm=algorithms.AES(self.key), mode=mode_ins)

        self.encryptor = self.cipher.encryptor()
        self.decryptor = self.cipher.decryptor()
