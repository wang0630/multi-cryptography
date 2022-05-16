from cryptography.hazmat.primitives import padding


class SymmetricBase:
    def __init__(self, key, block_size_bits, block_size_bytes):
        self.key = key
        self.cipher = None
        self.encryptor = None
        self.decryptor = None
        self.mode = None

        self.BLOCK_SIZE_BITS = block_size_bits
        self.BLOCK_SIZE_BYTES = block_size_bytes

        self.REQUIRED_PADDING_MODES = {'CBC'}
        self.NO_PADDING_MODES = {'CTR'}

    def encrypt_internal(self, text, padder=None):
        if self.mode in self.REQUIRED_PADDING_MODES:
            return self.encryptor.update(padder.update(text))

        return self.encryptor.update(text)

    def encrypt_finalize_internal(self, padder=None):
        if self.mode in self.REQUIRED_PADDING_MODES:
            return self.encryptor.update(padder.finalize()) + self.encryptor.finalize()

        return self.encryptor.finalize()

    def encrypt(self, file_path):
        # Read file as bytes
        ciphertext = []
        padder = padding.PKCS7(self.BLOCK_SIZE_BITS).padder()
        with open(file_path, 'rb') as fd:
            line = fd.read(self.BLOCK_SIZE_BYTES)
            while line:
                ciphertext.append(self.encrypt_internal(line, padder))
                line = fd.read(self.BLOCK_SIZE_BYTES)

        # Finalize with the last block with padding
        ciphertext.append(self.encrypt_finalize_internal(padder))

        return ciphertext

    def decrypt_internal(self, ciphertext, unpadder=None):
        if self.mode in self.REQUIRED_PADDING_MODES:
            padded_plaintext = self.decryptor.update(ciphertext)
            return unpadder.update(padded_plaintext)

        return self.decryptor.update(ciphertext)

    def decrypt_finalize_internal(self, unpadder=None):
        if self.mode in self.REQUIRED_PADDING_MODES:
            return unpadder.update(self.decryptor.finalize()) + unpadder.finalize()

        return self.decryptor.finalize()

    def decrypt(self, ciphertext):
        unpadder = padding.PKCS7(self.BLOCK_SIZE_BITS).unpadder()
        plaintext = []

        for c in ciphertext:
            plaintext.append(self.decrypt_internal(c, unpadder))

        final = self.decrypt_finalize_internal(unpadder)
        if final:
            plaintext.append(final)
        return plaintext

    def run(self, file_path):
        ciphertext = self.encrypt(file_path)
        plaintext = self.decrypt(ciphertext)
        return plaintext
