from saes import SimplifiedAES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.strxor import strxor
from Cryptodome.Util.Padding import pad, unpad

class SAES_CBC:
    '''
    This class should implement CBC mode of encryption/decryption for the Simplified AES cipher (saes.py)

    Attributes:
        key (bytes): key for encryption/decryption (must be 2 bytes long)
        iv (bytes): initialisation vector (must be 2 bytes long)
        block_cipher (SimplifiedAES): an instance of the SimplifiedAES cipher class using key
    '''
    def __init__(self, key : bytes, iv : bytes = None) -> None:
        self.blocksize=2
        if len(key) == self.blocksize:
            self.key = key
        else:
            raise ValueError('Key size must be equal to Simplified AES blocksize (2 bytes)')
        if iv is None:
            self.iv = get_random_bytes(self.blocksize)
        else:
            if len(iv) == self.blocksize:
                self.iv = iv
            else:
                raise ValueError('Initialisation vector size must be equal to Simplified AES blocksize (2 bytes)')
        self.block_cipher = SimplifiedAES(self.key)

    def encrypt(self, plaintext: bytes) -> bytes:
        '''
        This function should implement CBC mode of encryption for ``self.block_cipher``

        Parameters:
            plaintext (bytes): plaintext to be encrypted
        Returns:
            bytes: the ciphertext
        '''
        ciphertext = b''
        #TODO: Your code should go here
        prev = self.iv
        for i in range(0, len(plaintext), self.blocksize):
            block_i = plaintext[i:i+self.blocksize]
            xor_result = strxor(block_i, prev)
            block_e = self.block_cipher.encrypt(xor_result)
            ciphertext += block_e
            prev = block_e

        return ciphertext

    def decrypt(self, ciphertext: bytes) -> bytes:
        '''
        This function should implement CBC mode of decryption for ``self.block_cipher``

        Parameters:
            ciphertext (bytes): ciphertext to be decrypted
        Returns:
            bytes: the plaintext
        '''
        plaintext = b''
        #TODO: Your code should go here
        prev = self.iv
        for i in range(0, len(ciphertext), self.blocksize):
            block_i = ciphertext[i:i+self.blocksize]
            block_d = self.block_cipher.decrypt(block_i)
            xor_d = strxor(block_d, prev)
            plaintext += xor_d
            prev = block_i
        return plaintext

if __name__ == '__main__':
    key = get_random_bytes(2)
    print(key.hex())
    iv = get_random_bytes(2)
    print(iv.hex())
    saes_cbc = SAES_CBC(key,iv)
    plaintext = b'The quick brown fox jumps over the lazy dog'
    padded_plaintext = pad(plaintext, 2)
    print(padded_plaintext)
    ciphertext = saes_cbc.encrypt(padded_plaintext)
    print(ciphertext.hex())
    decrypted = saes_cbc.decrypt(ciphertext)
    print(decrypted)
    unpadded_decrypted = unpad(decrypted, 2)
    print(unpadded_decrypted)
