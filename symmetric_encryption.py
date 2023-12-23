# encryption_utils.py
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding


def encrypt_data(key, data):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        salt=b'saltsalt',
        iterations=100000,
        length=32,
        backend=default_backend()
    )
    derived_key = kdf.derive(key.encode('utf-8'))

    cipher = Cipher(algorithms.AES(derived_key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()

    # Add PKCS7 padding to the data
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data.encode('utf-8')) + padder.finalize()


    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    return encrypted_data


def decrypt_data(key, encrypted_data):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        salt=b'saltsalt',
        iterations=100000,
        length=32,
        backend=default_backend()
    )
    derived_key = kdf.derive(key.encode('utf-8'))

    cipher = Cipher(algorithms.AES(derived_key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # Remove PKCS7 padding
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
    print(f"Decrypted data: {unpadded_data}")


    return unpadded_data.decode('utf-8')
