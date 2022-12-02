import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization, hashes, padding as pad
from cryptography.hazmat.primitives.asymmetric import padding
import argparse
import sys

def symmetrical_encrypt(message, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    return aes_cbc_encrypt(message, cipher), iv

def aes_cbc_encrypt(message, cipher):
    message = pad_message(message)
    encryptor = cipher.encryptor()
    enc_message = encryptor.update(message) + encryptor.finalize()
    return enc_message

def pad_message(message):
    padder = pad.PKCS7(128).padder()
    return padder.update(message) + padder.finalize()

# Decrypt the message symmetrically
def symmetrical_decrypt(message, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    return aes_cbc_decrypt(message, cipher)

# AES-CBC Decryption
def aes_cbc_decrypt(enc_message, cipher):
    decryptor = cipher.decryptor()
    message = decryptor.update(enc_message) + decryptor.finalize()
    return unpad_message(message)


# Removing the pad when decrypting
def unpad_message(message):
    unpadder = pad.PKCS7(128).unpadder()
    return unpadder.update(message) + unpadder.finalize()
