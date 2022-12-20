from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import socket

# Generates values for the DH exchange initiator
def send_dh_parameters():
    parameters = dh.generate_parameters(generator=2, key_size=2048)
    private_key = parameters.generate_private_key()
    a = private_key.private_numbers().x
    g = parameters.parameter_numbers().g
    p = parameters.parameter_numbers().p

    gamodp = pow(g, a, p)
    return gamodp, g, p, a

# Generates values for the DH exchange receiver
def receive_dh_parameters(g, p):
    parameters = dh.generate_parameters(generator=2, key_size=2048)
    private_key = parameters.generate_private_key()
    b = private_key.private_numbers().x

    gbmodp = pow(g, b, p)
    return gbmodp, b
