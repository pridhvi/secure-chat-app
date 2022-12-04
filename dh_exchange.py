from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import socket

def send_dh_parameters():
    # Generate some parameters. These can be reused.
    parameters = dh.generate_parameters(generator=2, key_size=512)
    # Generate a private key for use in the exchange.
    private_key = parameters.generate_private_key()
    a = private_key.private_numbers().x
    g = parameters.parameter_numbers().g
    p = parameters.parameter_numbers().p
    gamodp = pow(g, a, p)
    return gamodp, g, p, a

def receive_dh_parameters(g, p):
    parameters = dh.generate_parameters(generator=2, key_size=512)

    private_key = parameters.generate_private_key()
    b = private_key.private_numbers().x

    gbmodp = pow(g, b, p)
    return gbmodp, b
