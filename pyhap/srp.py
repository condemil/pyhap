from hashlib import sha512
from os import urandom
from typing import Union

N_3072 = int(
    'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08'
    '8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B'
    '302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9'
    'A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6'
    '49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8'
    'FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D'
    '670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C'
    '180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718'
    '3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D'
    '04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7D'
    'B3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D226'
    '1AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200C'
    'BBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFC'
    'E0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF', 16)

g = 5
g_padded = g.to_bytes(384, byteorder='big')  # left padded with 0x00 bytes to extend length to 3072 bits (384 bytes)


def H(*args: Union[bytes, int]) -> bytes:
    h = sha512()
    for arg in args:
        if isinstance(arg, int):
            arg = to_bytes(arg)
        h.update(arg)
    return h.digest()


def calculate_M(I: bytes, s: bytes, A: int, B: int, K) -> bytes:
    H_xor = bytes(map(lambda i: i[0] ^ i[1], zip(H(g), H(N_3072))))
    return H(H_xor, H(I), s, A, B, K)


def to_bytes(data: int) -> bytes:
    return data.to_bytes((data.bit_length() + 7) // 8, byteorder='big')


def to_int(data: bytes) -> int:
    return int.from_bytes(data, byteorder='big')


def generate_salt() -> bytes:
    return urandom(16)


def generate_private_key() -> int:
    return to_int(urandom(32))


class Srp:
    """ SRP 6a protocol implementation (server part)

    Accessory is a server and iOS device is a client

    A - client public key
    B - server public key
    b - server private key
    H_AMK - server proof of session key
    I - username
    K - session key
    M - client proof of session key
    S - premaster secret
    s - salt
    u - random scrambling parameter
    v - server password verifier
    """
    def __init__(self, username: str, password: str) -> None:
        self.I = username.encode()
        self.s = generate_salt()
        self.b = generate_private_key()
        k = to_int(H(N_3072, g_padded))
        x = to_int(H(self.s, H(username.encode() + b':' + password.encode())))
        self.v = pow(g, x, N_3072)
        self.B: int = (k * self.v + pow(g, self.b, N_3072)) % N_3072
        self.u: int = None
        self.S: int = None
        self.K: bytes = None
        self.M: bytes = None
        self.H_AMK: bytes = None

    @property
    def public_key(self) -> bytes:
        return to_bytes(self.B)

    @property
    def salt(self) -> bytes:
        return self.s

    @property
    def session_key_proof(self) -> bytes:
        return self.H_AMK

    @property
    def session_key(self) -> bytes:
        return self.K

    def compute_shared_session_key(self, A: bytes) -> None:
        A_int = to_int(A)
        self.u = to_int(H(A_int, self.B))
        self.S = pow(A_int * pow(self.v, self.u, N_3072), self.b, N_3072)
        self.K = H(self.S)
        self.M = calculate_M(self.I, self.s, A_int, self.B, self.K)
        self.H_AMK = H(A_int, self.M, self.K)

    def verify_proof(self, M: bytes) -> bool:
        return M == self.M
