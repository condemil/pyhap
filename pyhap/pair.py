from logging import getLogger
from typing import List

import ed25519
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.hashes import SHA512
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from pyhap.config import (
    Config,
    ControllerPermission,
)
from pyhap.srp import Srp
from pyhap.tlv import (
    TlvCode,
    TlvState,
    TlvError,
    tlv_parser
)

logger = getLogger('pyhap')


MAX_AUTHENTICATION_ATTEMPTS = 100
SRP_USERNAME = 'Pair-Setup'
NONCE_SETUP_M5 = b'\x00\x00\x00\x00PS-Msg05'
NONCE_SETUP_M6 = b'\x00\x00\x00\x00PS-Msg06'
NONCE_VERIFY_M2 = b'\x00\x00\x00\x00PV-Msg02'
NONCE_VERIFY_M3 = b'\x00\x00\x00\x00PV-Msg03'
SALT_CONTROLLER = b'Pair-Setup-Controller-Sign-Salt'
INFO_CONTROLLER = b'Pair-Setup-Controller-Sign-Info'
SALT_ACCESSORY = b'Pair-Setup-Accessory-Sign-Salt'
INFO_ACCESSORY = b'Pair-Setup-Accessory-Sign-Info'
SALT_ENCRYPT = b'Pair-Setup-Encrypt-Salt'
INFO_ENCRYPT = b'Pair-Setup-Encrypt-Info'
SALT_VERIFY = b'Pair-Verify-Encrypt-Salt'
INFO_VERIFY = b'Pair-Verify-Encrypt-Info'
SALT_CONTROL = b'Control-Salt'
INFO_CONTROL_WRITE = b'Control-Write-Encryption-Key'
INFO_CONTROL_READ = b'Control-Read-Encryption-Key'


def srp_start(config: Config, context: dict, expected_tlv_state: TlvState) -> List[dict]:
    """pair_setup M1 and M2"""
    if config.paired:
        return _error(TlvState.m2, TlvError.unavailable, 'Accessory already paired, cannot accept additional pairings')

    if config.unsuccessful_authentication_attempts > MAX_AUTHENTICATION_ATTEMPTS:
        return _error(TlvState.m2, TlvError.max_tries, 'Max authentication attempts reached')

    if expected_tlv_state != TlvState.m1:
        return _error(TlvState.m2, TlvError.unknown, 'Unexpected pair_setup state')

    if config.pair_setup_mode:
        return _error(TlvState.m2, TlvError.busy, 'Currently perform pair setup operation with a different controller')

    config.pair_setup_mode = True
    srp = Srp(SRP_USERNAME, config.setup_code)
    context['srp'] = srp

    return [{
        TlvCode.state: TlvState.m2,
        TlvCode.public_key: srp.public_key,
        TlvCode.salt: srp.salt,
    }]


def srp_verify(context: dict, expected_tlv_state: TlvState, client_public_key: bytes,
               client_proof: bytes) -> List[dict]:
    """pair_setup M3 and M4"""
    srp = context.get('srp')

    if expected_tlv_state != TlvState.m3 or not srp:
        return _error(TlvState.m4, TlvError.unknown, 'Unexpected pair_setup state')

    srp.compute_shared_session_key(client_public_key)

    if not srp.verify_proof(client_proof):
        return _error(TlvState.m4, TlvError.authentication, 'Incorrect setup code, try again')

    return [{
        TlvCode.state: TlvState.m4,
        TlvCode.proof: srp.session_key_proof,
    }]


def exchange(config: Config, context: dict, expected_tlv_state: TlvState, encrypted_data: bytes) -> List[dict]:
    """pair_setup M5 and M6"""
    srp = context.get('srp')

    if expected_tlv_state != TlvState.m5 or not srp:
        return _error(TlvState.m6, TlvError.unknown, 'Unexpected pair_setup state')

    hkdf = HKDF(algorithm=SHA512(), length=32, salt=SALT_ENCRYPT, info=INFO_ENCRYPT, backend=default_backend())
    decrypt_key = hkdf.derive(srp.session_key)

    chacha = ChaCha20Poly1305(decrypt_key)

    try:
        data = chacha.decrypt(NONCE_SETUP_M5, encrypted_data, None)
    except InvalidTag:
        return _error(TlvState.m6, TlvError.authentication, 'pair_setup M5: invalid auth tag during chacha decryption')

    try:
        tlv = tlv_parser.decode(data)[0]
    except ValueError:
        return _error(TlvState.m6, TlvError.authentication, 'unable to decode decrypted tlv data')

    hkdf = HKDF(algorithm=SHA512(), length=32, salt=SALT_CONTROLLER, info=INFO_CONTROLLER, backend=default_backend())
    ios_device_x = hkdf.derive(srp.session_key)
    ios_device_info = ios_device_x + tlv[TlvCode.identifier].encode() + tlv[TlvCode.public_key]

    if not _verify_ed25519(key=tlv[TlvCode.public_key], message=ios_device_info, signature=tlv[TlvCode.signature]):
        return _error(TlvState.m6, TlvError.authentication, 'ios_device_info ed25519 signature verification is failed')

    config.add_pairing(tlv[TlvCode.identifier], tlv[TlvCode.public_key], ControllerPermission.admin)  # save pairing

    # M6 response generation
    hkdf = HKDF(algorithm=SHA512(), length=32, salt=SALT_ACCESSORY, info=INFO_ACCESSORY, backend=default_backend())
    accessory_x = hkdf.derive(srp.session_key)

    signing_key = ed25519.SigningKey(config.accessory_ltsk)
    public_key = signing_key.get_verifying_key().to_bytes()
    accessory_info = accessory_x + config.device_id.encode() + public_key
    accessory_signature = signing_key.sign(accessory_info)

    sub_tlv = tlv_parser.encode([{
        TlvCode.identifier: config.device_id,
        TlvCode.public_key: public_key,
        TlvCode.signature: accessory_signature,
    }])

    encrypted_data = chacha.encrypt(NONCE_SETUP_M6, sub_tlv, None)

    config.pair_setup_mode = False
    return [{
        TlvCode.state: TlvState.m6,
        TlvCode.encrypted_data: encrypted_data,
    }]


def verify_start(config: Config, context: dict, ios_device_public_key: bytes) -> List[dict]:
    """pair_verify M1 and M2"""
    curve25519 = X25519PrivateKey.generate()
    accessory_curve25519_public_key: bytes = curve25519.public_key().public_bytes()
    shared_secret: bytes = curve25519.exchange(X25519PublicKey.from_public_bytes(ios_device_public_key))

    accessory_info: bytes = accessory_curve25519_public_key + config.device_id.encode() + ios_device_public_key
    signing_key = ed25519.SigningKey(config.accessory_ltsk)
    accessory_signature = signing_key.sign(accessory_info)

    sub_tlv = tlv_parser.encode([{
        TlvCode.identifier: config.device_id,
        TlvCode.signature: accessory_signature,
    }])

    hkdf = HKDF(algorithm=SHA512(), length=32, salt=SALT_VERIFY, info=INFO_VERIFY, backend=default_backend())
    session_key = hkdf.derive(shared_secret)

    chacha = ChaCha20Poly1305(session_key)
    encrypted_data = chacha.encrypt(NONCE_VERIFY_M2, sub_tlv, None)

    context['session_key'] = session_key
    context['shared_secret'] = shared_secret
    context['accessory_curve25519_public_key'] = accessory_curve25519_public_key
    context['ios_device_curve25519_public_key'] = ios_device_public_key

    return [{
        TlvCode.state: TlvState.m2,
        TlvCode.public_key: accessory_curve25519_public_key,
        TlvCode.encrypted_data: encrypted_data,
    }]


def verify_finish(config: Config, context: dict, encrypted_data: bytes) -> List[dict]:
    """pair_verify M3 and M4"""
    session_key = context.get('session_key')
    accessory_curve25519_public_key = context.get('accessory_curve25519_public_key')
    ios_device_curve25519_public_key = context.get('ios_device_curve25519_public_key')

    if not session_key or not accessory_curve25519_public_key or not ios_device_curve25519_public_key:
        return _error(TlvState.m4, TlvError.authentication,
                      'verify_finished call before successful verify_start')

    chacha = ChaCha20Poly1305(session_key)

    try:
        data = chacha.decrypt(NONCE_VERIFY_M3, encrypted_data, None)
    except InvalidTag:
        return _error(TlvState.m4, TlvError.authentication, 'invalid auth tag during chacha decryption')

    try:
        tlv = tlv_parser.decode(data)[0]
    except ValueError:
        return _error(TlvState.m4, TlvError.authentication, 'unable to decode decrypted tlv data')

    ios_device_ltpk = config.get_pairing(tlv[TlvCode.identifier])[1]

    if not ios_device_ltpk:
        return _error(TlvState.m4, TlvError.authentication,
                      'unable to find requested ios device in config file')

    ios_device_info = ios_device_curve25519_public_key + tlv[TlvCode.identifier].encode() + \
        accessory_curve25519_public_key

    if not _verify_ed25519(ios_device_ltpk, message=ios_device_info, signature=tlv[TlvCode.signature]):
        return _error(TlvState.m4, TlvError.authentication,
                      'ios_device_info ed25519 signature verification is failed')

    context['paired'] = True
    context['ios_device_pairing_id'] = tlv[TlvCode.identifier]

    hkdf = HKDF(algorithm=SHA512(), length=32, salt=SALT_CONTROL, info=INFO_CONTROL_WRITE, backend=default_backend())
    context['decrypt_key'] = hkdf.derive(context['shared_secret'])

    hkdf = HKDF(algorithm=SHA512(), length=32, salt=SALT_CONTROL, info=INFO_CONTROL_READ, backend=default_backend())
    context['encrypt_key'] = hkdf.derive(context['shared_secret'])

    return [{
        TlvCode.state: TlvState.m4,
    }]


def list_pairings(config: Config) -> List[dict]:
    response: List[dict] = []

    for pairing in config.get_pairings():
        response.append({
            TlvCode.identifier: pairing[0],
            TlvCode.public_key: pairing[1],
            TlvCode.permissions: pairing[2].value,
        })

    if response:
        response[0][TlvCode.state] = TlvState.m2

    return response


def add_pairing(config: Config, ios_device_pairing_id: str, ios_device_public_key: bytes,
                permission: ControllerPermission) -> List[dict]:
    _, saved_ios_device_public_key, _ = config.get_pairing(ios_device_pairing_id)  # type: ignore

    if saved_ios_device_public_key and ios_device_public_key != saved_ios_device_public_key:
        return _error(TlvState.m2, TlvError.unknown,
                      'Received iOS device public key doesn\'t match with previously saved key')

    config.add_pairing(ios_device_pairing_id, ios_device_public_key, permission)

    return [{
        TlvCode.state: TlvState.m2,
    }]


def remove_pairing(config: Config, ios_device_pairing_id: str) -> List[dict]:
    config.remove_pairing(ios_device_pairing_id)

    return [{
        TlvCode.state: TlvState.m2,
    }]


def _error(tlv_state: TlvState, tlv_error: TlvError, reason: str) -> List[dict]:
    logger.error(f'{tlv_state}: {tlv_error} {reason}')
    return [{
        TlvCode.state: tlv_state,
        TlvCode.error: tlv_error,
    }]


def _verify_ed25519(key: bytes, message: bytes, signature: bytes) -> bool:
    verifying_key = ed25519.VerifyingKey(key)

    try:
        verifying_key.verify(signature, message)
        return True
    except ed25519.BadSignatureError:
        return False
