import struct
from enum import Enum, IntEnum
from io import BytesIO
from typing import (
    Dict,
    List,
    Tuple,
    Union,
)


class TlvMethod(IntEnum):
    reserved = 0
    pair_setup = 1
    pair_verify = 2
    add_pairing = 3
    remove_pairing = 4
    list_pairings = 5


class TlvError(IntEnum):
    unknown = 0x01  # generic error to handle unexpected errors
    authentication = 0x02  # setup code or signature verification failed
    backoff = 0x03  # client must look at the retry delay tlv item and wait that many seconds before retrying
    max_peers = 0x04  # server cannot accept any more pairings
    max_tries = 0x05  # server reached its maximum number of authentication attempts
    unavailable = 0x06  # server pairing method is unavailable
    busy = 0x07  # server busy and cannot accept pairing request at this time


class TlvCode(Enum):
    method = 0x00  # method to use for pairing
    identifier = 0x01  # identifier for authentication
    salt = 0x02  # 16+ bytes of random salt
    public_key = 0x03  # curve25519, srp public key or signed ed25519 key
    proof = 0x04  # ed25519 or srp proof
    encrypted_data = 0x05  # encrypted data with auth tag at end
    state = 0x06  # state of the pairing process
    error = 0x07  # error code, must only be present if error code is not 0
    retry_delay = 0x08  # seconds to delay until retrying a setup code
    certificate = 0x09  # x.509 certificate
    signature = 0x0a  # ed25519
    permissions = 0x0b  # bit value describing permissions of the controller being added, 0 - regular user, 1 - admin
    fragment_data = 0x0c  # non-last fragment of data, if length is 0, it is ack
    fragment_last = 0x0d  # last fragment data
    separator = 0xff  # zero-length tlv that separates different tlvs in a list


class TlvState(IntEnum):
    m1 = 0x01
    m2 = 0x02
    m3 = 0x03
    m4 = 0x04
    m5 = 0x05
    m6 = 0x06


class TlvParser:
    def __init__(self, values: List[Tuple[TlvCode, type]]) -> None:
        self.code_type_map: Dict[TlvCode, type] = {}

        for value, data_type in values:
            self.code_type_map[value] = data_type

    @staticmethod
    def get_by_code(code: int) -> TlvCode:
        return TlvCode(code)

    @staticmethod
    def get_by_name(name: str) -> TlvCode:
        result = None
        try:
            result = TlvCode[name]
        except KeyError:
            pass

        if not result:
            raise ValueError(f'Unable to identify TlvCode for {name}')

        return result

    @staticmethod
    def get_name(code: int) -> str:
        return TlvCode(code).name

    def get_type(self, code: TlvCode) -> type:
        result = None
        try:
            result = self.code_type_map[code]
        except KeyError:
            pass

        if not result:
            raise ValueError(f'Unable to identify type for {code}')

        return result

    def decode(self, data: bytes) -> List[dict]:
        """Decodes tlv byte stream.

        Supports merging records with same tlv code.
        Returns list of entries separated by TlvCode.separator.
        """
        result = []
        entry: dict = {}
        previous_tlv_code = None
        with BytesIO(data) as f:
            while True:
                tlv_code_raw: bytes = f.read(1)
                if not tlv_code_raw:
                    break
                tlv_code = self.get_by_code(int.from_bytes(tlv_code_raw, 'little'))
                tlv_size = int.from_bytes(f.read(1), 'little')

                if tlv_code == TlvCode.separator:
                    result.append(entry)
                    entry = {}
                    continue

                raw_tlv_data = f.read(tlv_size)
                tlv_type = self.get_type(tlv_code)
                tlv_data: Union[str, int, bytes]
                if tlv_type == str:
                    try:
                        tlv_data = raw_tlv_data.decode()  # type: ignore
                    except UnicodeDecodeError:
                        tlv_data = None
                    if not tlv_data:
                        raise ValueError(f'Unable to decode {tlv_code} string from bytes: {raw_tlv_data.hex()}')
                if tlv_type == int:
                    if tlv_size != 1:
                        raise ValueError('Only short (1-byte length) integers is supported')
                    tlv_data = int.from_bytes(raw_tlv_data, 'little')  # type: ignore
                if tlv_type == bytes:
                    tlv_data = raw_tlv_data

                if tlv_code == previous_tlv_code:
                    entry[tlv_code] = entry[tlv_code] + tlv_data  # append data to previous tlv
                else:
                    entry[tlv_code] = tlv_data

                previous_tlv_code = tlv_code

            result.append(entry)

        return result

    def encode(self, data: List[dict]) -> bytes:
        result = b''
        for i, entry in enumerate(data):
            if i != 0:
                # add separator
                result += struct.pack('<B', TlvCode.separator.value)
                result += b'\x00'  # length of separator is 0

            for tlv, tlv_data in entry.items():
                tlv_type = self.get_type(tlv)

                if tlv_type == int:
                    result += struct.pack('<B', tlv.value)
                    result += b'\x01'  # length of integer, only short (1-byte length) integers is supported
                    result += struct.pack('<B', tlv_data)
                    continue

                if tlv_type == str:
                    tlv_data = tlv_data.encode()

                with BytesIO(tlv_data) as f:
                    while True:
                        chunk = f.read(255)  # read up to 255 bytes per tlv chunk
                        if not chunk:
                            break
                        result += struct.pack('<B', tlv.value)
                        result += struct.pack('<B', len(chunk))
                        result += chunk
        return result


tlv_parser = TlvParser([
    (TlvCode.method, int),
    (TlvCode.identifier, str),
    (TlvCode.salt, bytes),
    (TlvCode.public_key, bytes),
    (TlvCode.proof, bytes),
    (TlvCode.encrypted_data, bytes),
    (TlvCode.state, int),
    (TlvCode.error, int),
    (TlvCode.retry_delay, int),
    (TlvCode.certificate, bytes),
    (TlvCode.signature, bytes),
    (TlvCode.permissions, int),
    (TlvCode.fragment_data, bytes),
    (TlvCode.fragment_last, bytes),
    (TlvCode.separator, None),
])
