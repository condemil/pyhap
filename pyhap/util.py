import colorsys
import json
from hashlib import blake2b  # pylint: disable=no-name-in-module
from os import urandom
from random import randint
from typing import Tuple
from uuid import UUID


def generate_device_id() -> str:
    """Generates 8 random bytes joined by semicolon"""
    return ':'.join(urandom(1).hex().upper() for _ in range(8))


def generate_signing_key() -> str:
    """Generated 32 random bytes and returns hex representation"""
    return urandom(32).hex()


def generate_setup_code() -> str:
    """Generates numeric setup code in the following format: ddd-dd-ddd"""
    return '{:03d}-{:02d}-{:03d}'.format(randint(0, 999), randint(0, 99), randint(0, 999))


def uuid_to_aduuid(uuid: UUID) -> str:
    """Converts Apple-defined UUID to a short form

    Includes only the first 8 characters with leading zeros removed

    In case of non-Apple-defined UUID returns full UUID
    """
    if str(uuid).endswith('-0000-1000-8000-0026bb765291'):
        first_part = str(uuid).split('-')[0]
        return first_part.lstrip('0').upper()

    return str(uuid).upper()


def aduuid_to_uuid(uuid: str) -> UUID:
    """Converts a short form of Apple-defined UUID to UUID

    In case of non-Apple-defined UUID returns full UUID back
    """
    if len(uuid) > 8:
        return UUID(uuid)

    if len(uuid) < 8:
        leading_zeros = '0' * (8 - len(uuid))
        uuid = leading_zeros + uuid

    return UUID(uuid + '-0000-1000-8000-0026bb765291')


def serial_number_hash(data: str) -> str:
    """Hashes any string to 6 bytes serial number

    Example: 'PyHAP' -> '3331779EC7A8'

    Hash function is BLAKE2b with 6 bytes digest size
    """
    h = blake2b(digest_size=6)  # type: ignore
    h.update(data.encode())
    return h.hexdigest().upper()


def hs_to_rgb(hue: int, saturation: int) -> Tuple[int, int, int]:
    red, green, blue = colorsys.hsv_to_rgb(hue/360, saturation/100, 1)
    return round(red * 255), round(green * 255), round(blue * 255)


class CustomJSONEncoder(json.JSONEncoder):
    def default(self, o):  # pylint: disable=method-hidden
        if hasattr(o, '__json__'):
            return o.__json__()
        return json.JSONEncoder.default(self, o)
