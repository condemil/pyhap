"""Configuration of PyHAP accessory"""

import json
from abc import abstractmethod
from enum import Enum, Flag
from typing import (
    List,
    Optional,
    Tuple,
)

from pyhap.util import (
    CustomJSONEncoder,
    generate_device_id,
    generate_setup_code,
    generate_signing_key,
)


class StatusFlag(Flag):
    """Accessory status"""
    not_paired = 0x01  # accessory has not been paired with any controllers
    no_wifi_configured = 0x02  # accessory has not been configured to join a Wi-Fi network
    problem = 0x04  # a problem has been detected on the accessory


class AccessoryCategory(Enum):
    """Available categories that represents accessory type"""
    other = 1
    bridge = 2
    fan = 3
    garage = 4
    lightbulb = 5
    door_lock = 6
    outlet = 7
    switch = 8
    thermostat = 9
    sensor = 10
    security_system = 11
    door = 12
    window = 13
    window_covering = 14
    programmable_switch = 15
    range_extender = 16
    ip_camera = 17
    video_door_bell = 18
    air_purifier = 19


class ControllerPermission(Enum):
    """Permission of paired controller"""
    user = 0x00
    admin = 0x01


class HAPStatusCode(Enum):
    success = 0
    insufficient_privileges = -70401
    service_unavailable = -70402
    resource_busy = -70403
    read_only = -70404
    write_only = -70405
    no_notification = -70406
    out_of_resources = -70407
    timeout = -70408
    resource_not_exists = -70409
    invalid_value = -70410
    insufficient_authorization = -70411


Pairing = Tuple[Optional[str], Optional[bytes], Optional[ControllerPermission]]


class Config:
    """Contains required configuration values for PyHAP accessory"""
    def __init__(self, server_ip: str) -> None:
        self._server_ip = server_ip
        self._server_port: int
        self._device_id: str
        self._configuration_number: int
        self._setup_code: str
        self._pair_setup_mode: bool = False
        self._pairings: dict
        self._accessory_ltsk: str

    @property
    def server_ip(self) -> str:
        """Web server IP to listen for HTTP requests"""
        return self._server_ip

    @property
    def server_port(self) -> int:
        """Web server port to listen for HTTP requests"""
        return self._server_port

    @property
    def device_id(self) -> str:
        """Also known as Accessory's Pairing Identifier (AccessoryPairingID)

        Unique random number, must be regenerated at every 'factory reset'.

        Must be formatted as 'XX:XX:XX:XX:XX:XX', where 'XX' is a hex byte.
        """
        return self._device_id

    @property
    def configuration_number(self) -> int:
        """Current configuration number.

        Must be incremented when accessory, service, or characteristic is added or removed.
        Maximum value must be uint32 and it should start over from 1 after overflow.
        """
        return self._configuration_number

    # TODO: add configuration number setter with overflow handling and saving config after change

    @property
    def model_name(self) -> str:
        """Model name of the accessory"""
        return 'PyHAP'

    @property
    def service_type(self) -> str:
        """Fully qualified service type name"""
        return '_hap._tcp.local.'

    @property
    def unsuccessful_authentication_attempts(self) -> int:
        """How many times accessory end up with unsuccessful authentication attempt"""
        # TODO: add proper increment
        return 0

    @property
    def accessory_ltsk(self) -> bytes:
        """Accessory's Ed25519 long-term secret key"""
        return bytes(bytearray.fromhex(self._accessory_ltsk))

    @property
    def setup_code(self) -> str:
        """Setup code is used to pair with iOS device"""
        return self._setup_code

    @property
    def pair_setup_mode(self) -> bool:
        """Returns True in case accessory is currently performing a pair setup operation"""
        return self._pair_setup_mode

    @pair_setup_mode.setter
    def pair_setup_mode(self, value: bool) -> None:
        """Set to True in case accessory is currently performing a pair setup operation"""
        self._pair_setup_mode = value

    @property
    def paired(self) -> bool:
        """Returns True in case accessory has paired controllers"""
        return len(self._pairings) > 0

    def add_pairing(self, ios_device_pairing_id: str, ios_device_public_key: bytes, permission: ControllerPermission):
        self._pairings[ios_device_pairing_id] = (ios_device_pairing_id, ios_device_public_key.hex(), permission.value)
        self.save()

    def get_pairing(self, ios_device_pairing_id: str) -> Pairing:
        pairing = self._pairings.get(ios_device_pairing_id)
        if not pairing:
            return None, None, None
        return ios_device_pairing_id, bytes(bytearray.fromhex(pairing[1])), ControllerPermission(pairing[2])

    def remove_pairing(self, ios_device_pairing_id: str) -> None:
        if ios_device_pairing_id in self._pairings:
            del self._pairings[ios_device_pairing_id]
            self.save()

    def get_pairings(self) -> List[Pairing]:
        result: List[Pairing] = []
        for _, pairing in self._pairings.items():
            result.append((pairing[0], bytes(bytearray.fromhex(pairing[1])), ControllerPermission(pairing[2])))
        return result

    def from_dict(self, _dict: dict):
        self._server_port = _dict.get('server_port', 8080)
        self._device_id = _dict.get('device_id', generate_device_id())
        self._configuration_number = _dict.get('configuration_number', 1)
        self._setup_code = _dict.get('setup_code', generate_setup_code())
        self._pairings = _dict.get('pairings', {})
        self._accessory_ltsk = _dict.get('accessory_ltsk', generate_signing_key())

    def to_dict(self) -> dict:
        return {
            'server_port': self._server_port,
            'device_id': self._device_id,
            'configuration_number': self._configuration_number,
            'setup_code': self._setup_code,
            'pairings': self._pairings,
            'accessory_ltsk': self._accessory_ltsk,
        }

    @abstractmethod
    def load(self):
        """Loads up config from storage"""
        raise NotImplementedError()

    @abstractmethod
    def save(self):
        """Saves config to storage"""
        raise NotImplementedError()


class JsonConfig(Config):
    def __init__(self, server_ip, config_filepath='pyhap_config.json'):
        super().__init__(server_ip)
        self.config_filepath = config_filepath
        self.load()
        self.save()  # save back just after load to avoid missing values

    def load(self):
        try:
            with open(self.config_filepath) as f:
                self.from_dict(json.load(f))
        except FileNotFoundError:
            self.from_dict({})
        except json.JSONDecodeError:
            self.from_dict({})

    def save(self):
        with open(self.config_filepath, 'w+') as f:
            json.dump(self.to_dict(), f, sort_keys=True, indent=4, cls=CustomJSONEncoder)
