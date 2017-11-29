# Autogenerated, do not edit. All changes will be undone.

from typing import List
from uuid import UUID

from pyhap.characteristic import (
    Characteristic,
    CharacteristicPermission,
)


class ConfigureBridgedAccessory(Characteristic):
    @property
    def characteristic_uuid(self) -> UUID:
        return UUID('000000A0-0000-1000-8000-0026BB765291')

    @property
    def characteristic_type(self) -> str:
        return 'public.hap.characteristic.configure.bridged.accessory'

    @property
    def characteristic_format(self) -> str:
        return 'tlv'

    @property
    def permissions(self) -> List[CharacteristicPermission]:
        return [
            CharacteristicPermission.pair_write,
        ]
