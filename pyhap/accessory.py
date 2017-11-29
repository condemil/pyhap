from logging import getLogger
from typing import (
    Any,
    Callable,
    Dict,
    Iterable,
    Iterator,
    List,
    Optional,
    Tuple,
)

from pyhap.config import HAPStatusCode
from pyhap.characteristic import (
    Characteristic,
    CharacteristicPermission,
    T as CHARACTERISTIC_VALUE,
)
from pyhap.characteristics import (
    FirmwareRevision,
    HardwareRevision,
    Identify,
    Manufacturer,
    Model,
    Name,
    SerialNumber,
)
from pyhap.service import Service
from pyhap.service import AccessoryInformationService
from pyhap.util import (
    serial_number_hash,
    uuid_to_aduuid,
)

logger = getLogger('pyhap')
IdentifyCallback = Optional[Callable[..., None]]


class Accessory:
    def __init__(self, name: str, model: str, manufacturer: str, serial_number: Optional[str] = None,
                 firmware_revision: str = '0.0.1', hardware_revision: Optional[str] = None,
                 identify_callback: IdentifyCallback = None) -> None:
        self._accessory_id: int = None  # set by bridge
        self.services: List[Service] = []
        self.characteristics: Dict[int, Characteristic] = {}
        self.object_count = 1
        self._identify_callback = identify_callback

        if not serial_number:
            serial_number = serial_number_hash(name)

        accessory_information = AccessoryInformationService()

        characteristics = (Name(name), Model(model), Manufacturer(manufacturer), SerialNumber(serial_number),
                           FirmwareRevision(firmware_revision), Identify())

        for characteristic in characteristics:
            accessory_information.add_characteristic(characteristic)

        if hardware_revision:
            accessory_information.add_characteristic(HardwareRevision(hardware_revision))

        self.add_service(accessory_information)

    @property
    def accessory_id(self) -> int:
        return self._accessory_id

    @accessory_id.setter
    def accessory_id(self, value: int):
        for characteristic in self.characteristics.values():
            characteristic.accessory_id = value
        self._accessory_id = value

    def add_service(self, service: Service):
        service.instance_id = self.object_count
        self.object_count += 1

        for characteristic in service.characteristics:
            characteristic.instance_id = self.object_count
            self.characteristics[characteristic.instance_id] = characteristic
            self.object_count += 1

        self.services.append(service)

    def get_characteristic(self, characteristic_id: int) -> Characteristic:
        characteristic = self.characteristics[characteristic_id]
        return characteristic

    async def identify(self):
        if self._identify_callback:
            await self._identify_callback(self)

    def __json__(self):
        return {
            'aid': self.accessory_id,
            'services': self.services,
        }


class Accessories(Iterable):
    # TODO: checks p.92
    def __init__(self, bridge: Optional[Accessory] = None) -> None:  # pylint: disable=super-init-not-called
        self.accessories: Dict[int, Accessory] = {}
        self.accessory_count = 0

        if not bridge:
            bridge = Accessory(name='PyHAP', model='PyHAP1,1', manufacturer='PyHAP')
        self.add(bridge)

    def __iter__(self) -> Iterator[Accessory]:
        for value in self.accessories.values():
            yield value

    def add(self, accessory):
        self.accessory_count += 1
        accessory.accessory_id = self.accessory_count
        self.accessories[accessory.accessory_id] = accessory

    def get_characteristic(self, accessory_id: int, characteristic_id: int) -> Characteristic:
        return self.accessories[accessory_id].get_characteristic(characteristic_id)

    def read_characteristic(self, query: dict) -> Tuple[bool, dict]:
        data = query['id'].split(',')
        include_metadata = query.get('meta', 0)
        include_permissions = query.get('perms', 0)
        include_type = query.get('type', 0)
        include_ev = query.get('ev', 0)
        result = []
        has_errors = False

        for item in data:
            accessory_id, characteristic_id = item.split('.')
            item_result: Dict[str, Any] = {
                'aid': int(accessory_id),
                'iid': int(characteristic_id),
            }
            characteristic = self.get_characteristic(int(accessory_id), int(characteristic_id))

            if CharacteristicPermission.pair_read in characteristic.permissions:
                item_result['value'] = characteristic.value
            else:
                item_result['status'] = HAPStatusCode.write_only.value
                has_errors = True

            if include_metadata:
                # TODO add metadata if include_metadata in params
                pass
            if include_permissions:
                item_result['perms'] = characteristic.serialize_permissions()
            if include_type:
                item_result['type'] = uuid_to_aduuid(characteristic.characteristic_uuid)
            if include_ev:
                # TODO include events, implement events p.89
                pass

            result.append(item_result)

        if has_errors:
            # all characteristics should have status in case at least one have failed
            for item in result:
                item['status'] = item.get('status', HAPStatusCode.success.value)

        return has_errors, {'characteristics': result}

    async def write_characteristic(self, data: list) -> list:
        result = []
        has_errors = False
        for item in data:
            item_result = {
                'aid': item['aid'],
                'iid': item['iid'],
            }
            characteristic = self.get_characteristic(item['aid'], item['iid'])

            if CharacteristicPermission.pair_write not in characteristic.permissions:
                item_result['status'] = HAPStatusCode.read_only.value
                result.append(item_result)
                has_errors = True
                continue

            value = item.get('value')
            old_value = characteristic.value

            if value:
                characteristic.value = value
            elif characteristic.characteristic_format == 'bool':  # value is None
                characteristic.value = False
            elif characteristic.characteristic_format == 'int':  # value is None
                characteristic.value = 0
            elif characteristic.characteristic_format == 'float':  # value is None
                characteristic.value = 0.0

            result.append(item_result)
            await self.fire_callbacks(characteristic, old_value)

        if has_errors:
            return result

        return []

    @staticmethod
    async def fire_callbacks(characteristic: Characteristic, old_value: CHARACTERISTIC_VALUE):
        if characteristic.value != old_value:
            for callback in characteristic.callbacks:
                await callback(characteristic.value)  # type: ignore

    def __json__(self):
        return {
            'accessories': list(self.accessories.values())
        }
