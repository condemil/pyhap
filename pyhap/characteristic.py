from abc import abstractmethod
from enum import Enum
from typing import (
    Callable,
    Generic,
    List,
    Optional,
    Type,
    TypeVar,
)
from uuid import UUID

from pyhap.util import uuid_to_aduuid

T = TypeVar('T', int, float, bool, str, None)


class CharacteristicPermission(Enum):
    pair_read = 'pr'
    pair_write = 'pw'
    notify = 'ev'
    broadcast = 'b'


class Characteristic(Generic[T]):
    def __init__(self, value: T = None, callback: Optional[Callable] = None) -> None:
        self._check_value(value)
        self._value: T = value
        self._accessory_id: int = None  # set by bridge
        self._instance_id: int = None  # set by bridge
        self.callback: Callable = callback

    @property
    def value(self) -> T:
        return self._value

    @value.setter
    def value(self, value: T) -> None:
        self._check_value(value)
        self._value = value

    @property
    @abstractmethod
    def characteristic_uuid(self) -> UUID:
        raise NotImplementedError()  # pragma: no cover

    @property
    @abstractmethod
    def characteristic_type(self) -> Type:
        raise NotImplementedError()  # pragma: no cover

    @property
    @abstractmethod
    def characteristic_format(self) -> str:
        raise NotImplementedError()  # pragma: no cover

    @property
    def permissions(self) -> List[CharacteristicPermission]:
        raise NotImplementedError()  # pragma: no cover

    @property
    def accessory_id(self) -> int:
        return self._accessory_id

    @accessory_id.setter
    def accessory_id(self, value: int):
        self._accessory_id = value

    @property
    def instance_id(self) -> int:
        return self._instance_id

    @instance_id.setter
    def instance_id(self, value: int):
        self._instance_id = value

    def serialize_permissions(self) -> List[str]:
        result = []
        for permission in self.permissions:
            result.append(permission.value)
        return result

    def __json__(self) -> dict:
        result = {
            'type': uuid_to_aduuid(self.characteristic_uuid),
            'perms': self.serialize_permissions(),
            'format': self.characteristic_format,
            'aid': self.accessory_id,
            'iid': self.instance_id,
        }

        if self._value is not None and CharacteristicPermission.pair_read in self.permissions:
            result['value'] = self._value

        if self.characteristic_format == 'string':
            result['maxLen'] = 64

        return result

    def _check_value(self, value: T):
        if not isinstance(value, self.characteristic_type):
            raise ValueError(f'Failed to set value {value} for {self.characteristic_format} characteristic '
                             f'{self.__class__.__name__}')
