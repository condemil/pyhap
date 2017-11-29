import asyncio
import json
from unittest import TestCase
from unittest.mock import Mock

from test import AsyncMock
from pyhap.accessory import (
    Accessories,
    Accessory,
)
from pyhap.characteristic import Characteristic
from pyhap.characteristics import (
    Brightness,
    On,
    Hue,
)
from pyhap.service import LightbulbService
from pyhap.util import CustomJSONEncoder


class TestAccessories(TestCase):
    def test_add(self):
        accessories = Accessories()
        accessory = Mock()

        self.assertEqual(accessories.accessory_count, 1)
        accessories.add(accessory)
        self.assertEqual(accessory.accessory_id, 2)
        self.assertEqual(accessories.accessories[2], accessory)
        self.assertEqual(accessories.accessory_count, 2)

    def test_iter(self):
        accessories = Accessories()

        for a in accessories:
            self.assertEqual(a, accessories.accessories[1])

    @staticmethod
    def test_identify():
        callback = AsyncMock()
        accessory = Accessory(name='test_name', model='test_model', manufacturer='test_manufacturer',
                              identify_callback=callback)
        asyncio.get_event_loop().run_until_complete(accessory.identify())
        callback.assert_called_once()

    def test_get_characteristic(self):
        accessories = Accessories()
        characteristic = accessories.get_characteristic(1, 2)
        self.assertIsInstance(characteristic, Characteristic)

    def test_read_characteristic(self):
        accessories = Accessories()
        error, characteristics = accessories.read_characteristic({
            'id': '1.2,1.3',
            'meta': '1',
            'perms': '1',
            'type': '1',
            'include_ev': '1',
        })

        self.assertFalse(error)

        self.assertEqual(characteristics['characteristics'][0], {
            'aid': 1,
            'iid': 2,
            'value': 'PyHAP',
            'perms': ['pr'],
            'type': '23',
        })

        self.assertEqual(characteristics['characteristics'][1], {
            'aid': 1,
            'iid': 3,
            'value': 'PyHAP1,1',
            'perms': ['pr'],
            'type': '21',
        })

    def test_read_characteristic_write_only(self):
        accessories = Accessories()
        error, characteristics = accessories.read_characteristic({'id': '1.7'})

        self.assertTrue(error)

        self.assertEqual(characteristics['characteristics'][0], {
            'aid': 1,
            'iid': 7,
            'status': -70405,
        })

    def test_write_characteristic(self):
        accessory = Accessory(name='PyHAP', model='PyHAP1,1', manufacturer='PyHAP', hardware_revision='0')
        service = LightbulbService()

        bool_characteristic = On(False)
        int_characteristic = Brightness(8)
        float_characteristic = Hue(5.0)

        service.add_characteristic(bool_characteristic)
        service.add_characteristic(int_characteristic)
        service.add_characteristic(float_characteristic)

        accessories = Accessories()
        accessory.add_service(service)
        accessories.add(accessory)

        callback = AsyncMock()
        bool_characteristic.callbacks.append(callback)

        self.assertEqual(bool_characteristic.value, False)
        result = asyncio.get_event_loop().run_until_complete(
            accessories.write_characteristic([{'aid': 2, 'iid': 10, 'value': True}])
        )
        callback.assert_called_once_with(True)
        self.assertEqual(result, [])
        self.assertEqual(bool_characteristic.value, True)

        # None value with bool format
        self.assertEqual(bool_characteristic.value, True)
        result = asyncio.get_event_loop().run_until_complete(
            accessories.write_characteristic([{'aid': 2, 'iid': 10, 'value': None}])
        )
        self.assertEqual(result, [])
        self.assertEqual(bool_characteristic.value, False)

        # None value with int format
        self.assertEqual(int_characteristic.value, 8)
        result = asyncio.get_event_loop().run_until_complete(
            accessories.write_characteristic([{'aid': 2, 'iid': 11, 'value': None}])
        )
        self.assertEqual(result, [])
        self.assertEqual(int_characteristic.value, 0)

        # None value with float format
        self.assertEqual(float_characteristic.value, 5.0)
        result = asyncio.get_event_loop().run_until_complete(
            accessories.write_characteristic([{'aid': 2, 'iid': 12, 'value': None}])
        )
        self.assertEqual(result, [])
        self.assertEqual(float_characteristic.value, 0.0)

    def test_write_characteristic_read_only(self):
        accessories = Accessories()

        result = asyncio.get_event_loop().run_until_complete(
            accessories.write_characteristic([{'aid': 1, 'iid': 2, 'value': 'test_value'}])
        )

        self.assertEqual(result, [{
            'aid': 1,
            'iid': 2,
            'status': -70404,
        }])

    # pylint: disable=line-too-long
    def test_json(self):
        accessories = Accessories()
        result = json.loads(json.dumps(accessories.__json__(), cls=CustomJSONEncoder))
        self.assertEqual(result, {
            'accessories': [{
                'aid': 1,
                'services': [{
                    'type': '3E',
                    'iid': 1,
                    'characteristics': [
                        {'type': '23', 'perms': ['pr'], 'format': 'string', 'aid': 1, 'iid': 2, 'value': 'PyHAP', 'maxLen': 64},
                        {'type': '21', 'perms': ['pr'], 'format': 'string', 'aid': 1, 'iid': 3, 'value': 'PyHAP1,1', 'maxLen': 64},
                        {'type': '20', 'perms': ['pr'], 'format': 'string', 'aid': 1, 'iid': 4, 'value': 'PyHAP', 'maxLen': 64},
                        {'type': '30', 'perms': ['pr'], 'format': 'string', 'aid': 1, 'iid': 5, 'value': '3331779EC7A8', 'maxLen': 64},
                        {'type': '52', 'perms': ['pr'], 'format': 'string', 'aid': 1, 'iid': 6, 'value': '0.0.1', 'maxLen': 64},
                        {'type': '14', 'perms': ['pw'], 'format': 'bool', 'aid': 1, 'iid': 7}
                    ]
                }]
            }]
        })
