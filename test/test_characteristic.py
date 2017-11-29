from asyncio import get_event_loop
from unittest import TestCase
from uuid import UUID

from test import AsyncMock
from pyhap.characteristics import Name


TEST_ACCESSORY_ID = 5
TEST_INSTANCE_ID = 8
TEST_VALUE = 'test_value'
TEST_NEW_VALUE = 'test_new_value'
TEST_CHARACTERISTIC_SHORT_UUID = '23'
TEST_PERMISSIONS = ['pr']


class TestCharacteristic(TestCase):
    def setUp(self):
        self.callback = AsyncMock()
        self.characteristic = Name(TEST_VALUE, self.callback)

    def test_get_set_value(self):
        self.assertEqual(self.characteristic.value, TEST_VALUE)
        self.characteristic.value = TEST_NEW_VALUE
        self.assertEqual(self.characteristic.value, TEST_NEW_VALUE)
        self.characteristic.value = TEST_VALUE

    def test_characteristic_uuid(self):
        self.assertIsInstance(self.characteristic.characteristic_uuid, UUID)

    def test_get_set_accessory_id(self):
        self.assertEqual(self.characteristic.accessory_id, None)
        self.characteristic.accessory_id = TEST_ACCESSORY_ID
        self.assertEqual(self.characteristic.accessory_id, TEST_ACCESSORY_ID)

    def test_get_set_instance_id(self):
        self.assertEqual(self.characteristic.instance_id, None)
        self.characteristic.instance_id = TEST_INSTANCE_ID
        self.assertEqual(self.characteristic.instance_id, TEST_INSTANCE_ID)

    def test_fire_callbacks(self):
        get_event_loop().run_until_complete(self.characteristic.fire_callbacks())
        self.callback.assert_called_once_with(TEST_VALUE)

    def test_json(self):
        self.characteristic.accessory_id = TEST_ACCESSORY_ID
        self.characteristic.instance_id = TEST_INSTANCE_ID
        self.characteristic.value = TEST_VALUE
        self.assertEqual(self.characteristic.__json__(), {
            'type': TEST_CHARACTERISTIC_SHORT_UUID,
            'perms': TEST_PERMISSIONS,
            'format': 'string',
            'aid': TEST_ACCESSORY_ID,
            'iid': TEST_INSTANCE_ID,
            'value': TEST_VALUE,
            'maxLen': 64,
        })
