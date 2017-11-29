import json
import re
from unittest import TestCase
from uuid import UUID

from pyhap import util


TEST_SERIAL_NUMBER_HASH = 'C879FBCC3F07'
DEVICE_ID_REGEX = re.compile(r'^([0-9A-Z]{2}:){7}[0-9A-Z]{2}$')
SINGING_KEY_REGEX = re.compile(r'^[0-9a-z]{64}$')
SETUP_CODE_REGEX = re.compile(r'^\d\d\d-\d\d-\d\d\d$')


class TestUtil(TestCase):
    def test_generate_device_id(self):
        self.assertRegex(util.generate_device_id(), DEVICE_ID_REGEX)

    def test_generate_signing_key(self):
        self.assertRegex(util.generate_signing_key(), SINGING_KEY_REGEX)

    def test_generate_setup_code(self):
        self.assertRegex(util.generate_setup_code(), SETUP_CODE_REGEX)

    def test_uuid_to_aduuid(self):
        self.assertEqual(util.uuid_to_aduuid(UUID('00000001-0000-1000-8000-0026BB765291')), '1')
        self.assertEqual(util.uuid_to_aduuid(UUID('00000F25-0000-1000-8000-0026BB765291')), 'F25')
        self.assertEqual(util.uuid_to_aduuid(UUID('0000BBAB-0000-1000-8000-0026BB765291')), 'BBAB')
        self.assertEqual(util.uuid_to_aduuid(UUID('010004FF-0000-1000-8000-0026BB765291')), '10004FF')
        self.assertEqual(util.uuid_to_aduuid(UUID('FF000000-0000-1000-8000-0026BB765291')), 'FF000000')

        random_uuid4 = '69815C8D-2B70-450B-8024-EECE4CC8CE04'
        self.assertEqual(util.uuid_to_aduuid(UUID(random_uuid4)), random_uuid4)

    def test_aduuid_to_uuid(self):
        self.assertEqual(util.aduuid_to_uuid('1'), UUID('00000001-0000-1000-8000-0026BB765291'))
        self.assertEqual(util.aduuid_to_uuid('F25'), UUID('00000F25-0000-1000-8000-0026BB765291'))
        self.assertEqual(util.aduuid_to_uuid('BBAB'), UUID('0000BBAB-0000-1000-8000-0026BB765291'))
        self.assertEqual(util.aduuid_to_uuid('10004FF'), UUID('010004FF-0000-1000-8000-0026BB765291'))
        self.assertEqual(util.aduuid_to_uuid('FF000000'), UUID('FF000000-0000-1000-8000-0026BB765291'))

        random_uuid4 = '69815C8D-2B70-450B-8024-EECE4CC8CE04'
        self.assertEqual(util.aduuid_to_uuid(random_uuid4), UUID(random_uuid4))

    def test_serial_number_hash(self):
        self.assertEqual(util.serial_number_hash('test'), TEST_SERIAL_NUMBER_HASH)

    def test_custom_json_encoder(self):
        test_class = CustomJsonEncoderClass()
        self.assertEqual(json.dumps(test_class, cls=util.CustomJSONEncoder), '{"test_key": "test_value"}')

        with self.assertRaises(TypeError):
            test_normal_class = CustomJsonEncoderNormalClass()
            json.dumps(test_normal_class, cls=util.CustomJSONEncoder)

    def test_hs_to_rgb(self):
        self.assertEqual(util.hs_to_rgb(0, 0), (255, 255, 255))
        self.assertEqual(util.hs_to_rgb(0, 100), (255, 0, 0))
        self.assertEqual(util.hs_to_rgb(359, 0), (255, 255, 255))
        self.assertEqual(util.hs_to_rgb(359, 100), (255, 0, 4))

        self.assertEqual(util.hs_to_rgb(342, 60), (255, 102, 148))
        self.assertEqual(util.hs_to_rgb(243, 51), (131, 125, 255))
        self.assertEqual(util.hs_to_rgb(132, 46), (138, 255, 161))
        self.assertEqual(util.hs_to_rgb(48, 56), (255, 226, 112))

        # degrees over 359
        self.assertEqual(util.hs_to_rgb(0, 80), util.hs_to_rgb(360, 80))
        self.assertEqual(util.hs_to_rgb(10, 80), util.hs_to_rgb(370, 80))


class CustomJsonEncoderClass:
    @staticmethod
    def __json__():
        return {'test_key': 'test_value'}


class CustomJsonEncoderNormalClass:
    def __init__(self):
        self.test_key = 'test_value'
