import os
from tempfile import NamedTemporaryFile
from unittest import TestCase
from unittest.mock import patch

from pyhap.config import (
    Config,
    ControllerPermission,
    JsonConfig,
)

SERVER_IP = '0.0.0.0'
DEFAULT_SERVER_PORT = 8080
DEVICE_ID_MOCK = '7B:45:9B:C1:33:42:FB:96'
MODEL_NAME = 'PyHAP'
SERVICE_TYPE = '_hap._tcp.local.'
SIGNING_KEY_MOCK = 'f4e786f11fb7a172fe07a9801aede0c80deffe661ae9cf37423ee1943a8321ed'
SETUP_CODE_MOCK = '925-52-789'

PARING_ID = 'test pairing'
PUBLIC_KEY = b'test_public_key'

NOT_AVAILABLE_FILE = '/tmp/not-available-ff6adf36-fdbb-402b-9ac7-5783e58381e8.json'


class TestConfig(TestCase):
    def setUp(self):
        self.patch_generate_device_id = patch('pyhap.config.generate_device_id', new=lambda: DEVICE_ID_MOCK)
        self.addCleanup(self.patch_generate_device_id.stop)
        self.patch_generate_device_id.start()

        self.patch_generate_signing_key = patch('pyhap.config.generate_signing_key', new=lambda: SIGNING_KEY_MOCK)
        self.addCleanup(self.patch_generate_signing_key.stop)
        self.patch_generate_signing_key.start()

        self.patch_generate_setup_code = patch('pyhap.config.generate_setup_code', new=lambda: SETUP_CODE_MOCK)
        self.addCleanup(self.patch_generate_setup_code.stop)
        self.patch_generate_setup_code.start()

        if os.path.exists(NOT_AVAILABLE_FILE):
            os.remove(NOT_AVAILABLE_FILE)

        self.config_fp = NamedTemporaryFile()
        self.config = JsonConfig(SERVER_IP, self.config_fp.name)

    def tearDown(self):
        self.config_fp.close()

    def test_server_ip(self):
        self.assertEqual(self.config.server_ip, SERVER_IP)

    def test_server_port(self):
        self.assertEqual(self.config.server_port, DEFAULT_SERVER_PORT)

    def test_device_id(self):
        self.assertEqual(self.config.device_id, DEVICE_ID_MOCK)

    def test_configuration_number(self):
        self.assertEqual(self.config.configuration_number, 1)

    def test_model_name(self):
        self.assertEqual(self.config.model_name, MODEL_NAME)

    def test_service_type(self):
        self.assertEqual(self.config.service_type, SERVICE_TYPE)

    def test_unsuccessful_authentication_attempts(self):
        self.assertEqual(self.config.unsuccessful_authentication_attempts, 0)

    def test_accessory_ltsk(self):
        self.assertEqual(self.config.accessory_ltsk.hex(), SIGNING_KEY_MOCK)

    def test_setup_code(self):
        self.assertEqual(self.config.setup_code, SETUP_CODE_MOCK)

    def test_pair_setup_mode(self):
        self.assertFalse(self.config.pair_setup_mode)
        self.config.pair_setup_mode = True
        self.assertTrue(self.config.pair_setup_mode)

    def test_paired(self):
        self.assertFalse(self.config.paired)

    def test_crud_pairings(self):
        self.assertEqual(self.config.get_pairings(), [])
        self.config.add_pairing(PARING_ID, PUBLIC_KEY, ControllerPermission.admin)
        self.assertEqual(self.config.get_pairings(), [(PARING_ID, PUBLIC_KEY, ControllerPermission.admin)])
        self.assertEqual(self.config.get_pairing(PARING_ID), (PARING_ID, PUBLIC_KEY, ControllerPermission.admin))
        self.config.remove_pairing(PARING_ID)
        self.assertEqual(self.config.get_pairings(), [])
        self.assertEqual(self.config.get_pairing('not exists'), (None, None, None))

    def test_load_save(self):
        config = Config(SERVER_IP)

        with self.assertRaises(NotImplementedError):
            config.load()

        with self.assertRaises(NotImplementedError):
            config.save()

    def test_json_file_not_found(self):
        config = JsonConfig(SERVER_IP, config_filepath=NOT_AVAILABLE_FILE)
        self.assertIsInstance(config, JsonConfig)
