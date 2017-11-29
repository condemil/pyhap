from unittest import TestCase
from unittest.mock import patch, Mock

from pyhap import pyhap
from pyhap.pyhap import (
    MDNSServer,
    WebServer,
)

class TestPyHAP(TestCase):
    def setUp(self):
        patch_mdns_server = patch('pyhap.pyhap.MDNSServer')
        self.addCleanup(patch_mdns_server.stop)
        self.mock_mdns_server = patch_mdns_server.start()

        patch_web_server = patch('pyhap.pyhap.WebServer')
        self.addCleanup(patch_web_server.stop)
        self.mock_web_server = patch_web_server.start()

    def test_start(self):
        config = Mock()
        accessories = Mock()

        pyhap.start(config, accessories)

        self.mock_mdns_server.assert_called_once_with(config)
        self.mock_mdns_server().start.assert_called_once()

        self.mock_web_server.assert_called_once_with(config, accessories)
        self.mock_web_server().start.assert_called_once()


class TestMDNSServer(TestCase):
    def setUp(self):
        patch_zeroconf = patch('pyhap.pyhap.Zeroconf')
        self.addCleanup(patch_zeroconf.stop)
        self.mock_zeroconf = patch_zeroconf.start()

        patch_service_info = patch('pyhap.pyhap.ServiceInfo')
        self.addCleanup(patch_service_info.stop)
        self.mock_service_info = patch_service_info.start()

        patch_inet_aton = patch('pyhap.pyhap.inet_aton')
        self.addCleanup(patch_inet_aton.stop)
        self.mock_inet_aton = patch_inet_aton.start()

        self.mock_config = Mock()
        self.mdns_server = MDNSServer(self.mock_config)

    def test_update_service(self):
        self.mock_config.model_name = 'test_model_name'
        self.mock_config.service_type = 'test_service_type'
        self.mock_config.configuration_number = 500

        self.mdns_server.update_service()

        self.assertEqual(self.mdns_server.hap_service, self.mock_service_info())
        self.assertEqual(self.mock_service_info.call_args_list[0][1]['type_'], 'test_service_type')
        self.assertEqual(self.mock_service_info.call_args_list[0][1]['name'], 'test_model_name.test_service_type')
        self.assertEqual(self.mock_service_info.call_args_list[0][1]['address'], self.mock_inet_aton())
        self.assertEqual(self.mock_service_info.call_args_list[0][1]['port'], self.mock_config.server_port)
        self.assertEqual(self.mock_service_info.call_args_list[0][1]['properties'], {
            'c#': '500',
            'ff': '0',
            'id': self.mock_config.device_id,
            'md': self.mock_config.model_name,
            'pv': '1.0',
            's#': '1',
            'sf': '1',
            'ci': '2',
        })

    def test_restart(self):
        self.mdns_server.start()

        self.mock_zeroconf().unregister_service = Mock()
        self.mock_zeroconf().register_service = Mock()
        self.mdns_server.restart()

        # stop
        self.mock_zeroconf().unregister_service.assert_called_with(self.mock_service_info())

        # start
        self.mock_service_info.assert_called()
        self.mock_zeroconf().register_service.assert_called_with(self.mock_service_info())

    def test_close(self):
        self.mdns_server.close()
        self.mock_zeroconf().close.assert_called()


class TestWebServer(TestCase):
    def setUp(self):
        patch_route = patch('pyhap.pyhap.route')
        self.addCleanup(patch_route.stop)
        self.mock_route = patch_route.start()

        patch_http_server = patch('pyhap.pyhap.HTTPServer')
        self.addCleanup(patch_http_server.stop)
        self.mock_http_server = patch_http_server.start()

    def test_init(self):
        config = Mock()
        accessories = Mock()

        web_server = WebServer(config, accessories)

        self.assertEqual(web_server.http_server, self.mock_http_server())

    def test_start(self):
        config = Mock()
        accessories = Mock()

        web_server = WebServer(config, accessories)
        web_server.start()

        self.mock_http_server().run.assert_called_once()
