import asyncio
from http import HTTPStatus
from unittest import TestCase
from unittest.mock import patch, Mock

from test import AsyncMock
from pyhap import route
from pyhap.config import ControllerPermission
from pyhap.tlv import (
    TlvCode,
    TlvError,
    TlvMethod,
    TlvState,
)


class TestRoute(TestCase):
    def setUp(self):
        self.patch_response = patch('pyhap.route.Response')
        self.addCleanup(self.patch_response.stop)
        self.mock_response = self.patch_response.start()

    def test_accessories(self):
        mock_accessories = 'test_accessories'
        request = Mock()
        request.context = {'encrypted': 'test_encrypted'}
        request.global_context = {'accessories':  mock_accessories}
        response = asyncio.get_event_loop().run_until_complete(route.accessories(request))

        self.mock_response.assert_called_once_with('application/hap+json', data=b'"test_accessories"')
        self.assertEqual(self.mock_response(), response)

    def test_characteristics(self):
        mock_accessories = Mock()
        mock_request = Mock()
        mock_request.context = {'encrypted': 'test_encrypted'}
        mock_request.global_context = {'accessories':  mock_accessories}

        # request.method: unknown
        with self.assertRaises(ValueError):
            asyncio.get_event_loop().run_until_complete(route.characteristics(mock_request))

        # request.method: get
        mock_request.method = 'GET'

        mock_accessories.read_characteristic.return_value = None, 'test_result'

        asyncio.get_event_loop().run_until_complete(route.characteristics(mock_request))

        mock_accessories.read_characteristic.assert_called_with(mock_request.query)
        self.mock_response.assert_called_with('application/hap+json', HTTPStatus.OK, data=b'"test_result"')

        # error status
        mock_accessories.read_characteristic.return_value = 'test_error', 'test_result'

        asyncio.get_event_loop().run_until_complete(route.characteristics(mock_request))

        mock_accessories.read_characteristic.assert_called_with(mock_request.query)
        self.mock_response.assert_called_with('application/hap+json', HTTPStatus.MULTI_STATUS, data=b'"test_result"')

        # request.method: put
        mock_request.method = 'PUT'
        mock_read = AsyncMock(return_value=b'{"characteristics": "test_characteristics"}')
        mock_request.read = mock_read
        mock_accessories.write_characteristic = AsyncMock(return_value=None)

        asyncio.get_event_loop().run_until_complete(route.characteristics(mock_request))

        mock_request.read.assert_called_once()
        mock_accessories.write_characteristic.assert_called_once_with("test_characteristics")
        self.mock_response.assert_called_with(status=HTTPStatus.NO_CONTENT)

        # error status
        mock_accessories.write_characteristic = AsyncMock(return_value='test_error')

        asyncio.get_event_loop().run_until_complete(route.characteristics(mock_request))

        mock_accessories.write_characteristic.assert_called_once_with("test_characteristics")
        self.mock_response.assert_called_with(status=HTTPStatus.MULTI_STATUS, data=b'"test_error"')

    def test_identify(self):
        mock_accessory = Mock()
        mock_accessory.identify = AsyncMock()
        mock_config = Mock()
        mock_config.paired = False
        mock_request = Mock()
        mock_request.method = 'POST'
        mock_request.global_context = {'accessories':  [mock_accessory], 'config': mock_config}

        asyncio.get_event_loop().run_until_complete(route.identify(mock_request))

        mock_accessory.identify.assert_called_once()
        self.mock_response.assert_called_with(status=HTTPStatus.NO_CONTENT)

        # request.method: unknown
        mock_request.method = 'unknown'

        asyncio.get_event_loop().run_until_complete(route.identify(mock_request))

        self.mock_response.assert_called_with(status=HTTPStatus.NOT_FOUND)

        # already paired
        mock_config.paired = True
        mock_request.method = 'POST'

        asyncio.get_event_loop().run_until_complete(route.identify(mock_request))

        self.mock_response.assert_called_with(
            'application/hap+json', status=HTTPStatus.BAD_REQUEST, data=b'{"status": -70401}')

    @patch('pyhap.route.exchange')
    @patch('pyhap.route.srp_verify')
    @patch('pyhap.route.srp_start')
    @patch('pyhap.route.tlv_parser')
    def test_pair_setup(self, mock_tlv_parser, mock_srp_start, mock_srp_verify, mock_exchange):
        mock_config = Mock()
        mock_request = Mock()
        mock_read = AsyncMock(return_value=b'test_read')
        mock_request.read = mock_read
        mock_request.global_context = {
            'config': mock_config,
            'pair_setup_expected_state': 'test_pair_setup_expected_state',
        }

        # m1
        mock_tlv_parser.decode.return_value = [{
            TlvCode.state: TlvState.m1,
            TlvCode.method: TlvMethod.reserved,
        }]

        asyncio.get_event_loop().run_until_complete(route.pair_setup(mock_request))

        mock_srp_start.assert_called_once_with(mock_config, mock_request.context, 'test_pair_setup_expected_state')
        self.assertEqual(mock_request.global_context['pair_setup_expected_state'], TlvState.m3)
        self.mock_response.assert_called_with('application/pairing+tlv8', data=mock_tlv_parser.encode())
        mock_request.global_context['pair_setup_expected_state'] = 'test_pair_setup_expected_state'

        # m3
        mock_tlv_parser.decode.return_value = [{
            TlvCode.state: TlvState.m3,
            TlvCode.public_key: 'test_public_key',
            TlvCode.proof: 'test_proof',
        }]

        asyncio.get_event_loop().run_until_complete(route.pair_setup(mock_request))

        mock_srp_verify.assert_called_once_with(
            mock_request.context, 'test_pair_setup_expected_state', 'test_public_key', 'test_proof')
        self.assertEqual(mock_request.global_context['pair_setup_expected_state'], TlvState.m5)
        self.mock_response.assert_called_with('application/pairing+tlv8', data=mock_tlv_parser.encode())
        mock_request.global_context['pair_setup_expected_state'] = 'test_pair_setup_expected_state'

        # m5
        mock_tlv_parser.decode.return_value = [{
            TlvCode.state: TlvState.m5,
            TlvCode.encrypted_data: 'test_encrypted_data',
        }]

        asyncio.get_event_loop().run_until_complete(route.pair_setup(mock_request))

        mock_exchange.assert_called_once_with(
            mock_config, mock_request.context, 'test_pair_setup_expected_state', 'test_encrypted_data')
        self.assertEqual(mock_request.global_context['pair_setup_expected_state'], TlvState.m1)
        self.mock_response.assert_called_with('application/pairing+tlv8', data=mock_tlv_parser.encode())
        mock_request.global_context['pair_setup_expected_state'] = 'test_pair_setup_expected_state'

        # unknown data
        mock_tlv_parser.decode.return_value = [{
            TlvCode.state: TlvState.m1,
            TlvCode.method: TlvMethod.pair_setup,
        }]

        with self.assertRaises(ValueError):
            asyncio.get_event_loop().run_until_complete(route.pair_setup(mock_request))

        # error in result
        mock_srp_start.return_value = [{TlvCode.error: TlvError.unavailable}]
        mock_tlv_parser.decode.return_value = [{
            TlvCode.state: TlvState.m1,
            TlvCode.method: TlvMethod.reserved,
        }]

        asyncio.get_event_loop().run_until_complete(route.pair_setup(mock_request))

        self.assertEqual(mock_request.global_context['pair_setup_expected_state'], TlvState.m1)
        self.assertFalse(mock_config.pair_setup_mode)
        mock_request.global_context['pair_setup_expected_state'] = 'test_pair_setup_expected_state'

    @patch('pyhap.route.verify_finish')
    @patch('pyhap.route.verify_start')
    @patch('pyhap.route.tlv_parser')
    def test_pair_verify(self, mock_tlv_parser, mock_verify_start, mock_verify_finish):
        mock_config = Mock()
        mock_request = Mock()
        mock_read = AsyncMock(return_value=b'test_read')
        mock_request.read = mock_read
        mock_request.global_context = {'config': mock_config}
        mock_request.context = {'paired': True}

        # m1
        mock_tlv_parser.decode.return_value = [{
            TlvCode.state: TlvState.m1,
            TlvCode.public_key: 'test_public_key',
        }]

        asyncio.get_event_loop().run_until_complete(route.pair_verify(mock_request))

        mock_verify_start.assert_called_once_with(mock_config, mock_request.context, 'test_public_key')
        self.mock_response.assert_called_with('application/pairing+tlv8', data=mock_tlv_parser.encode(), upgrade=False)

        # m3
        mock_tlv_parser.decode.return_value = [{
            TlvCode.state: TlvState.m3,
            TlvCode.encrypted_data: 'test_encrypted_data',
        }]

        asyncio.get_event_loop().run_until_complete(route.pair_verify(mock_request))

        mock_verify_finish.assert_called_once_with(mock_config, mock_request.context, 'test_encrypted_data')
        self.mock_response.assert_called_with('application/pairing+tlv8', data=mock_tlv_parser.encode(), upgrade=True)

        # unknown data
        mock_tlv_parser.decode.return_value = [{TlvCode.state: TlvState.m2}]

        with self.assertRaises(ValueError):
            asyncio.get_event_loop().run_until_complete(route.pair_verify(mock_request))

    @patch('pyhap.route.remove_pairing')
    @patch('pyhap.route.add_pairing')
    @patch('pyhap.route.list_pairings')
    @patch('pyhap.route.tlv_parser')
    def test_pairings(self, mock_tlv_parser, mock_list_pairings, mock_add_pairing, mock_remove_pairing):
        mock_config = Mock()
        mock_request = Mock()
        mock_read = AsyncMock(return_value=b'test_read')
        mock_request.read = mock_read
        mock_request.global_context = {'config': mock_config}
        mock_request.context = {
            'ios_device_pairing_id': 'test_ios_device_pairing_id',
            'encrypted': 'test_encrypted'
        }
        mock_config.get_pairing.return_value = None, None, ControllerPermission.admin

        # list pairings
        mock_tlv_parser.decode.return_value = [{
            TlvCode.method: TlvMethod.list_pairings,
            TlvCode.state: TlvState.m1,
        }]

        asyncio.get_event_loop().run_until_complete(route.pairings(mock_request))

        mock_list_pairings.assert_called_once_with(mock_config)
        self.mock_response.assert_called_with(
            'application/pairing+tlv8', data=mock_tlv_parser.encode(), keep_alive=True)

        # add pairing
        mock_tlv_parser.decode.return_value = [{
            TlvCode.method: TlvMethod.add_pairing,
            TlvCode.state: TlvState.m1,
            TlvCode.identifier: 'test_identifier',
            TlvCode.public_key: 'test_public_key',
            TlvCode.permissions: 0,
        }]

        asyncio.get_event_loop().run_until_complete(route.pairings(mock_request))

        mock_add_pairing.assert_called_once_with(
            mock_config, 'test_identifier', 'test_public_key', ControllerPermission.user)
        self.mock_response.assert_called_with(
            'application/pairing+tlv8', data=mock_tlv_parser.encode(), keep_alive=True)

        # remove pairing
        mock_tlv_parser.decode.return_value = [{
            TlvCode.method: TlvMethod.remove_pairing,
            TlvCode.state: TlvState.m1,
            TlvCode.identifier: 'test_identifier',
        }]

        asyncio.get_event_loop().run_until_complete(route.pairings(mock_request))

        mock_remove_pairing.assert_called_once_with(mock_config, 'test_identifier')
        self.mock_response.assert_called_with(
            'application/pairing+tlv8', data=mock_tlv_parser.encode(), keep_alive=False)

        # unknown data
        mock_tlv_parser.decode.return_value = [{
            TlvCode.method: TlvMethod.list_pairings,
            TlvCode.state: TlvState.m2,
        }]

        with self.assertRaises(ValueError):
            asyncio.get_event_loop().run_until_complete(route.pairings(mock_request))

        # permission denied
        mock_config.get_pairing.return_value = None, None, ControllerPermission.user
        asyncio.get_event_loop().run_until_complete(route.pairings(mock_request))

        mock_tlv_parser.encode.assert_called_with([{
            TlvCode.state: TlvState.m2,
            TlvCode.error: TlvError.authentication,
        }])
        self.mock_response.assert_called_with('application/pairing+tlv8', data=mock_tlv_parser.encode())
        mock_config.get_pairing.return_value = None, None, ControllerPermission.admin
