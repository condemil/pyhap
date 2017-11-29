from unittest import TestCase
from unittest.mock import Mock, patch

from cryptography.exceptions import InvalidTag
from ed25519 import BadSignatureError

from pyhap import pair
from pyhap.config import ControllerPermission
from pyhap.tlv import (
    TlvCode,
    TlvError,
    TlvState,
)


class TestPair(TestCase):
    def setUp(self):
        patch_srp = patch('pyhap.pair.Srp')
        self.addCleanup(patch_srp.stop)
        self.mock_srp = patch_srp.start()

    def test_srp_start(self):
        config = Mock()
        config.paired = False
        config.unsuccessful_authentication_attempts = 0
        config.pair_setup_mode = False
        context = {}
        expected_tlv_state = TlvState.m1

        result = pair.srp_start(config, context, expected_tlv_state)
        self.assertIn('srp', context)
        self.assertEqual(result, [{
            TlvCode.state: TlvState.m2,
            TlvCode.public_key: context['srp'].public_key,
            TlvCode.salt: context['srp'].salt,
        }])

        # handle 'Accessory already paired, cannot accept additional pairings'
        config.paired = True
        result = pair.srp_start(config, context, expected_tlv_state)
        self.assertEqual(result, [{
            TlvCode.state: TlvState.m2,
            TlvCode.error: TlvError.unavailable,
        }])
        config.paired = False

        # handle 'Max authentication attempts reached'
        config.unsuccessful_authentication_attempts = 101
        result = pair.srp_start(config, context, expected_tlv_state)
        self.assertEqual(result, [{
            TlvCode.state: TlvState.m2,
            TlvCode.error: TlvError.max_tries,
        }])
        config.unsuccessful_authentication_attempts = 0

        # handle 'Unexpected pair_setup state'
        expected_tlv_state = TlvState.m2
        result = pair.srp_start(config, context, expected_tlv_state)
        self.assertEqual(result, [{
            TlvCode.state: TlvState.m2,
            TlvCode.error: TlvError.unknown,
        }])
        expected_tlv_state = TlvState.m1

        # handle 'Currently perform pair setup operation with a different controller'
        config.pair_setup_mode = True
        result = pair.srp_start(config, context, expected_tlv_state)
        self.assertEqual(result, [{
            TlvCode.state: TlvState.m2,
            TlvCode.error: TlvError.busy,
        }])
        config.pair_setup_mode = False

    def test_srp_verify(self):
        context = {'srp': Mock()}
        expected_tlv_state = TlvState.m3
        client_public_key = b'test_client_public_key'
        client_proof = b'test_client_proof'

        result = pair.srp_verify(context, expected_tlv_state, client_public_key, client_proof)

        context['srp'].compute_shared_session_key.assert_called_with(client_public_key)
        context['srp'].compute_shared_session_key.verify_proof(client_proof)
        self.assertEqual(result, [{
            TlvCode.state: TlvState.m4,
            TlvCode.proof: context['srp'].session_key_proof,
        }])

        # handle 'Unexpected pair_setup state'
        expected_tlv_state = TlvState.m1
        result = pair.srp_verify(context, expected_tlv_state, client_public_key, client_proof)
        self.assertEqual(result, [{
            TlvCode.state: TlvState.m4,
            TlvCode.error: TlvError.unknown,
        }])
        expected_tlv_state = TlvState.m3

        # handle 'Incorrect setup code, try again'
        context['srp'].verify_proof.return_value = False
        result = pair.srp_verify(context, expected_tlv_state, client_public_key, client_proof)
        self.assertEqual(result, [{
            TlvCode.state: TlvState.m4,
            TlvCode.error: TlvError.authentication,
        }])
        context['srp'].verify_proof.return_value = True

    @patch('pyhap.pair.ed25519')
    @patch('pyhap.pair.tlv_parser')
    @patch('pyhap.pair.default_backend')
    @patch('pyhap.pair.SHA512')
    @patch('pyhap.pair.HKDF')
    @patch('pyhap.pair.ChaCha20Poly1305')
    def test_exchange(self, mock_chacha20_poly1305, mock_hkdf, mock_sha512, mocker_default_backend, mock_tlv_parser,
                      mock_ed25519):
        config = Mock()
        config.get_pairing.return_value = None, None, None
        context = {'srp': Mock()}
        expected_tlv_state = TlvState.m5
        encrypted_input = b'test_encrypted_input'
        encrypted_output = b'test_encrypted_output'
        mock_chacha20_poly1305().encrypt.return_value = encrypted_output
        mock_tlv_parser.decode.return_value = [{
            TlvCode.identifier: 'test_identifier',
            TlvCode.public_key: b'test_public_key',
            TlvCode.signature: b'test_signature',
        }]

        result = pair.exchange(config, context, expected_tlv_state, encrypted_input)
        mock_hkdf.assert_called_with(algorithm=mock_sha512(), length=32, salt=b'Pair-Setup-Accessory-Sign-Salt',
                                     info=b'Pair-Setup-Accessory-Sign-Info', backend=mocker_default_backend())
        mock_hkdf().derive.assert_called_with(context['srp'].session_key)
        mock_chacha20_poly1305.assert_called_with(mock_hkdf().derive())
        mock_chacha20_poly1305().decrypt.assert_called_with(b'\x00\x00\x00\x00PS-Msg05', encrypted_input, None)
        mock_tlv_parser.decode.assert_called_with(mock_chacha20_poly1305().decrypt())
        self.assertEqual(result, [{
            TlvCode.state: TlvState.m6,
            TlvCode.encrypted_data: encrypted_output,
        }])

        # handle 'Unexpected pair_setup state'
        expected_tlv_state = TlvState.m1
        result = pair.exchange(config, context, expected_tlv_state, encrypted_input)
        self.assertEqual(result, [{
            TlvCode.state: TlvState.m6,
            TlvCode.error: TlvError.unknown,
        }])
        expected_tlv_state = TlvState.m5

        # handle 'pair_setup M5: invalid auth tag during chacha decryption'
        mock_chacha20_poly1305().decrypt.side_effect = InvalidTag()
        result = pair.exchange(config, context, expected_tlv_state, encrypted_input)
        self.assertEqual(result, [{
            TlvCode.state: TlvState.m6,
            TlvCode.error: TlvError.authentication,
        }])
        mock_chacha20_poly1305().decrypt.side_effect = None

        # handle 'unable to decode decrypted tlv data'
        mock_tlv_parser.decode.side_effect = ValueError()
        result = pair.exchange(config, context, expected_tlv_state, encrypted_input)
        self.assertEqual(result, [{
            TlvCode.state: TlvState.m6,
            TlvCode.error: TlvError.authentication,
        }])
        mock_tlv_parser.decode.side_effect = None

        # handle 'ios_device_info ed25519 signature verification is failed'
        mock_ed25519.BadSignatureError = BadSignatureError
        mock_ed25519.VerifyingKey().verify.side_effect = BadSignatureError()
        result = pair.exchange(config, context, expected_tlv_state, encrypted_input)
        self.assertEqual(result, [{
            TlvCode.state: TlvState.m6,
            TlvCode.error: TlvError.authentication,
        }])
        mock_ed25519.VerifyingKey().verify.side_effect = None

    @patch('pyhap.pair.ChaCha20Poly1305')
    @patch('pyhap.pair.HKDF')
    @patch('pyhap.pair.tlv_parser')
    @patch('pyhap.pair.ed25519')
    @patch('pyhap.pair.X25519PublicKey')
    @patch('pyhap.pair.X25519PrivateKey')
    def test_verify_start(self, mock_x25519_private_key, mock_x25519_public_key, mock_ed25519, mock_tlv_parser,
                          mock_hkdf, mock_chacha20_poly1305):
        config = Mock()
        context = {'srp': Mock()}
        ios_device_public_key = b'test_ios_device_public_key'
        accessory_curve25519_public_key = mock_x25519_private_key.generate().public_key().public_bytes()

        result = pair.verify_start(config, context, ios_device_public_key)
        mock_x25519_public_key.from_public_bytes.assert_called_once_with(ios_device_public_key)
        mock_ed25519.SigningKey.assert_called_once_with(config.accessory_ltsk)
        mock_tlv_parser.encode.assert_called_once_with([{
            TlvCode.identifier: config.device_id,
            TlvCode.signature: mock_ed25519.SigningKey().sign(),
        }])
        mock_hkdf.assert_called_once()
        self.assertEqual(result, [{
            TlvCode.state: TlvState.m2,
            TlvCode.public_key: accessory_curve25519_public_key,
            TlvCode.encrypted_data: mock_chacha20_poly1305().encrypt(),
        }])

    @patch('pyhap.pair.ed25519')
    @patch('pyhap.pair.tlv_parser')
    @patch('pyhap.pair.ChaCha20Poly1305')
    def test_verify_finish(self, mock_chacha20_poly1305, mock_tlv_parser, mock_ed25519):
        config = Mock()
        config.get_pairing.return_value = None, 'test_ios_device_ltpk', None
        context = {
            'session_key': 'test_session_key',
            'accessory_curve25519_public_key': b'test_accessory_curve25519_public_key',
            'ios_device_curve25519_public_key': b'test_ios_device_curve25519_public_key',
            'shared_secret': b'shared_secret',
        }
        encrypted_input = b'test_encrypted_input'
        mock_tlv_parser.decode.return_value = [{
            TlvCode.identifier: 'test_identifier',
            TlvCode.signature: b'test_signature',
        }]

        result = pair.verify_finish(config, context, encrypted_input)
        self.assertEqual(result, [{
            TlvCode.state: TlvState.m4,
        }])

        # handle 'verify_finished call before successful verify_start'
        context['session_key'] = None
        result = pair.verify_finish(config, context, encrypted_input)
        self.assertEqual(result, [{
            TlvCode.state: TlvState.m4,
            TlvCode.error: TlvError.authentication,
        }])
        context['session_key'] = 'test_session_key'

        # handle 'invalid auth tag during chacha decryption'
        mock_chacha20_poly1305().decrypt.side_effect = InvalidTag()
        result = pair.verify_finish(config, context, encrypted_input)
        self.assertEqual(result, [{
            TlvCode.state: TlvState.m4,
            TlvCode.error: TlvError.authentication,
        }])
        mock_chacha20_poly1305().decrypt.side_effect = None

        # handle 'unable to decode decrypted tlv data'
        mock_tlv_parser.decode.side_effect = ValueError()
        result = pair.verify_finish(config, context, encrypted_input)
        self.assertEqual(result, [{
            TlvCode.state: TlvState.m4,
            TlvCode.error: TlvError.authentication,
        }])
        mock_tlv_parser.decode.side_effect = None

        # handle 'unable to find requested ios device in config file'
        config.get_pairing.return_value = None, None, None
        result = pair.verify_finish(config, context, encrypted_input)
        self.assertEqual(result, [{
            TlvCode.state: TlvState.m4,
            TlvCode.error: TlvError.authentication,
        }])
        config.get_pairing.return_value = None, 'test_ios_device_ltpk', None

        # handle 'ios_device_info ed25519 signature verification is failed'
        mock_ed25519.BadSignatureError = BadSignatureError
        mock_ed25519.VerifyingKey().verify.side_effect = BadSignatureError()
        result = pair.verify_finish(config, context, encrypted_input)
        self.assertEqual(result, [{
            TlvCode.state: TlvState.m4,
            TlvCode.error: TlvError.authentication,
        }])
        mock_ed25519.VerifyingKey().verify.side_effect = None

    def test_list_pairings(self):
        test_pairings = ('test_identifier', b'test_public_key', ControllerPermission.user)
        config = Mock()
        config.get_pairings.return_value = [test_pairings]

        result = pair.list_pairings(config)
        self.assertEqual(result, [{
            TlvCode.state: TlvState.m2,
            TlvCode.identifier: test_pairings[0],
            TlvCode.public_key: test_pairings[1],
            TlvCode.permissions: test_pairings[2].value,
        }])

    def test_add_pairing(self):
        ios_device_public_key = b'test_ios_device_public_key'
        config = Mock()
        config.get_pairing.return_value = None, ios_device_public_key, None
        ios_device_pairing_id = 'test_ios_device_pairing_id'
        permission = ControllerPermission.user

        result = pair.add_pairing(config, ios_device_pairing_id, ios_device_public_key, permission)
        self.assertEqual(result, [{
            TlvCode.state: TlvState.m2,
        }])

        # handle 'Received iOS device public key doesn\'t match with previously saved key'
        ios_device_public_key = b'test_other_ios_device_public_key'
        result = pair.add_pairing(config, ios_device_pairing_id, ios_device_public_key, permission)
        self.assertEqual(result, [{
            TlvCode.state: TlvState.m2,
            TlvCode.error: TlvError.unknown,
        }])
        ios_device_public_key = b'test_ios_device_public_key'

    def test_remove_pairing(self):
        config = Mock()
        ios_device_pairing_id = 'test_ios_device_pairing_id'

        result = pair.remove_pairing(config, ios_device_pairing_id)
        self.assertEqual(result, [{
            TlvCode.state: TlvState.m2,
        }])
