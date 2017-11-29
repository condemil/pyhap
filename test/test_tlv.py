from unittest import TestCase

from pyhap.tlv import TlvCode, TlvParser, tlv_parser


class TestTlv(TestCase):
    def test_tlv_decode(self):
        data = bytes([
            0x06,  # state
            0x01,  # 1 byte value size
            0x03,  # M3
            0x01,  # identifier
            0x05,  # 5 byte value size
            0x68,  # ASCII 'h'
            0x65,  # ASCII 'e'
            0x6c,  # ASCII 'l'
            0x6c,  # ASCII 'l'
            0x6f,  # ASCII 'o'
        ])

        result = tlv_parser.decode(data)[0]
        expected_result = {
            TlvCode.state: 3,
            TlvCode.identifier: 'hello'
        }
        self.assertEqual(result, expected_result)

        with self.assertRaises(ValueError):
            tlv_parser.decode(bytes([
                0xfa,  # unknown TlvCode
            ]))

        with self.assertRaises(ValueError):
            tlv_parser.decode(bytes([
                0x01,  # identifier (string type)
                0x01,  # 1 byte value size
                0xf0,  # invalid unicode symbol
            ]))

        with self.assertRaises(ValueError):
            tlv_parser.decode(bytes([
                0x00,  # method (integer type)
                0x02,  # 2 byte value size
                0x00,  # first integer byte
                0x00,  # second integer byte (only 1-byte length integers is supported)
            ]))

    def test_tlv_decode_merge(self):
        data = [
            0x06,  # state
            0x01,  # 1 byte value size
            0x03,  # M3
            0x09,  # certificate
            0xff,  # 255 byte value size
            0x61,  # ASCII 'a'
        ]
        data.extend([0x61] * 254)  # 254 more bytes containing 0x61 (ASCII 'a')
        data.extend([
            0x09,  # certificate, continuation of previous TLV
            0x2d,  # 45 byte value size
            0x61,  # ASCII 'a'
        ])
        data.extend([0x61] * 44)  # 44 more bytes containing 0x61 (ASCII 'a')
        data.extend([
            0x01,  # identifier, new TLV item
            0x05,  # 5 byte value size
            0x68,  # ASCII 'h'
            0x65,  # ASCII 'e'
            0x6c,  # ASCII 'l'
            0x6c,  # ASCII 'l'
            0x6f,  # ASCII 'o'
        ])

        result = tlv_parser.decode(bytes(data))[0]
        expected_result = {
            TlvCode.state: 3,
            TlvCode.certificate: b'a'*300,
            TlvCode.identifier: 'hello'
        }
        self.assertEqual(result, expected_result)

    def test_tlv_decode_separated(self):
        data = bytes([
            0x01,  # identifier
            0x05,  # 5 byte value size
            0x68,  # ASCII 'h'
            0x65,  # ASCII 'e'
            0x6c,  # ASCII 'l'
            0x6c,  # ASCII 'l'
            0x6f,  # ASCII 'o'
            0x0b,  # permissions
            0x01,  # 1 byte value size
            0x00,  # user permission
            0xff,  # separator
            0x00,  # 0 byte value size
            0x01,  # identifier
            0x05,  # 5 byte value size
            0x77,  # ASCII 'w'
            0x6f,  # ASCII 'o'
            0x72,  # ASCII 'r'
            0x6c,  # ASCII 'l'
            0x64,  # ASCII 'd'
            0x0b,  # permissions
            0x01,  # 1 byte value size
            0x01,  # admin permission
        ])

        result = tlv_parser.decode(data)
        expected_result = [{
            TlvCode.identifier: 'hello',
            TlvCode.permissions: 0
        }, {
            TlvCode.identifier: 'world',
            TlvCode.permissions: 1
        }]
        self.assertEqual(result, expected_result)

    def test_tlv_encode(self):
        data = [{
            TlvCode.state: 3,
            TlvCode.identifier: 'hello',
        }]

        result = tlv_parser.encode(data)
        expected_result = bytes([
            0x06,  # state
            0x01,  # 1 byte value size
            0x03,  # M3
            0x01,  # identifier
            0x05,  # 5 byte value size
            0x68,  # ASCII 'h'
            0x65,  # ASCII 'e'
            0x6c,  # ASCII 'l'
            0x6c,  # ASCII 'l'
            0x6f,  # ASCII 'o'
        ])
        self.assertEqual(result, expected_result)

    def test_tlv_encode_merge(self):
        data = [{
            TlvCode.state: 3,
            TlvCode.certificate: b'a'*300,
            TlvCode.identifier: 'hello',
        }]

        result = tlv_parser.encode(data)
        expected_result = [
            0x06,  # state
            0x01,  # 1 byte value size
            0x03,  # M3
            0x09,  # certificate
            0xff,  # 255 byte value size
            0x61,  # ASCII 'a'
        ]
        expected_result.extend([0x61] * 254)  # 254 more bytes containing 0x61 (ASCII 'a')
        expected_result.extend([
            0x09,  # certificate, continuation of previous TLV
            0x2d,  # 45 byte value size
            0x61,  # ASCII 'a'
        ])
        expected_result.extend([0x61] * 44)  # 44 more bytes containing 0x61 (ASCII 'a')
        expected_result.extend([
            0x01,  # identifier, new TLV item
            0x05,  # 5 byte value size
            0x68,  # ASCII 'h'
            0x65,  # ASCII 'e'
            0x6c,  # ASCII 'l'
            0x6c,  # ASCII 'l'
            0x6f,  # ASCII 'o'
        ])
        self.assertEqual(result, bytes(expected_result))

    def test_tlv_encode_separated(self):
        data = [{
            TlvCode.identifier: 'hello',
            TlvCode.permissions: 0
        }, {
            TlvCode.identifier: 'world',
            TlvCode.permissions: 1
        }]

        result = tlv_parser.encode(data)
        expected_result = bytes([
            0x01,  # identifier
            0x05,  # 5 byte value size
            0x68,  # ASCII 'h'
            0x65,  # ASCII 'e'
            0x6c,  # ASCII 'l'
            0x6c,  # ASCII 'l'
            0x6f,  # ASCII 'o'
            0x0b,  # permissions
            0x01,  # 1 byte value size
            0x00,  # user permission
            0xff,  # separator
            0x00,  # 0 bytes value size
            0x01,  # identifier
            0x05,  # 5 byte value size
            0x77,  # ASCII 'w'
            0x6f,  # ASCII 'o'
            0x72,  # ASCII 'r'
            0x6c,  # ASCII 'l'
            0x64,  # ASCII 'd'
            0x0b,  # permissions
            0x01,  # 1 byte value size
            0x01,  # admin permission
        ])
        self.assertEqual(result, expected_result)

    def test_get_by_code(self):
        self.assertEqual(TlvParser.get_by_code(0), TlvCode.method)
        self.assertEqual(TlvParser.get_by_code(255), TlvCode.separator)

        with self.assertRaises(ValueError):
            TlvParser.get_by_code(250)

    def test_get_by_name(self):
        self.assertEqual(TlvParser.get_by_name('method'), TlvCode.method)
        self.assertEqual(TlvParser.get_by_name('separator'), TlvCode.separator)

        with self.assertRaises(ValueError):
            TlvParser.get_by_name('test')

    def test_get_name(self):
        self.assertEqual(TlvParser.get_name(0), 'method')
        self.assertEqual(TlvParser.get_name(255), 'separator')

        with self.assertRaises(ValueError):
            TlvParser.get_name(250)  # code 250 is not presented in TlvCode

    def test_get_type(self):
        self.assertEqual(tlv_parser.get_type(TlvCode.method), int)
        self.assertEqual(tlv_parser.get_type(TlvCode.identifier), str)

        with self.assertRaises(ValueError):
            tlv_parser.get_type(TlvCode.separator)  # TlvCode.separator type is None

        with self.assertRaises(ValueError):
            tlv_parser.get_type(0)  # any wrong data
