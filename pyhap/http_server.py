import asyncio
from asyncio import (
    StreamReader,
    StreamWriter,
)
from asyncio.base_events import Server
from email.utils import formatdate
from functools import wraps
from http import HTTPStatus
from logging import getLogger
from typing import Dict
from urllib.parse import (
    parse_qsl,
    urlsplit,
)

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from pyhap.exception import SecurityError

logger = getLogger('pyhap.http_server')

AUTH_TAG_LENGTH = 16
ENCRYPTED_DATA_LENGTH = 2
ENCRYPTED_CHUNK_MAX_SIZE = 1024


class Request:
    def __init__(self, global_context: dict, context: dict, method: str, headers: dict, query: dict,
                 reader: StreamReader) -> None:
        self.global_context = global_context
        self.context = context
        self.method = method
        self.headers = headers
        self.query = query
        self.reader = reader

    async def read(self):
        content_length = int(self.headers['content-length'])
        return await self.reader.read(content_length)


class Response:
    def __init__(self, content_type: str = 'text/html', status: HTTPStatus = HTTPStatus.OK, data: bytes = b'',
                 keep_alive: bool = True, upgrade=False) -> None:
        if not isinstance(data, bytes):
            raise ValueError(f'Response data should be bytes, received {type(data)}')

        self.content_type = content_type
        self.status = status
        self.data = data
        self.keep_alive = keep_alive
        self.upgrade = upgrade


class Handler:
    def __init__(self, reader: StreamReader, writer: StreamWriter, routes: dict, global_context: dict) -> None:
        self.reader = reader
        self.writer = writer
        self.routes = routes
        self.global_context = global_context
        self.context = {'encrypted': False}  # context is available only within http keep-alive socket connection
        self.close_connection = False
        self.encrypted_request_count = 0
        self.encrypted_response_count = 0
        self.decrypt_key: bytes = None

        self.http_method: str = None
        self.request_path: str = None
        self.http_version: str = None
        self.headers: Dict[str, str] = None
        self.query: Dict[str, str] = {}

    async def start_handling(self):
        while not self.close_connection:
            await self.handle()

    async def handle(self) -> None:
        self.close_connection = True

        if self.context['encrypted']:
            try:
                reader = await self.decrypt_stream(self.reader)
            except SecurityError as e:
                logger.info(str(e))
                return
        else:
            reader = self.reader

        if not await self.parse_request(reader):
            return

        request = Request(self.global_context, self.context, self.http_method, self.headers, self.query, reader)
        route = self.routes[self.request_path]

        if route:
            try:
                response = await route(request)
            except SecurityError as e:
                logger.info(str(e))
                return
        else:
            logger.info(f'Handler for path {self.request_path} is not found')
            response = Response(status=HTTPStatus.NOT_FOUND)

        if not isinstance(response, Response):
            logger.warning(f'Response for path {self.request_path} was not returned from handler')
            response = Response(status=HTTPStatus.NOT_FOUND)

        if response.upgrade and not self.context.get('encrypt_key'):
            logger.info('Attempt to upgrade to encrypted stream without encrypt_key in context')
            await self.send_error(HTTPStatus.LENGTH_REQUIRED)
            return

        await self.send_response(response)

        if response.upgrade:
            logger.debug('Upgrade to encrypted stream')
            self.context['encrypted'] = True

    async def parse_request(self, reader: StreamReader) -> bool:
        request_line = await reader.readline()

        if not request_line:
            return False  # client disconnected

        self.http_method, raw_url, self.http_version = request_line.decode().split()  # GET / HTTP/1.1

        url = urlsplit(raw_url)
        self.request_path = url.path
        self.query = dict(parse_qsl(url.query))

        if self.http_version != 'HTTP/1.1':
            await self.send_error(HTTPStatus.HTTP_VERSION_NOT_SUPPORTED, f'Invalid HTTP version ({self.http_version})')
            return False

        self.headers = await self.parse_headers(reader)

        if self.http_method != 'GET' and not self.headers.get('content-length'):
            await self.send_error(HTTPStatus.LENGTH_REQUIRED)
            return False

        connection = self.headers.get('connection', '')

        if connection.lower() == 'keep-alive':
            self.close_connection = False

        return True

    @staticmethod
    async def parse_headers(reader: StreamReader) -> Dict[str, str]:
        headers: Dict[str, str] = {}

        while True:
            raw_header = await reader.readline()
            header = raw_header.decode()

            if header == '\r\n':
                break

            key, value = header.split(':', 1)
            headers[key.lower()] = value.strip()

        return headers

    async def decrypt_stream(self, reader: StreamReader) -> StreamReader:
        data_length = await reader.read(ENCRYPTED_DATA_LENGTH)

        if not data_length:
            raise SecurityError('Encrypted data is empty')

        data_length_int = int.from_bytes(data_length, byteorder='little') + AUTH_TAG_LENGTH

        encrypted_data = await reader.read(data_length_int)

        chacha = ChaCha20Poly1305(self.context['decrypt_key'])

        nonce = b'\x00\x00\x00\x00' + self.encrypted_request_count.to_bytes(8, byteorder='little')
        try:
            decrypted_data = chacha.decrypt(nonce, encrypted_data, data_length)
        except InvalidTag:
            decrypted_data = None

        if not decrypted_data:
            raise SecurityError('Unable to decrypt encrypted data')

        self.encrypted_request_count += 1

        decrypted_reader = StreamReader()
        decrypted_reader.feed_data(decrypted_data)
        return decrypted_reader

    async def send_response(self, response: Response):
        if response.keep_alive:
            self.close_connection = False
            connection = 'keep-alive'
        else:
            self.close_connection = True
            connection = 'close'

        headers = (
            'HTTP/1.1 {} {}\r\n'
            'Server: PyHAP\r\n'
            'Date: {}\r\n'
            'Content-Length: {}\r\n'
            'Content-Type: {}\r\n'
            'Connection: {}\r\n'
            '\r\n'
        ).format(
            response.status.value,
            response.status.phrase,
            formatdate(usegmt=True),
            str(len(response.data)),
            response.content_type,
            connection,
        ).encode()

        # call write once to prevent http response split to several tcp packets
        if self.context['encrypted']:
            self.writer.write(self.encrypt_data(headers + response.data))
        else:
            self.writer.write(headers + response.data)
        await self.writer.drain()

    def encrypt_data(self, encrypted_data: bytes) -> bytes:
        data_length = len(encrypted_data).to_bytes(2, byteorder='little')

        chacha = ChaCha20Poly1305(self.context['encrypt_key'])

        nonce = b'\x00\x00\x00\x00' + self.encrypted_response_count.to_bytes(8, byteorder='little')
        self.encrypted_response_count += 1

        return data_length + chacha.encrypt(nonce, encrypted_data, data_length)

    async def send_error(self, status: HTTPStatus, description: str = None):
        if not description:
            description = status.description
        logger.error(f'HTTP Error: {status.value}: {status.phrase} ({description})')
        await self.send_response(Response(status=status, data=description.encode(), keep_alive=False))


class HTTPServer:
    def __init__(self, routes: dict) -> None:
        self.routes = routes
        self.global_context: dict = {}
        self.handlers: set = set()

    async def handler(self, reader: StreamReader, writer: StreamWriter):
        handler = Handler(reader, writer, self.routes, self.global_context)
        self.handlers.add(handler)
        await handler.start_handling()
        self.handlers.remove(handler)

    def run(self, host: str, port: int):
        loop = asyncio.get_event_loop()

        server: Server = loop.run_until_complete(asyncio.start_server(self.handler, host, port))

        try:
            loop.run_forever()
        except KeyboardInterrupt:
            pass

        for handler in self.handlers:
            handler.close_connection = True

        server.close()
        loop.run_until_complete(server.wait_closed())
        loop.close()


def encrypted(func):
    @wraps(func)
    def wrapper(request: Request):
        if not request.context['encrypted']:
            raise SecurityError('Call for route without authentication')
        return func(request)

    return wrapper
