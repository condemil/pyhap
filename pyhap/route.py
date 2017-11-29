import json
from http import HTTPStatus
from logging import getLogger

from pyhap.accessory import Accessories
from pyhap.config import (
    ControllerPermission,
    HAPStatusCode,
)
from pyhap.http_server import (
    Request,
    Response,
    encrypted,
)
from pyhap.pair import (
    add_pairing,
    exchange,
    list_pairings,
    remove_pairing,
    srp_start,
    srp_verify,
    verify_start,
    verify_finish,
)
from pyhap.tlv import (
    tlv_parser,
    TlvCode,
    TlvError,
    TlvState,
    TlvMethod,
)
from pyhap.util import CustomJSONEncoder

logger = getLogger('pyhap')
PAIRING_CONTENT_TYPE = 'application/pairing+tlv8'
JSON_CONTENT_TYPE = 'application/hap+json'


@encrypted
async def accessories(request: Request) -> Response:
    logger.debug('/accessories called')
    accs: Accessories = request.global_context['accessories']
    logger.debug('Accessories: %s', json.dumps(accs, cls=CustomJSONEncoder))
    return Response(JSON_CONTENT_TYPE, data=json.dumps(accs, cls=CustomJSONEncoder).encode())


@encrypted
async def characteristics(request: Request) -> Response:
    logger.debug(f'{request.method} /characteristics called')
    accs: Accessories = request.global_context['accessories']

    if request.method == 'GET':
        logger.debug(f'{request.method} /characteristics query: {request.query}')
        error, result = accs.read_characteristic(request.query)
        logger.debug('Characteristics: %s', json.dumps(result, cls=CustomJSONEncoder))
        if error:
            status = HTTPStatus.MULTI_STATUS
        else:
            status = HTTPStatus.OK
        return Response(JSON_CONTENT_TYPE, status, data=json.dumps(result, cls=CustomJSONEncoder).encode())
    elif request.method == 'PUT':
        data = await request.read()
        error_data = await accs.write_characteristic(json.loads(data)['characteristics'])
        if error_data:
            return Response(status=HTTPStatus.MULTI_STATUS, data=json.dumps(error_data).encode())

        return Response(status=HTTPStatus.NO_CONTENT)
    else:
        raise ValueError('Unknown http method received: {}'.format(request.method))


async def identify(request: Request) -> Response:
    logger.debug('/identify called')
    global_context = request.global_context
    config = global_context['config']
    accs: Accessories = global_context['accessories']

    if request.method != 'POST':
        return Response(status=HTTPStatus.NOT_FOUND)
    elif config.paired:
        return Response(JSON_CONTENT_TYPE, status=HTTPStatus.BAD_REQUEST,
                        data=json.dumps({'status': HAPStatusCode.insufficient_privileges.value}).encode())

    for accessory in accs:
        await accessory.identify()

    return Response(status=HTTPStatus.NO_CONTENT)


async def pair_setup(request: Request) -> Response:
    global_context = request.global_context
    config = global_context['config']

    parsed_body = tlv_parser.decode(await request.read())[0]
    requested_state = parsed_body.get(TlvCode.state)
    expected_state = global_context['pair_setup_expected_state']

    logger.debug(f'Requested pair_setup state: {requested_state}')

    if requested_state == TlvState.m1 and parsed_body.get(TlvCode.method) == TlvMethod.reserved:
        result = srp_start(config, request.context, expected_state)
        global_context['pair_setup_expected_state'] = TlvState.m3
    elif requested_state == TlvState.m3:
        result = srp_verify(request.context, expected_state, parsed_body[TlvCode.public_key],
                            parsed_body[TlvCode.proof])
        global_context['pair_setup_expected_state'] = TlvState.m5
    elif requested_state == TlvState.m5:
        result = exchange(config, request.context, expected_state, parsed_body[TlvCode.encrypted_data])
        global_context['pair_setup_expected_state'] = TlvState.m1
    else:
        raise ValueError('Unknown data received: {}'.format(parsed_body))

    if TlvCode.error in result[0]:
        config.pair_setup_mode = False
        global_context['pair_setup_expected_state'] = TlvState.m1

    return Response(PAIRING_CONTENT_TYPE, data=tlv_parser.encode(result))


async def pair_verify(request: Request) -> Response:
    config = request.global_context['config']
    upgrade = False

    parsed_body = tlv_parser.decode(await request.read())[0]
    requested_state = parsed_body.get(TlvCode.state)

    logger.debug(f'Requested pair_verify state: {requested_state}')

    if requested_state == TlvState.m1:
        result = verify_start(config, request.context, parsed_body[TlvCode.public_key])
    elif requested_state == TlvState.m3:
        result = verify_finish(config, request.context, parsed_body[TlvCode.encrypted_data])
        if request.context.get('paired'):
            upgrade = True  # verify_finish end up without errors, upgrade to fully encrypted communication
    else:
        raise ValueError('Unknown data received: {}'.format(parsed_body))

    return Response(PAIRING_CONTENT_TYPE, data=tlv_parser.encode(result), upgrade=upgrade)


@encrypted
async def pairings(request: Request) -> Response:
    logger.debug('/pairings called')

    config = request.global_context['config']

    if config.get_pairing(request.context['ios_device_pairing_id'])[2] != ControllerPermission.admin:
        logger.error('Controller without admin permission is trying to call /pairings')
        return Response(PAIRING_CONTENT_TYPE, data=tlv_parser.encode([{
            TlvCode.state: TlvState.m2,
            TlvCode.error: TlvError.authentication,
        }]))

    parsed_body = tlv_parser.decode(await request.read())[0]
    method = parsed_body.get(TlvCode.method)
    requested_state = parsed_body.get(TlvCode.state)
    keep_alive = True

    if method == TlvMethod.list_pairings and requested_state == TlvState.m1:
        logger.debug('/pairings list_pairings called')
        result = list_pairings(config)
    elif method == TlvMethod.add_pairing and requested_state == TlvState.m1:
        logger.debug('/pairings add_pairing called')
        ios_device_pairing_id = parsed_body[TlvCode.identifier]
        ios_device_public_key = parsed_body[TlvCode.public_key]
        permission = parsed_body[TlvCode.permissions]
        result = add_pairing(config, ios_device_pairing_id, ios_device_public_key, ControllerPermission(permission))
    elif method == TlvMethod.remove_pairing and requested_state == TlvState.m1:
        logger.debug('/pairings remove_pairing called')
        ios_device_pairing_id = parsed_body[TlvCode.identifier]
        result = remove_pairing(config, ios_device_pairing_id)
        if not config.get_pairing(ios_device_pairing_id)[0]:
            keep_alive = False
    else:
        raise ValueError('Unknown data received: {}'.format(parsed_body))

    return Response(PAIRING_CONTENT_TYPE, data=tlv_parser.encode(result), keep_alive=keep_alive)
