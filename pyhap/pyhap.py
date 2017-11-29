from logging import getLogger
from socket import inet_aton

from zeroconf import ServiceInfo, Zeroconf

from pyhap.accessory import Accessories
from pyhap.config import (
    AccessoryCategory,
    Config,
    StatusFlag,
)
from pyhap import route
from pyhap.http_server import HTTPServer
from pyhap.tlv import TlvState


logger = getLogger('pyhap')


def start(config: Config, accessories: Accessories):
    # TODO: increment configuration_number in case hash of accessory list json is changed before starting up mdns
    logger.info('Starting up PyHAP, setup code: %s', config.setup_code)
    mdns_server = MDNSServer(config)
    mdns_server.start()
    http_server = WebServer(config, accessories)
    http_server.start()


class MDNSServer:
    """Announce accessory on the network via mDNS / DNS-SD

    To debug service: avahi-browse -r -k _hap._tcp
    """
    # TODO: restart / reload zeroconf on config change
    def __init__(self, config: Config) -> None:
        self.zeroconf = Zeroconf()
        self.hap_service: ServiceInfo = None
        self.config = config

    def update_service(self):
        self.hap_service = ServiceInfo(
            type_=self.config.service_type,
            name=f'{self.config.model_name}.{self.config.service_type}',
            address=inet_aton(self.config.server_ip),
            port=self.config.server_port,
            properties={
                'c#': str(self.config.configuration_number),
                'ff': '0',  # feature flag: enable HAP pairing  # TODO: disable pairing once paired
                'id': self.config.device_id,
                'md': self.config.model_name,
                'pv': '1.0',  # protocol version
                's#': '1',  # current state number, this must have a value of '1'
                'sf': str(StatusFlag.not_paired.value),  # pylint: disable=no-member
                'ci': str(AccessoryCategory.bridge.value),  # accessory category identifier
            },
        )

    def start(self):
        """Start announcing accessory on the network"""
        self.update_service()
        self.zeroconf.register_service(self.hap_service)

    def restart(self):
        self.stop()
        self.update_service()
        self.start()

    def stop(self):
        self.zeroconf.unregister_service(self.hap_service)

    def close(self):
        self.zeroconf.close()


class WebServer:
    def __init__(self, config: Config, accessories_obj: Accessories) -> None:
        self.http_server = HTTPServer({
            '/accessories': route.accessories,
            '/characteristics': route.characteristics,
            '/identify': route.identify,
            '/pair-setup': route.pair_setup,
            '/pair-verify': route.pair_verify,
            '/pairings': route.pairings,
        })

        self.http_server.global_context['accessories'] = accessories_obj
        self.http_server.global_context['config'] = config
        self.http_server.global_context['pair_setup_expected_state'] = TlvState.m1

    def start(self):
        config = self.http_server.global_context['config']
        logger.debug(f'Serving at http://{config.server_ip}:{config.server_port}')
        self.http_server.run(config.server_ip, config.server_port)
