import logging

from pyhap.accessory import (
    Accessory,
    Accessories,
)
from pyhap.characteristics import (
    Brightness,
    On,
)
from pyhap.config import JsonConfig
from pyhap.pyhap import start
from pyhap.service import (
    LightbulbService,
)

IP_ADDRESS = 'XXX.XXX.XXX.XXX'  # change to your IP address


def main():
    logging.basicConfig(level=logging.INFO)

    lightbulb1 = Accessory(name='Acme LED Light Bulb', model='LEDBulb1,1', manufacturer='Acme')

    lightbulb1_lightbulb = LightbulbService()
    lightbulb1_lightbulb.add_characteristic(On(True, bulb_on))
    lightbulb1_lightbulb.add_characteristic(Brightness(50, bulb_brightness))
    lightbulb1.add_service(lightbulb1_lightbulb)

    accessories = Accessories()
    accessories.add(lightbulb1)

    config = JsonConfig(IP_ADDRESS)
    start(config, accessories)


async def bulb_on(value: bool) -> None:
    if value:
        print('Bulb is on')
    else:
        print('Bulb is off')


async def bulb_brightness(value):
    print(f'Brightness is {value}%')


if __name__ == '__main__':
    main()
